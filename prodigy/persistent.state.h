#pragma once

#include <algorithm>
#include <cstring>
#include <memory>

#include <networking/includes.h>
#include <types/types.containers.h>
#include <databases/embedded/tidesdb.h>
#include <prodigy/bootstrap.config.h>
#include <prodigy/runtime.environment.h>
#include <prodigy/transport.tls.h>
#include <prodigy/types.h>
#include <services/base64.h>
#include <services/random.h>

class ProdigyPersistentBootState
{
public:

   ProdigyBootstrapConfig bootstrapConfig;
   String bootstrapSshUser;
   Vault::SSHKeyPackage bootstrapSshKeyPackage;
   Vault::SSHKeyPackage bootstrapSshHostKeyPackage;
   String bootstrapSshPrivateKeyPath;
   ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
   ClusterTopology initialTopology; // boot-only authoritative topology for first start before any brain snapshot exists

   bool operator==(const ProdigyPersistentBootState& other) const
   {
      return bootstrapConfig == other.bootstrapConfig
         && bootstrapSshUser.equals(other.bootstrapSshUser)
         && bootstrapSshKeyPackage == other.bootstrapSshKeyPackage
         && bootstrapSshHostKeyPackage == other.bootstrapSshHostKeyPackage
         && bootstrapSshPrivateKeyPath.equals(other.bootstrapSshPrivateKeyPath)
         && runtimeEnvironment == other.runtimeEnvironment
         && initialTopology == other.initialTopology;
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
      if (failure) failure->snprintf<"{} requires object"_ctv>(String(fieldName));
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
            if (failure) failure->snprintf<"{}.privateKeyOpenSSH requires string"_ctv>(String(fieldName));
            return false;
         }

         parsed.privateKeyOpenSSH.assign(field.value.get_c_str());
      }
      else if (key.equal("publicKeyOpenSSH"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->snprintf<"{}.publicKeyOpenSSH requires string"_ctv>(String(fieldName));
            return false;
         }

         parsed.publicKeyOpenSSH.assign(field.value.get_c_str());
      }
      else
      {
         if (failure) failure->snprintf<"invalid {} field"_ctv>(String(fieldName));
         return false;
      }
   }

   if (prodigyPersistentBootStateSSHKeyPackageConfigured(parsed)
      && Vault::validateSSHKeyPackageEd25519(parsed, failure) == false)
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

   if (prodigyPersistentBootStateSSHKeyPackageConfigured(config.bootstrapSshKeyPackage) == false
      && prodigyPersistentBootStateSSHKeyPackageConfigured(state.bootstrapSshKeyPackage))
   {
      config.bootstrapSshKeyPackage = state.bootstrapSshKeyPackage;
   }

   if (prodigyPersistentBootStateSSHKeyPackageConfigured(config.bootstrapSshHostKeyPackage) == false
      && prodigyPersistentBootStateSSHKeyPackageConfigured(state.bootstrapSshHostKeyPackage))
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

class ProdigyPersistentBrainSnapshot
{
public:

   Vector<ProdigyBootstrapConfig::BootstrapPeer> brainPeers;
   ClusterTopology topology;
   BrainConfig brainConfig;
   ProdigyPersistentMasterAuthorityPackage masterAuthority;
   Vector<ProdigyMetricSample> metricSamples;
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
   serializer.object(snapshot.metricSamples);
}

static inline const char *defaultProdigyPersistentStateDBPath(void)
{
   return "/var/lib/prodigy/state";
}

class ProdigyPersistentLocalBrainState
{
public:

   uint128_t uuid = 0;
   uint128_t ownerClusterUUID = 0;
   ProdigyTransportTLSMaterial transportTLS;

   bool transportTLSConfigured(void) const
   {
      return uuid != 0 && transportTLS.configured();
   }

   bool canMintTransportTLS(void) const
   {
      return uuid != 0 && transportTLS.canMintForCluster();
   }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentLocalBrainState& state)
{
   serializer.value16b(state.uuid);
   serializer.value16b(state.ownerClusterUUID);
   serializer.object(state.transportTLS);
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
   if (failure) failure->clear();

   if (localState.uuid == 0)
   {
      if (failure) failure->assign("local brain uuid required for transport tls authority"_ctv);
      return false;
   }

   if (authority.canMintForCluster() == false)
   {
      if (failure) failure->assign("transport tls authority incomplete"_ctv);
      return false;
   }

   String localCertPem = {};
   String localKeyPem = {};
   Vector<String> addresses;
   if (Vault::generateTransportNodeCertificateEd25519(
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
      if (failure) failure->assign("invalid local brain state json");
      return false;
   }

   if (doc.type() != simdjson::dom::element_type::OBJECT)
   {
      if (failure) failure->assign("local brain state must be an object");
      return false;
   }

   ProdigyPersistentLocalBrainState parsed = {};
   bool sawUUID = false;
   bool sawRootCert = false;
   bool sawLocalCert = false;
   bool sawLocalKey = false;

   for (auto field : doc.get_object())
   {
      String key;
      key.setInvariant(field.key.data(), field.key.size());

      if (key == "uuid"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("local brain state uuid requires string");
            return false;
         }

         String encoded(field.value.get_c_str());
         if (Vault::parseNodeCommonName(encoded, parsed.uuid) == false)
         {
            if (failure) failure->assign("local brain state uuid must be 32 hex characters");
            return false;
         }

         sawUUID = true;
      }
      else if (key == "ownerClusterUUID"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("local brain state ownerClusterUUID requires string");
            return false;
         }

         String encoded(field.value.get_c_str());
         if (Vault::parseNodeCommonName(encoded, parsed.ownerClusterUUID) == false)
         {
            if (failure) failure->assign("local brain state ownerClusterUUID must be 32 hex characters");
            return false;
         }
      }
      else if (key == "generation"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::INT64
            && field.value.type() != simdjson::dom::element_type::UINT64)
         {
            if (failure) failure->assign("local brain state generation requires integer");
            return false;
         }

         parsed.transportTLS.generation = uint64_t(field.value.get_uint64().value_unsafe());
      }
      else if (key == "clusterRootCertPem"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("local brain state clusterRootCertPem requires string");
            return false;
         }

         parsed.transportTLS.clusterRootCertPem.assign(field.value.get_c_str());
         sawRootCert = (parsed.transportTLS.clusterRootCertPem.size() > 0);
      }
      else if (key == "clusterRootKeyPem"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("local brain state clusterRootKeyPem requires string");
            return false;
         }

         parsed.transportTLS.clusterRootKeyPem.assign(field.value.get_c_str());
      }
      else if (key == "localCertPem"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("local brain state localCertPem requires string");
            return false;
         }

         parsed.transportTLS.localCertPem.assign(field.value.get_c_str());
         sawLocalCert = (parsed.transportTLS.localCertPem.size() > 0);
      }
      else if (key == "localKeyPem"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("local brain state localKeyPem requires string");
            return false;
         }

         parsed.transportTLS.localKeyPem.assign(field.value.get_c_str());
         sawLocalKey = (parsed.transportTLS.localKeyPem.size() > 0);
      }
      else
      {
         if (failure) failure->assign("invalid local brain state field");
         return false;
      }
   }

   if (sawUUID == false)
   {
      if (failure) failure->assign("local brain state uuid required");
      return false;
   }

   if (sawRootCert == false)
   {
      if (sawLocalCert || sawLocalKey)
      {
         if (failure) failure->assign("local brain state clusterRootCertPem required when tls material is present");
         return false;
      }
   }
   else if (sawLocalCert == false || sawLocalKey == false)
   {
      if (failure) failure->assign("local brain state localCertPem and localKeyPem required when tls material is present");
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

   if (state.transportTLS.clusterRootCertPem.size() > 0
      || state.transportTLS.clusterRootKeyPem.size() > 0
      || state.transportTLS.localCertPem.size() > 0
      || state.transportTLS.localKeyPem.size() > 0
      || state.transportTLS.generation > 0)
   {
      json.append(",\"generation\":"_ctv);
      json.append(String(state.transportTLS.generation));

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
   json.append("}"_ctv);
}

static inline void prodigyBackfillLocalBrainOwnerClusterUUID(
   ProdigyPersistentLocalBrainState& state,
   const ProdigyPersistentBrainSnapshot& snapshot,
   bool *changed = nullptr)
{
   if (changed) *changed = false;

   if (state.ownerClusterUUID != 0 || snapshot.brainConfig.clusterUUID == 0)
   {
      return;
   }

   state.ownerClusterUUID = snapshot.brainConfig.clusterUUID;
   if (changed) *changed = true;
}

static inline bool prodigyEnsureLocalBrainOwnedByCluster(
   ProdigyPersistentLocalBrainState& state,
   uint128_t clusterUUID,
   bool *changed = nullptr,
   String *failure = nullptr)
{
   if (changed) *changed = false;
   if (failure) failure->clear();

   if (clusterUUID == 0)
   {
      return true;
   }

   if (state.ownerClusterUUID == 0)
   {
      state.ownerClusterUUID = clusterUUID;
      if (changed) *changed = true;
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
      if (failure) failure->assign("runtimeEnvironment.bgp requires object");
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
         if (field.value.type() != simdjson::dom::element_type::BOOL
            || field.value.get(parsed.config.enabled) != simdjson::SUCCESS)
         {
            if (failure) failure->assign("runtimeEnvironment.bgp.enabled requires bool");
            return false;
         }
      }
      else if (key == "bgpID"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("runtimeEnvironment.bgp.bgpID requires string");
            return false;
         }

         String value(field.value.get_c_str());
         if (prodigyParseBGPIDText(value, parsed.config.ourBGPID) == false)
         {
            if (failure) failure->assign("runtimeEnvironment.bgp.bgpID requires ipv4 string");
            return false;
         }
      }
      else if (key == "community"_ctv)
      {
         uint64_t value = 0;
         if ((field.value.type() != simdjson::dom::element_type::INT64
               && field.value.type() != simdjson::dom::element_type::UINT64)
            || field.value.get(value) != simdjson::SUCCESS
            || value > UINT32_MAX)
         {
            if (failure) failure->assign("runtimeEnvironment.bgp.community requires uint32");
            return false;
         }

         parsed.config.community = uint32_t(value);
      }
      else if (key == "nextHop4"_ctv || key == "nextHop6"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->snprintf<"runtimeEnvironment.bgp.{} requires string"_ctv>(key);
            return false;
         }

         IPAddress parsedAddress = {};
         String value(field.value.get_c_str());
         if (prodigyParseIPAddressText(value, parsedAddress) == false)
         {
            if (failure) failure->snprintf<"runtimeEnvironment.bgp.{} invalid address"_ctv>(key);
            return false;
         }

         if (key == "nextHop4"_ctv)
         {
            if (parsedAddress.is6)
            {
               if (failure) failure->assign("runtimeEnvironment.bgp.nextHop4 requires ipv4");
               return false;
            }

            parsed.config.nextHop4 = parsedAddress;
         }
         else
         {
            if (parsedAddress.is6 == false)
            {
               if (failure) failure->assign("runtimeEnvironment.bgp.nextHop6 requires ipv6");
               return false;
            }

            parsed.config.nextHop6 = parsedAddress;
         }
      }
      else if (key == "peers"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::ARRAY)
         {
            if (failure) failure->assign("runtimeEnvironment.bgp.peers requires array");
            return false;
         }

         for (auto peerValue : field.value.get_array())
         {
            if (peerValue.type() != simdjson::dom::element_type::OBJECT)
            {
               if (failure) failure->assign("runtimeEnvironment.bgp.peers requires object members");
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
                  if ((peerField.value.type() != simdjson::dom::element_type::INT64
                        && peerField.value.type() != simdjson::dom::element_type::UINT64)
                     || peerField.value.get(value) != simdjson::SUCCESS
                     || value > UINT16_MAX)
                  {
                     if (failure) failure->assign("runtimeEnvironment.bgp.peers[].peerASN requires uint16");
                     return false;
                  }

                  peer.peerASN = uint16_t(value);
               }
               else if (peerKey == "peerAddress"_ctv || peerKey == "sourceAddress"_ctv)
               {
                  if (peerField.value.type() != simdjson::dom::element_type::STRING)
                  {
                     if (failure) failure->snprintf<"runtimeEnvironment.bgp.peers[].{} requires string"_ctv>(peerKey);
                     return false;
                  }

                  IPAddress parsedAddress = {};
                  String value(peerField.value.get_c_str());
                  if (prodigyParseIPAddressText(value, parsedAddress) == false)
                  {
                     if (failure) failure->snprintf<"runtimeEnvironment.bgp.peers[].{} invalid address"_ctv>(peerKey);
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
                     if (failure) failure->assign("runtimeEnvironment.bgp.peers[].md5Password requires string");
                     return false;
                  }

                  peer.md5Password.assign(peerField.value.get_c_str());
               }
               else if (peerKey == "hopLimit"_ctv)
               {
                  uint64_t value = 0;
                  if ((peerField.value.type() != simdjson::dom::element_type::INT64
                        && peerField.value.type() != simdjson::dom::element_type::UINT64)
                     || peerField.value.get(value) != simdjson::SUCCESS
                     || value > UINT8_MAX)
                  {
                     if (failure) failure->assign("runtimeEnvironment.bgp.peers[].hopLimit requires uint8");
                     return false;
                  }

                  peer.hopLimit = uint8_t(value);
               }
               else
               {
                  if (failure) failure->assign("invalid runtimeEnvironment.bgp.peers[] field");
                  return false;
               }
            }

            parsed.config.peers.push_back(peer);
         }
      }
      else
      {
         if (failure) failure->assign("invalid runtimeEnvironment.bgp field");
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
      if (failure) failure->assign("runtimeEnvironment must be an object");
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
            if (failure) failure->assign("runtimeEnvironment.kind requires string");
            return false;
         }

         String value(field.value.get_c_str());
         if (parseProdigyEnvironmentKind(value, parsed.kind) == false)
         {
            if (failure) failure->assign("runtimeEnvironment.kind invalid");
            return false;
         }
      }
      else if (key == "providerScope"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("runtimeEnvironment.providerScope requires string");
            return false;
         }

         parsed.providerScope.assign(field.value.get_c_str());
      }
      else if (key == "providerCredentialMaterial"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("runtimeEnvironment.providerCredentialMaterial requires string");
            return false;
         }

         parsed.providerCredentialMaterial.assign(field.value.get_c_str());
      }
      else if (key == "aws"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::OBJECT)
         {
            if (failure) failure->assign("runtimeEnvironment.aws requires object");
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
                  if (failure) failure->assign("runtimeEnvironment.aws.bootstrapLaunchTemplateName requires string");
                  return false;
               }

               parsed.aws.bootstrapLaunchTemplateName.assign(nestedField.value.get_c_str());
            }
            else if (nestedKey == "bootstrapLaunchTemplateVersion"_ctv)
            {
               if (nestedField.value.type() != simdjson::dom::element_type::STRING)
               {
                  if (failure) failure->assign("runtimeEnvironment.aws.bootstrapLaunchTemplateVersion requires string");
                  return false;
               }

               parsed.aws.bootstrapLaunchTemplateVersion.assign(nestedField.value.get_c_str());
            }
            else if (nestedKey == "bootstrapCredentialRefreshCommand"_ctv)
            {
               if (nestedField.value.type() != simdjson::dom::element_type::STRING)
               {
                  if (failure) failure->assign("runtimeEnvironment.aws.bootstrapCredentialRefreshCommand requires string");
                  return false;
               }

               parsed.aws.bootstrapCredentialRefreshCommand.assign(nestedField.value.get_c_str());
            }
            else if (nestedKey == "bootstrapCredentialRefreshFailureHint"_ctv)
            {
               if (nestedField.value.type() != simdjson::dom::element_type::STRING)
               {
                  if (failure) failure->assign("runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint requires string");
                  return false;
               }

               parsed.aws.bootstrapCredentialRefreshFailureHint.assign(nestedField.value.get_c_str());
            }
            else if (nestedKey == "instanceProfileName"_ctv)
            {
               if (nestedField.value.type() != simdjson::dom::element_type::STRING)
               {
                  if (failure) failure->assign("runtimeEnvironment.aws.instanceProfileName requires string");
                  return false;
               }

               parsed.aws.instanceProfileName.assign(nestedField.value.get_c_str());
            }
            else if (nestedKey == "instanceProfileArn"_ctv)
            {
               if (nestedField.value.type() != simdjson::dom::element_type::STRING)
               {
                  if (failure) failure->assign("runtimeEnvironment.aws.instanceProfileArn requires string");
                  return false;
               }

               parsed.aws.instanceProfileArn.assign(nestedField.value.get_c_str());
            }
            else
            {
               if (failure) failure->assign("invalid runtimeEnvironment.aws field");
               return false;
            }
         }
      }
      else if (key == "gcp"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::OBJECT)
         {
            if (failure) failure->assign("runtimeEnvironment.gcp requires object");
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
                  if (failure) failure->assign("runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand requires string");
                  return false;
               }

               parsed.gcp.bootstrapAccessTokenRefreshCommand.assign(nestedField.value.get_c_str());
            }
            else if (nestedKey == "bootstrapAccessTokenRefreshFailureHint"_ctv)
            {
               if (nestedField.value.type() != simdjson::dom::element_type::STRING)
               {
                  if (failure) failure->assign("runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint requires string");
                  return false;
               }

               parsed.gcp.bootstrapAccessTokenRefreshFailureHint.assign(nestedField.value.get_c_str());
            }
            else
            {
               if (failure) failure->assign("invalid runtimeEnvironment.gcp field");
               return false;
            }
         }
      }
      else if (key == "azure"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::OBJECT)
         {
            if (failure) failure->assign("runtimeEnvironment.azure requires object");
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
                  if (failure) failure->assign("runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand requires string");
                  return false;
               }

               parsed.azure.bootstrapAccessTokenRefreshCommand.assign(nestedField.value.get_c_str());
            }
            else if (nestedKey == "bootstrapAccessTokenRefreshFailureHint"_ctv)
            {
               if (nestedField.value.type() != simdjson::dom::element_type::STRING)
               {
                  if (failure) failure->assign("runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint requires string");
                  return false;
               }

               parsed.azure.bootstrapAccessTokenRefreshFailureHint.assign(nestedField.value.get_c_str());
            }
            else if (nestedKey == "managedIdentityResourceID"_ctv)
            {
               if (nestedField.value.type() != simdjson::dom::element_type::STRING)
               {
                  if (failure) failure->assign("runtimeEnvironment.azure.managedIdentityResourceID requires string");
                  return false;
               }

               parsed.azure.managedIdentityResourceID.assign(nestedField.value.get_c_str());
            }
            else
            {
               if (failure) failure->assign("invalid runtimeEnvironment.azure field");
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
         if (failure) failure->assign("invalid runtimeEnvironment field");
         return false;
      }
   }

   prodigyApplyInternalRuntimeEnvironmentDefaults(parsed);
   config = parsed;
   return true;
}

static inline bool parseProdigyPersistentBootStateJSON(const String& json, ProdigyPersistentBootState& state, String *failure = nullptr)
{
   simdjson::dom::parser parser;
   simdjson::dom::element doc;
   if (parser.parse(json.data(), json.size()).get(doc))
   {
      if (failure) failure->assign("invalid boot json");
      return false;
   }

   if (doc.type() != simdjson::dom::element_type::OBJECT)
   {
      if (failure) failure->assign("boot state must be an object");
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
            if (failure) failure->assign("bootstrapPeers requires array");
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
            if (failure) failure->assign("nodeRole requires string");
            return false;
         }

         String value(field.value.get_c_str());
         if (parseProdigyBootstrapNodeRole(value, parsed.bootstrapConfig.nodeRole) == false)
         {
            if (failure) failure->assign("nodeRole invalid");
            return false;
         }

         sawNodeRole = true;
      }
      else if (key == "controlSocketPath"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("controlSocketPath requires string");
            return false;
         }

         parsed.bootstrapConfig.controlSocketPath.assign(field.value.get_c_str());
         sawControlSocketPath = true;
      }
      else if (key == "bootstrapSshUser"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("bootstrapSshUser requires string");
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
            if (failure) failure->assign("bootstrapSshPrivateKeyPath requires string");
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
      else if (key == "initialTopology"_ctv)
      {
         if (field.value.type() != simdjson::dom::element_type::STRING)
         {
            if (failure) failure->assign("initialTopology requires string");
            return false;
         }

         String encodedTopology = {};
         encodedTopology.assign(field.value.get_c_str());
         String decodedTopology = {};
         if (Base64::decode(encodedTopology, decodedTopology) == false)
         {
            if (failure) failure->assign("initialTopology base64 decode failed");
            return false;
         }

         ClusterTopology initialTopology = {};
         if (BitseryEngine::deserializeSafe(decodedTopology, initialTopology) == false)
         {
            if (failure) failure->assign("initialTopology decode failed");
            return false;
         }

         parsed.initialTopology = std::move(initialTopology);
      }
      else
      {
         if (failure) failure->assign("invalid boot state field");
         return false;
      }
   }

   if (sawBootstrapPeers == false)
   {
      if (failure) failure->assign("bootstrapPeers required");
      return false;
   }

   if (sawNodeRole == false)
   {
      if (failure) failure->assign("nodeRole required");
      return false;
   }

   if (sawControlSocketPath == false || parsed.bootstrapConfig.controlSocketPath.size() == 0)
   {
      if (failure) failure->assign("controlSocketPath required");
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
            json.append(String(runtimeEnvironment.bgp.config.community));
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
               json.append(String(uint32_t(peer.peerASN)));

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
                  json.append(String(uint32_t(peer.hopLimit)));
               }

               json.append("}"_ctv);
            }
            json.append("]"_ctv);
         }

         json.append("}"_ctv);
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
   key.append(String(version));
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

static inline void prodigyClearPersistentSSHPrivateKey(Vault::SSHKeyPackage& package)
{
   prodigyClearPersistentSecretString(package.privateKeyOpenSSH);
}

class ProdigyPersistentStoredBootState
{
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

class ProdigyPersistentStoredBrainSnapshot
{
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

class ProdigyPersistentStoredLocalBrainState
{
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

class ProdigyPersistentBootStateSecrets
{
public:

   String bootstrapSshPrivateKeyOpenSSH;
   String bootstrapSshHostPrivateKeyOpenSSH;

   bool empty(void) const
   {
      return bootstrapSshPrivateKeyOpenSSH.size() == 0
         && bootstrapSshHostPrivateKeyOpenSSH.size() == 0;
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

class ProdigyPersistentApplicationTlsVaultFactorySecrets
{
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

class ProdigyPersistentApiCredentialSecret
{
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

class ProdigyPersistentApplicationApiCredentialSetSecrets
{
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

class ProdigyPersistentPendingAddMachinesOperationSecrets
{
public:

   uint64_t operationID = 0;
   String bootstrapSshPrivateKeyOpenSSH;
   String bootstrapSshHostPrivateKeyOpenSSH;

   bool empty(void) const
   {
      return bootstrapSshPrivateKeyOpenSSH.size() == 0
         && bootstrapSshHostPrivateKeyOpenSSH.size() == 0;
   }

   void clear(void)
   {
      prodigyClearPersistentSecretString(bootstrapSshPrivateKeyOpenSSH);
      prodigyClearPersistentSecretString(bootstrapSshHostPrivateKeyOpenSSH);
   }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentPendingAddMachinesOperationSecrets& secrets)
{
   serializer.value8b(secrets.operationID);
   serializer.text1b(secrets.bootstrapSshPrivateKeyOpenSSH, UINT32_MAX);
   serializer.text1b(secrets.bootstrapSshHostPrivateKeyOpenSSH, UINT32_MAX);
}

class ProdigyPersistentBrainSnapshotSecrets
{
public:

   String bootstrapSshPrivateKeyOpenSSH;
   String bootstrapSshHostPrivateKeyOpenSSH;
   String reporterPassword;
   bytell_hash_map<uint16_t, ProdigyPersistentApplicationTlsVaultFactorySecrets> tlsVaultFactorySecretsByApp;
   bytell_hash_map<uint16_t, ProdigyPersistentApplicationApiCredentialSetSecrets> apiCredentialSecretsByApp;
   String transportTLSAuthorityClusterRootKeyPem;
   Vector<ProdigyPersistentPendingAddMachinesOperationSecrets> pendingAddMachinesOperationSecrets;

   bool empty(void) const
   {
      return bootstrapSshPrivateKeyOpenSSH.size() == 0
         && bootstrapSshHostPrivateKeyOpenSSH.size() == 0
         && reporterPassword.size() == 0
         && tlsVaultFactorySecretsByApp.empty()
         && apiCredentialSecretsByApp.empty()
         && transportTLSAuthorityClusterRootKeyPem.size() == 0
         && pendingAddMachinesOperationSecrets.empty();
   }

   void clear(void)
   {
      prodigyClearPersistentSecretString(bootstrapSshPrivateKeyOpenSSH);
      prodigyClearPersistentSecretString(bootstrapSshHostPrivateKeyOpenSSH);
      prodigyClearPersistentSecretString(reporterPassword);
      prodigyClearPersistentSecretString(transportTLSAuthorityClusterRootKeyPem);

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

      for (auto& operationSecrets : pendingAddMachinesOperationSecrets)
      {
         operationSecrets.clear();
      }

      tlsVaultFactorySecretsByApp.clear();
      apiCredentialSecretsByApp.clear();
      pendingAddMachinesOperationSecrets.clear();
   }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentBrainSnapshotSecrets& secrets)
{
   serializer.text1b(secrets.bootstrapSshPrivateKeyOpenSSH, UINT32_MAX);
   serializer.text1b(secrets.bootstrapSshHostPrivateKeyOpenSSH, UINT32_MAX);
   serializer.text1b(secrets.reporterPassword, UINT32_MAX);
   serializer.object(secrets.tlsVaultFactorySecretsByApp);
   serializer.object(secrets.apiCredentialSecretsByApp);
   serializer.text1b(secrets.transportTLSAuthorityClusterRootKeyPem, UINT32_MAX);
   serializer.object(secrets.pendingAddMachinesOperationSecrets);
}

class ProdigyPersistentLocalBrainStateSecrets
{
public:

   String clusterRootKeyPem;
   String localKeyPem;

   bool empty(void) const
   {
      return clusterRootKeyPem.size() == 0 && localKeyPem.size() == 0;
   }

   void clear(void)
   {
      prodigyClearPersistentSecretString(clusterRootKeyPem);
      prodigyClearPersistentSecretString(localKeyPem);
   }
};

template <typename S>
static void serialize(S&& serializer, ProdigyPersistentLocalBrainStateSecrets& secrets)
{
   serializer.text1b(secrets.clusterRootKeyPem, UINT32_MAX);
   serializer.text1b(secrets.localKeyPem, UINT32_MAX);
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

static inline void prodigyExtractPersistentBrainSnapshotSecrets(
   ProdigyPersistentBrainSnapshot snapshot,
   ProdigyPersistentBrainSnapshot& publicSnapshot,
   ProdigyPersistentBrainSnapshotSecrets& secrets)
{
   publicSnapshot = std::move(snapshot);
   secrets.clear();

   secrets.bootstrapSshPrivateKeyOpenSSH = publicSnapshot.brainConfig.bootstrapSshKeyPackage.privateKeyOpenSSH;
   secrets.bootstrapSshHostPrivateKeyOpenSSH = publicSnapshot.brainConfig.bootstrapSshHostKeyPackage.privateKeyOpenSSH;
   secrets.reporterPassword = publicSnapshot.brainConfig.reporter.password;
   prodigyClearPersistentSSHPrivateKey(publicSnapshot.brainConfig.bootstrapSshKeyPackage);
   prodigyClearPersistentSSHPrivateKey(publicSnapshot.brainConfig.bootstrapSshHostKeyPackage);
   prodigyClearPersistentSecretString(publicSnapshot.brainConfig.reporter.password);

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

   secrets.transportTLSAuthorityClusterRootKeyPem = publicSnapshot.masterAuthority.runtimeState.transportTLSAuthority.clusterRootKeyPem;
   prodigyClearPersistentSecretString(publicSnapshot.masterAuthority.runtimeState.transportTLSAuthority.clusterRootKeyPem);

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
}

static inline bool prodigyApplyPersistentBrainSnapshotSecrets(
   ProdigyPersistentBrainSnapshot& snapshot,
   const ProdigyPersistentBrainSnapshotSecrets& secrets,
   String *failure = nullptr)
{
   if (failure) failure->clear();

   snapshot.brainConfig.bootstrapSshKeyPackage.privateKeyOpenSSH = secrets.bootstrapSshPrivateKeyOpenSSH;
   snapshot.brainConfig.bootstrapSshHostKeyPackage.privateKeyOpenSSH = secrets.bootstrapSshHostPrivateKeyOpenSSH;
   snapshot.brainConfig.reporter.password = secrets.reporterPassword;

   for (const auto& [applicationID, factorySecrets] : secrets.tlsVaultFactorySecretsByApp)
   {
      auto it = snapshot.masterAuthority.tlsVaultFactoriesByApp.find(applicationID);
      if (it == snapshot.masterAuthority.tlsVaultFactoriesByApp.end())
      {
         if (failure) failure->snprintf<"persistent brain snapshot tls factory secrets missing app {}"_ctv>(String(applicationID));
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
         if (failure) failure->snprintf<"persistent brain snapshot api credential secrets missing app {}"_ctv>(String(applicationID));
         return false;
      }

      for (const auto& credentialSecret : setSecrets.credentials)
      {
         bool matched = false;
         for (auto& credential : it->second.credentials)
         {
            if (credential.name.equals(credentialSecret.name)
               && credential.provider.equals(credentialSecret.provider)
               && credential.generation == credentialSecret.generation)
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

   snapshot.masterAuthority.runtimeState.transportTLSAuthority.clusterRootKeyPem = secrets.transportTLSAuthorityClusterRootKeyPem;

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
            failure->snprintf<"persistent brain snapshot add-machines secrets missing operation {}"_ctv>(
               String(operationSecrets.operationID));
         }
         return false;
      }
   }

   return true;
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
}

static inline void prodigyApplyPersistentLocalBrainStateSecrets(
   ProdigyPersistentLocalBrainState& state,
   const ProdigyPersistentLocalBrainStateSecrets& secrets)
{
   state.transportTLS.clusterRootKeyPem = secrets.clusterRootKeyPem;
   state.transportTLS.localKeyPem = secrets.localKeyPem;
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

static bool prodigyPersistentRawBytesEqual(const String& lhs, const String& rhs)
{
   return lhs.size() == rhs.size()
      && (lhs.size() == 0 || std::memcmp(lhs.data(), rhs.data(), lhs.size()) == 0);
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
   return payload.size() == 0
      || std::memcmp(serializedBytes + sizeof(uint64_t), payload.data(), payload.size()) == 0;
}

template <typename StoredRecord, typename LegacyRecord>
static bool prodigyLoadPersistentStoredRecord(const String& serialized, StoredRecord& record)
{
   record = {};
   if (BitseryEngine::deserializeSafe(serialized, record))
   {
      return true;
   }

   LegacyRecord legacy = {};
   if (BitseryEngine::deserializeSafe(serialized, legacy))
   {
      record.state = std::move(legacy);
      return true;
   }

   return false;
}

class ProdigyPersistentStateStore
{
private:

   static constexpr const char *bootColumnFamily = "boot";
   static constexpr const char *brainColumnFamily = "brain";
   static constexpr const char *bootKey = "local";
   static constexpr const char *brainSnapshotKey = "snapshot";
   static constexpr const char *localBrainStateKey = "local_brain_state";

   TidesDB db;
   TidesDB secretsDb;

   bool loadStoredBootStateRecord(ProdigyPersistentStoredBootState& record, String *failure = nullptr)
   {
      String serialized = {};
      if (db.read(bootColumnFamily, bootKey, serialized, failure) == false)
      {
         return false;
      }

      if (prodigyLoadPersistentStoredRecord<ProdigyPersistentStoredBootState, ProdigyPersistentBootState>(serialized, record) == false)
      {
         if (failure) failure->assign("invalid persistent boot state");
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

      if (prodigyLoadPersistentStoredRecord<ProdigyPersistentStoredBrainSnapshot, ProdigyPersistentBrainSnapshot>(serialized, record) == false)
      {
         if (failure) failure->assign("invalid persistent brain snapshot");
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

      if (prodigyLoadPersistentStoredRecord<ProdigyPersistentStoredLocalBrainState, ProdigyPersistentLocalBrainState>(serialized, record) == false)
      {
         if (failure) failure->assign("invalid persistent local brain state");
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
         if (failure) failure->assign(failureMessage);
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
            if (failure) failure->clear();
            return true;
         }
      }
      else if (loadFailure.size() > 0 && loadFailure != "record not found"_ctv)
      {
         if (failure) failure->assign(loadFailure);
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
      prodigyExtractPersistentBrainSnapshotSecrets(std::move(canonicalSnapshot), publicSnapshot, secrets);

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
               if (serializedSecrets.size() == 0
                  && prodigyPersistentStoredRecordPayloadEquals(existingStoredRecord, serializedPublicSnapshot))
               {
                  Vault::secureClearString(serializedPublicSnapshot);
                  secrets.clear();
                  if (failure) failure->clear();
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
                     if (failure) failure->clear();
                     return true;
                  }
               }
               else if (secretFailure.size() > 0 && secretFailure != "record not found"_ctv)
               {
                  Vault::secureClearString(serializedPublicSnapshot);
                  Vault::secureClearString(serializedSecrets);
                  secrets.clear();
                  if (failure) failure->assign(secretFailure);
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
         if (failure) failure->assign(loadFailure);
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

         prodigyApplyPersistentLocalBrainStateSecrets(state, secrets);
         secrets.clear();
      }

      return true;
   }

   bool saveLocalBrainState(const ProdigyPersistentLocalBrainState& state, String *failure = nullptr)
   {
      ProdigyPersistentLocalBrainState existingState = {};
      String loadFailure = {};
      if (loadLocalBrainState(existingState, &loadFailure))
      {
         if (prodigyPersistentSerializedEqual(existingState, state))
         {
            if (failure) failure->clear();
            return true;
         }
      }
      else if (loadFailure.size() > 0 && loadFailure != "record not found"_ctv)
      {
         if (failure) failure->assign(loadFailure);
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
         if (failure) failure->assign(loadFailure);
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

      if (failure) failure->clear();
      return true;
   }

   bool removeBrainSnapshot(String *failure = nullptr)
   {
      return db.remove(brainColumnFamily, brainSnapshotKey, failure);
   }
};
