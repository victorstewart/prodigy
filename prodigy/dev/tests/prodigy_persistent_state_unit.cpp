#include <prodigy/persistent.state.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/brain/brain.h>
#include <services/debug.h>
#include <prodigy/dev/tests/prodigy_test_ssh_keys.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <algorithm>

class TestSuite
{
public:

   int failed = 0;

   void expect(bool condition, const char *name)
   {
      if (condition)
      {
         basics_log("PASS: %s\n", name);
      }
      else
      {
         basics_log("FAIL: %s\n", name);
         std::fprintf(stderr, "FAIL: %s\n", name);
         std::fflush(stderr);
         failed += 1;
      }
   }
};

class PersistentStateTestBrain final : public Brain
{
public:

   uint32_t persistCalls = 0;

   void configureCloudflareTunnel(String& mothershipEndpoint) override
   {
      mothershipEndpoint.assign("127.0.0.1"_ctv);
   }

   void teardownCloudflareTunnel(void) override
   {
   }

   void pushSpinApplicationProgressToMothership(ApplicationDeployment *deployment, const String& message) override
   {
      (void)deployment;
      (void)message;
   }

   void spinApplicationFailed(ApplicationDeployment *deployment, const String& message) override
   {
      (void)deployment;
      (void)message;
   }

   void persistLocalRuntimeState(void) override
   {
      persistCalls += 1;
   }
};

template <typename... Args>
static Message *buildBrainMessage(String& buffer, BrainTopic topic, Args&&... args)
{
   buffer.clear();
   Message::construct(buffer, topic, std::forward<Args>(args)...);
   return reinterpret_cast<Message *>(buffer.data());
}

template <typename... Args>
static Message *buildMothershipMessage(String& buffer, MothershipTopic topic, Args&&... args)
{
   buffer.clear();
   Message::construct(buffer, topic, std::forward<Args>(args)...);
   return reinterpret_cast<Message *>(buffer.data());
}

static bool stringContains(const String& haystack, const char *needle)
{
   size_t needleLength = std::strlen(needle);
   if (needleLength == 0)
   {
      return true;
   }

   return std::search(haystack.data(),
      haystack.data() + haystack.size(),
      needle,
      needle + needleLength) != (haystack.data() + haystack.size());
}

static bool stringContains(const String& haystack, const String& needle)
{
   if (needle.size() == 0)
   {
      return true;
   }

   return std::search(haystack.data(),
      haystack.data() + haystack.size(),
      needle.data(),
      needle.data() + needle.size()) != (haystack.data() + haystack.size());
}

static bool readRawTidesDBRecord(const String& dbPath, const String& columnFamily, const String& key, String& value, String *failure = nullptr)
{
   TidesDB db(dbPath);
   return db.read(columnFamily, key, value, failure);
}

static bool cleanupPersistentStateRoots(const String& dbPath)
{
   String secretsPath = {};
   resolveProdigyPersistentSecretsDBPath(dbPath, secretsPath);

   std::error_code cleanupError = {};
   std::filesystem::remove_all(std::string(reinterpret_cast<const char *>(dbPath.data()), dbPath.size()), cleanupError);
   if (cleanupError)
   {
      return false;
   }

   cleanupError = {};
   std::filesystem::remove_all(std::string(reinterpret_cast<const char *>(secretsPath.data()), secretsPath.size()), cleanupError);
   return !cleanupError;
}

static bool equalRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& lhs, const ProdigyRuntimeEnvironmentConfig& rhs)
{
   return lhs == rhs;
}

static bool equalBootstrapConfigs(const ProdigyBootstrapConfig& lhs, const ProdigyBootstrapConfig& rhs)
{
   return lhs == rhs;
}

static bool equalMachineConfig(const MachineConfig& lhs, const MachineConfig& rhs)
{
   return lhs.kind == rhs.kind
      && lhs.slug.equals(rhs.slug)
      && lhs.nLogicalCores == rhs.nLogicalCores
      && lhs.nMemoryMB == rhs.nMemoryMB
      && lhs.nStorageMB == rhs.nStorageMB
      && lhs.vmImageURI.equals(rhs.vmImageURI)
      && lhs.gcpInstanceTemplate.equals(rhs.gcpInstanceTemplate)
      && lhs.gcpInstanceTemplateSpot.equals(rhs.gcpInstanceTemplateSpot)
      && lhs.providesHostPublic4 == rhs.providesHostPublic4
      && lhs.providesHostPublic6 == rhs.providesHostPublic6;
}

static bool equalBrainConfigs(const BrainConfig& lhs, const BrainConfig& rhs)
{
   if (lhs.clusterUUID != rhs.clusterUUID
      || lhs.datacenterFragment != rhs.datacenterFragment
      || lhs.autoscaleIntervalSeconds != rhs.autoscaleIntervalSeconds
      || lhs.sharedCPUOvercommitPermille != rhs.sharedCPUOvercommitPermille
      || lhs.requiredBrainCount != rhs.requiredBrainCount
      || lhs.architecture != rhs.architecture
      || lhs.bootstrapSshUser.equals(rhs.bootstrapSshUser) == false
      || lhs.bootstrapSshKeyPackage != rhs.bootstrapSshKeyPackage
      || lhs.bootstrapSshHostKeyPackage != rhs.bootstrapSshHostKeyPackage
      || lhs.bootstrapSshPrivateKeyPath.equals(rhs.bootstrapSshPrivateKeyPath) == false
      || lhs.remoteProdigyPath.equals(rhs.remoteProdigyPath) == false
      || lhs.controlSocketPath.equals(rhs.controlSocketPath) == false
      || lhs.vmImageURI.equals(rhs.vmImageURI) == false
      || equalRuntimeEnvironment(lhs.runtimeEnvironment, rhs.runtimeEnvironment) == false
      || lhs.configBySlug.size() != rhs.configBySlug.size())
   {
      return false;
   }

   for (const auto& [slug, machineConfig] : lhs.configBySlug)
   {
      auto it = rhs.configBySlug.find(slug);
      if (it == rhs.configBySlug.end() || equalMachineConfig(machineConfig, it->second) == false)
      {
         return false;
      }
   }

   return true;
}

static bool equalBootStates(const ProdigyPersistentBootState& lhs, const ProdigyPersistentBootState& rhs)
{
   return equalBootstrapConfigs(lhs.bootstrapConfig, rhs.bootstrapConfig)
      && lhs.bootstrapSshUser.equals(rhs.bootstrapSshUser)
      && lhs.bootstrapSshKeyPackage == rhs.bootstrapSshKeyPackage
      && lhs.bootstrapSshHostKeyPackage == rhs.bootstrapSshHostKeyPackage
      && lhs.bootstrapSshPrivateKeyPath.equals(rhs.bootstrapSshPrivateKeyPath)
      && equalRuntimeEnvironment(lhs.runtimeEnvironment, rhs.runtimeEnvironment)
      && lhs.initialTopology == rhs.initialTopology;
}

template <typename T>
static bool equalSerializedObjects(const T& lhs, const T& rhs)
{
   String serializedLhs = {};
   String serializedRhs = {};
   T mutableLhs = lhs;
   T mutableRhs = rhs;
   BitseryEngine::serialize(serializedLhs, mutableLhs);
   BitseryEngine::serialize(serializedRhs, mutableRhs);
   return serializedLhs.equals(serializedRhs);
}

template <typename K, typename V>
static bool equalMapBySerializedValue(const bytell_hash_map<K, V>& lhs, const bytell_hash_map<K, V>& rhs)
{
   if (lhs.size() != rhs.size())
   {
      return false;
   }

   for (const auto& [key, value] : lhs)
   {
      auto it = rhs.find(key);
      if (it == rhs.end() || equalSerializedObjects(value, it->second) == false)
      {
         return false;
      }
   }

   return true;
}

static bool equalMetricSamples(const Vector<ProdigyMetricSample>& lhs, const Vector<ProdigyMetricSample>& rhs)
{
   if (lhs.size() != rhs.size())
   {
      return false;
   }

   for (uint32_t index = 0; index < lhs.size(); ++index)
   {
      if (lhs[index] != rhs[index])
      {
         return false;
      }
   }

   return true;
}

static bool equalMasterAuthorityPackages(const ProdigyPersistentMasterAuthorityPackage& lhs, const ProdigyPersistentMasterAuthorityPackage& rhs)
{
   if (equalMapBySerializedValue(lhs.tlsVaultFactoriesByApp, rhs.tlsVaultFactoriesByApp) == false
      || equalMapBySerializedValue(lhs.apiCredentialSetsByApp, rhs.apiCredentialSetsByApp) == false
      || lhs.reservedApplicationIDsByName.size() != rhs.reservedApplicationIDsByName.size()
      || lhs.reservedApplicationNamesByID.size() != rhs.reservedApplicationNamesByID.size()
      || lhs.reservedApplicationServices.size() != rhs.reservedApplicationServices.size()
      || lhs.nextReservableApplicationID != rhs.nextReservableApplicationID
      || equalMapBySerializedValue(lhs.deploymentPlans, rhs.deploymentPlans) == false
      || lhs.failedDeployments.size() != rhs.failedDeployments.size()
      || lhs.runtimeState != rhs.runtimeState)
   {
      return false;
   }

   for (const auto& [name, applicationID] : lhs.reservedApplicationIDsByName)
   {
      auto it = rhs.reservedApplicationIDsByName.find(name);
      if (it == rhs.reservedApplicationIDsByName.end() || it->second != applicationID)
      {
         return false;
      }
   }

   for (const auto& [applicationID, name] : lhs.reservedApplicationNamesByID)
   {
      auto it = rhs.reservedApplicationNamesByID.find(applicationID);
      if (it == rhs.reservedApplicationNamesByID.end() || it->second.equals(name) == false)
      {
         return false;
      }
   }

   for (uint32_t index = 0; index < lhs.reservedApplicationServices.size(); ++index)
   {
      if (equalSerializedObjects(lhs.reservedApplicationServices[index], rhs.reservedApplicationServices[index]) == false)
      {
         return false;
      }
   }

   for (const auto& [deploymentID, failure] : lhs.failedDeployments)
   {
      auto it = rhs.failedDeployments.find(deploymentID);
      if (it == rhs.failedDeployments.end() || it->second.equals(failure) == false)
      {
         return false;
      }
   }

   return true;
}

static bool equalBrainSnapshots(const ProdigyPersistentBrainSnapshot& lhs, const ProdigyPersistentBrainSnapshot& rhs)
{
   if (lhs.brainPeers.size() != rhs.brainPeers.size()
      || lhs.topology != rhs.topology
      || equalBrainConfigs(lhs.brainConfig, rhs.brainConfig) == false
      || equalMasterAuthorityPackages(lhs.masterAuthority, rhs.masterAuthority) == false
      || equalMetricSamples(lhs.metricSamples, rhs.metricSamples) == false)
   {
      return false;
   }

   for (uint32_t index = 0; index < lhs.brainPeers.size(); ++index)
   {
      if (lhs.brainPeers[index] != rhs.brainPeers[index])
      {
         return false;
      }
   }

   return true;
}

static void testPersistentBrainSnapshotLargeMetricSampleRoundtrip(TestSuite& suite)
{
   ProdigyPersistentBrainSnapshot snapshot = {};
   constexpr uint32_t sampleCount = 70'000;
   snapshot.metricSamples.reserve(sampleCount);

   for (uint32_t index = 0; index < sampleCount; ++index)
   {
      ProdigyMetricSample sample = {};
      sample.ms = 1700000000000 + int64_t(index);
      sample.deploymentID = 0x510000 + uint64_t(index % 11);
      sample.containerUUID = uint128_t(0x990000) + index;
      sample.metricKey = ProdigyMetrics::runtimeContainerCpuUtilPctKey() + uint64_t(index % 3);
      sample.value = float(index % 1000) / 10.0f;
      snapshot.metricSamples.push_back(sample);
   }

   String serialized = {};
   BitseryEngine::serialize(serialized, snapshot);

   ProdigyPersistentBrainSnapshot decoded = {};
   const bool deserialized = BitseryEngine::deserializeSafe(serialized, decoded);
   suite.expect(deserialized, "persistent_snapshot_large_metric_samples_deserializes");
   suite.expect(decoded.metricSamples.size() == sampleCount, "persistent_snapshot_large_metric_sample_count");
   suite.expect(
      decoded.metricSamples.size() == sampleCount
         && decoded.metricSamples.front() == snapshot.metricSamples.front()
         && decoded.metricSamples.back() == snapshot.metricSamples.back(),
      "persistent_snapshot_large_metric_sample_edges");
}

static ProdigyBootstrapConfig::BootstrapPeer makeBootstrapPeer(const char *address, uint8_t cidr)
{
   ProdigyBootstrapConfig::BootstrapPeer peer = {};
   ClusterMachinePeerAddress candidate = {};
   candidate.address.assign(address);
   candidate.cidr = cidr;
   peer.addresses.push_back(candidate);
   return peer;
}

static NeuronBGPPeerConfig makeBGPConfigPeer(const char *peerAddress, const char *sourceAddress, uint16_t peerASN, const char *md5Password, uint8_t hopLimit)
{
   NeuronBGPPeerConfig peer = {};
   peer.peerASN = peerASN;
   peer.peerAddress = IPAddress(peerAddress, std::strchr(peerAddress, ':') != nullptr);
   peer.sourceAddress = IPAddress(sourceAddress, std::strchr(sourceAddress, ':') != nullptr);
   peer.md5Password.assign(md5Password);
   peer.hopLimit = hopLimit;
   return peer;
}

static bool equalLocalBrainStates(const ProdigyPersistentLocalBrainState& lhs, const ProdigyPersistentLocalBrainState& rhs)
{
   return lhs.uuid == rhs.uuid
      && lhs.ownerClusterUUID == rhs.ownerClusterUUID
      && lhs.transportTLS == rhs.transportTLS;
}

static bool generateApplicationTlsFactory(ApplicationTlsVaultFactory& factory, String& failure)
{
   failure.clear();

   X509 *rootCert = nullptr;
   EVP_PKEY *rootKey = nullptr;
   X509 *intermediateCert = nullptr;
   EVP_PKEY *intermediateKey = nullptr;

   VaultCertificateRequest rootRequest = {};
   rootRequest.type = CertificateType::root;
   rootRequest.scheme = CryptoScheme::ed25519;
   generateCertificateAndKeys(rootRequest, nullptr, nullptr, rootCert, rootKey);

   VaultCertificateRequest intermediateRequest = {};
   intermediateRequest.type = CertificateType::intermediary;
   intermediateRequest.scheme = CryptoScheme::ed25519;
   generateCertificateAndKeys(intermediateRequest, rootCert, rootKey, intermediateCert, intermediateKey);

   bool ok = (rootCert != nullptr)
      && (rootKey != nullptr)
      && (intermediateCert != nullptr)
      && (intermediateKey != nullptr)
      && VaultPem::x509ToPem(rootCert, factory.rootCertPem)
      && VaultPem::privateKeyToPem(rootKey, factory.rootKeyPem)
      && VaultPem::x509ToPem(intermediateCert, factory.intermediateCertPem)
      && VaultPem::privateKeyToPem(intermediateKey, factory.intermediateKeyPem);

   if (rootCert) X509_free(rootCert);
   if (rootKey) EVP_PKEY_free(rootKey);
   if (intermediateCert) X509_free(intermediateCert);
   if (intermediateKey) EVP_PKEY_free(intermediateKey);

   if (ok == false)
   {
      failure.assign("failed to generate application tls factory"_ctv);
   }

   return ok;
}

int main(void)
{
   TestSuite suite;
   testPersistentBrainSnapshotLargeMetricSampleRoundtrip(suite);

   char scratch[] = "/tmp/nametag-prodigy-persistent-state-XXXXXX";
   char *created = mkdtemp(scratch);
   suite.expect(created != nullptr, "mkdtemp_created");
   if (created == nullptr)
   {
      return EXIT_FAILURE;
   }

   String dbPath;
   dbPath.assign(created);

   ProdigyPersistentBootState storedBootState = {};
   storedBootState.bootstrapConfig.bootstrapPeers.push_back(makeBootstrapPeer("10.0.0.10", 24));
   storedBootState.bootstrapConfig.bootstrapPeers.push_back(makeBootstrapPeer("10.0.0.11", 24));
   storedBootState.bootstrapConfig.nodeRole = ProdigyBootstrapNodeRole::brain;
   storedBootState.bootstrapConfig.controlSocketPath = "/run/prodigy/control.sock"_ctv;
   storedBootState.bootstrapSshUser = "root"_ctv;
   storedBootState.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
   String parseFailure;
   suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
         storedBootState.bootstrapSshPrivateKeyPath,
         storedBootState.bootstrapSshKeyPackage,
         &parseFailure),
      "persistent_boot_state_reads_bootstrap_ssh_key_package");
   suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
         prodigyTestSSHDHostPrivateKeyPath(),
         storedBootState.bootstrapSshHostKeyPackage,
         &parseFailure),
      "persistent_boot_state_reads_bootstrap_ssh_host_key_package");
   storedBootState.runtimeEnvironment.kind = ProdigyEnvironmentKind::aws;
   storedBootState.runtimeEnvironment.providerScope = "acct-test/us-east-1"_ctv;
   storedBootState.runtimeEnvironment.providerCredentialMaterial = "secret-1"_ctv;
   storedBootState.runtimeEnvironment.aws.bootstrapCredentialRefreshCommand = "aws configure export-credentials --format process"_ctv;
   storedBootState.runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint = "run `aws sso login`"_ctv;
   storedBootState.runtimeEnvironment.aws.instanceProfileName = "prodigy-controller-profile"_ctv;
   storedBootState.runtimeEnvironment.bgp.specified = true;
   storedBootState.runtimeEnvironment.bgp.config.enabled = true;
   storedBootState.runtimeEnvironment.bgp.config.ourBGPID = inet_addr("10.0.0.10");
   storedBootState.runtimeEnvironment.bgp.config.community = (uint32_t(20473) << 16) | 6000u;
   storedBootState.runtimeEnvironment.bgp.config.nextHop4 = IPAddress("10.0.0.1", false);
   storedBootState.runtimeEnvironment.bgp.config.nextHop6 = IPAddress("2001:db8::10", true);
   storedBootState.runtimeEnvironment.bgp.config.peers.push_back(makeBGPConfigPeer("169.254.1.1", "10.0.0.10", 64512, "peer-md5-v4", 2));
   storedBootState.runtimeEnvironment.bgp.config.peers.push_back(makeBGPConfigPeer("2001:19f0:ffff::1", "2001:db8::10", 64512, "peer-md5-v6", 3));
   prodigyApplyInternalRuntimeEnvironmentDefaults(storedBootState.runtimeEnvironment);
   storedBootState.initialTopology.version = 7;

   ClusterMachine bootTopologyMachine = {};
   bootTopologyMachine.source = ClusterMachineSource::created;
   bootTopologyMachine.backing = ClusterMachineBacking::cloud;
   bootTopologyMachine.kind = MachineConfig::MachineKind::vm;
   bootTopologyMachine.lifetime = MachineLifetime::ondemand;
   bootTopologyMachine.isBrain = true;
   bootTopologyMachine.cloud.schema = "vm-small"_ctv;
   bootTopologyMachine.cloud.providerMachineType = "c7i-flex.large"_ctv;
   bootTopologyMachine.cloud.cloudID = "i-0123456789abcdef0"_ctv;
   bootTopologyMachine.ssh.address = "44.223.80.52"_ctv;
   bootTopologyMachine.ssh.port = 22;
   bootTopologyMachine.ssh.user = "root"_ctv;
   bootTopologyMachine.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   prodigyAppendUniqueClusterMachineAddress(bootTopologyMachine.addresses.publicAddresses, "44.223.80.52"_ctv, 24, "44.223.80.1"_ctv);
   prodigyAppendUniqueClusterMachineAddress(bootTopologyMachine.addresses.privateAddresses, "10.0.0.10"_ctv, 24, "10.0.0.1"_ctv);
   bootTopologyMachine.totalLogicalCores = 2;
   bootTopologyMachine.totalMemoryMB = 4096;
   bootTopologyMachine.totalStorageMB = 20480;
   bootTopologyMachine.hardware.cpu.model = "Intel(R) Xeon(R) Platinum 8488C"_ctv;
   bootTopologyMachine.hardware.cpu.logicalCores = 2;
   bootTopologyMachine.hardware.memory.totalMB = 4096;
   bootTopologyMachine.hardware.inventoryComplete = true;
   MachineDiskHardwareProfile bootDisk = {};
   bootDisk.name = "nvme0n1"_ctv;
   bootDisk.sizeMB = 20480;
   bootTopologyMachine.hardware.disks.push_back(bootDisk);
   bootTopologyMachine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   bootTopologyMachine.ownedLogicalCores = 2;
   bootTopologyMachine.ownedMemoryMB = 4096;
   bootTopologyMachine.ownedStorageMB = 20480;
   storedBootState.initialTopology.machines.push_back(bootTopologyMachine);

   ProdigyPersistentBootState expectedManagedBootState = storedBootState;
   prodigyStripManagedCloudBootstrapCredentials(expectedManagedBootState.runtimeEnvironment);

   String bootJSON;
   renderProdigyPersistentBootStateJSON(storedBootState, bootJSON);
   suite.expect(bootJSON.size() > 0, "render_boot_state_json_nonempty");
   suite.expect(stringContains(bootJSON, "\"bootstrapSshUser\":\"root\""), "render_boot_state_json_bootstrap_ssh_user");
   suite.expect(stringContains(bootJSON, "\"bootstrapSshPrivateKeyPath\":\""), "render_boot_state_json_bootstrap_ssh_private_key_path");
   suite.expect(stringContains(bootJSON, "\"bootstrapSshKeyPackage\":{"), "render_boot_state_json_bootstrap_ssh_key_package");
   suite.expect(stringContains(bootJSON, "\"bootstrapSshHostKeyPackage\":{"), "render_boot_state_json_bootstrap_ssh_host_key_package");
   suite.expect(stringContains(bootJSON, "\"bootstrapLaunchTemplateName\":\"prodigy-bootstrap-us-east-1\""), "render_boot_state_json_launch_template_name");
   suite.expect(stringContains(bootJSON, "\"bootstrapLaunchTemplateVersion\":\"$Default\""), "render_boot_state_json_launch_template_version");
   suite.expect(stringContains(bootJSON, "\"instanceProfileName\":\"prodigy-controller-profile\""), "render_boot_state_json_instance_profile_name");
   suite.expect(stringContains(bootJSON, "\"providerCredentialMaterial\"") == false, "render_boot_state_json_scrubs_provider_credential");
   suite.expect(stringContains(bootJSON, "\"bootstrapCredentialRefreshCommand\":\"aws configure export-credentials --format process\"") == false, "render_boot_state_json_scrubs_refresh_command");
   suite.expect(stringContains(bootJSON, "\"bootstrapCredentialRefreshFailureHint\":\"run `aws sso login`\"") == false, "render_boot_state_json_scrubs_refresh_hint");
   suite.expect(stringContains(bootJSON, "\"bgp\":{\"enabled\":true"), "render_boot_state_json_bgp_present");
   suite.expect(stringContains(bootJSON, "\"bgpID\":\"10.0.0.10\""), "render_boot_state_json_bgp_id");
   suite.expect(stringContains(bootJSON, "\"peerAddress\":\"169.254.1.1\""), "render_boot_state_json_bgp_peer_v4");
   suite.expect(stringContains(bootJSON, "\"peerAddress\":\"2001:19f0:ffff::1\""), "render_boot_state_json_bgp_peer_v6");

   String printedBootJSON = {};
   renderProdigyPersistentBootStateJSON(storedBootState, printedBootJSON, true);
   String printedBootstrapPublicKey = storedBootState.bootstrapSshKeyPackage.publicKeyOpenSSH;
   while (printedBootstrapPublicKey.size() > 0
      && (printedBootstrapPublicKey[printedBootstrapPublicKey.size() - 1] == '\n'
         || printedBootstrapPublicKey[printedBootstrapPublicKey.size() - 1] == '\r'))
   {
      printedBootstrapPublicKey.trim(1);
   }
   String printedHostPublicKey = storedBootState.bootstrapSshHostKeyPackage.publicKeyOpenSSH;
   while (printedHostPublicKey.size() > 0
      && (printedHostPublicKey[printedHostPublicKey.size() - 1] == '\n'
         || printedHostPublicKey[printedHostPublicKey.size() - 1] == '\r'))
   {
      printedHostPublicKey.trim(1);
   }
   suite.expect(printedBootJSON.size() > 0, "render_print_boot_state_json_nonempty");
   suite.expect(stringContains(printedBootJSON, "\"privateKeyOpenSSH\":\"[redacted]\""), "render_print_boot_state_json_redacts_private_key_material");
   suite.expect(stringContains(printedBootJSON, "-----BEGIN OPENSSH PRIVATE KEY-----") == false, "render_print_boot_state_json_omits_private_key_material");
   suite.expect(stringContains(printedBootJSON, printedBootstrapPublicKey.c_str()), "render_print_boot_state_json_preserves_bootstrap_public_key");
   suite.expect(stringContains(printedBootJSON, printedHostPublicKey.c_str()), "render_print_boot_state_json_preserves_host_public_key");
   suite.expect(stringContains(printedBootJSON, "\"providerCredentialMaterial\"") == false, "render_print_boot_state_json_scrubs_provider_credential");

   ProdigyPersistentBootState parsedBootState = {};
   suite.expect(parseProdigyPersistentBootStateJSON(bootJSON, parsedBootState, &parseFailure), "parse_rendered_boot_state_json");
   suite.expect(equalBootStates(expectedManagedBootState, parsedBootState), "parse_rendered_boot_state_roundtrip");
   suite.expect(parsedBootState.runtimeEnvironment.providerCredentialMaterial.size() == 0, "parse_rendered_boot_state_scrubs_provider_credential");
   suite.expect(parsedBootState.runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.size() == 0, "parse_rendered_boot_state_scrubs_refresh_command");
   ClusterTopology resolvedInitialTopology = {};
   suite.expect(prodigyResolveInitialTopologyFromBootState(parsedBootState, resolvedInitialTopology), "resolve_initial_topology_from_boot_state");
   suite.expect(resolvedInitialTopology == storedBootState.initialTopology, "resolve_initial_topology_matches");

   BrainConfig backfilledBrainConfig = {};
   prodigyBackfillBrainConfigSSHFromBootState(parsedBootState, backfilledBrainConfig);
   suite.expect(backfilledBrainConfig.bootstrapSshUser.equals(parsedBootState.bootstrapSshUser), "boot_state_backfills_brain_config_ssh_user");
   suite.expect(backfilledBrainConfig.bootstrapSshKeyPackage == parsedBootState.bootstrapSshKeyPackage, "boot_state_backfills_brain_config_ssh_key_package");
   suite.expect(backfilledBrainConfig.bootstrapSshHostKeyPackage == parsedBootState.bootstrapSshHostKeyPackage, "boot_state_backfills_brain_config_ssh_host_key_package");
   suite.expect(backfilledBrainConfig.bootstrapSshPrivateKeyPath.equals(parsedBootState.bootstrapSshPrivateKeyPath), "boot_state_backfills_brain_config_ssh_private_key_path");

   {
      PersistentStateTestBrain masterBrain = {};
      masterBrain.weAreMaster = true;

      String reserveFailure = {};
      suite.expect(masterBrain.reserveApplicationIDMapping("TopicServiceApp"_ctv, 52000, &reserveFailure), "persistent_master_service_topic_seed_application");

      Mothership mothership = {};
      String requestBuffer = {};
      ApplicationServiceReserveRequest request = {};
      request.applicationID = 52000;
      request.applicationName.assign("TopicServiceApp"_ctv);
      request.serviceName.assign("clients"_ctv);
      request.kind = ApplicationServiceIdentity::Kind::stateless;

      String serializedRequest = {};
      BitseryEngine::serialize(serializedRequest, request);
      Message *message = buildMothershipMessage(requestBuffer, MothershipTopic::reserveServiceID, serializedRequest);
      masterBrain.mothershipHandler(&mothership, message);

      ApplicationServiceReserveResponse response = {};
      response.success = false;
      suite.expect(mothership.wBuffer.size() >= sizeof(Message), "persistent_master_service_topic_emits_response");
      if (mothership.wBuffer.size() >= sizeof(Message))
      {
         Message *responseMessage = reinterpret_cast<Message *>(mothership.wBuffer.data());
         String serializedResponse = {};
         uint8_t *args = responseMessage->args;
         Message::extractToStringView(args, serializedResponse);
         suite.expect(BitseryEngine::deserializeSafe(serializedResponse, response), "persistent_master_service_topic_deserializes_response");
      }

      suite.expect(response.success, "persistent_master_service_topic_creates_service");
      suite.expect(masterBrain.persistCalls == 1, "persistent_master_service_topic_persists_created_service");
   }

   {
      PersistentStateTestBrain followerBrain = {};
      followerBrain.noMasterYet = false;

      String reserveFailure = {};
      suite.expect(followerBrain.reserveApplicationIDMapping("ReplicaPersistentApp"_ctv, 53000, &reserveFailure), "persistent_replica_service_seed_application");

      ApplicationServiceIdentity incomingService = {};
      incomingService.applicationID = 53000;
      incomingService.serviceName.assign("siblings"_ctv);
      incomingService.serviceSlot = 2;
      incomingService.kind = ApplicationServiceIdentity::Kind::stateful;

      BrainView peer = {};
      String messageBuffer = {};
      String serialized = {};
      BitseryEngine::serialize(serialized, incomingService);
      Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateApplicationServiceReservation, serialized);
      followerBrain.brainHandler(&peer, message);

      ApplicationServiceIdentity restoredReplicaService = {};
      suite.expect(
         followerBrain.resolveReservedApplicationService(53000, "siblings"_ctv, restoredReplicaService),
         "persistent_replica_service_apply_restores_mapping");
      suite.expect(restoredReplicaService.serviceSlot == 2, "persistent_replica_service_apply_restores_slot");
      suite.expect(followerBrain.persistCalls == 1, "persistent_replica_service_apply_persists_runtime_state");
   }

   ProdigyPersistentBrainSnapshot storedSnapshot = {};
   storedSnapshot.brainPeers.push_back(makeBootstrapPeer("10.0.0.10", 24));
   storedSnapshot.brainPeers.push_back(makeBootstrapPeer("10.0.0.11", 24));
   storedSnapshot.topology.version = 4;
   storedSnapshot.brainConfig.datacenterFragment = 9;
   storedSnapshot.brainConfig.clusterUUID = 0x3301;
   storedSnapshot.brainConfig.autoscaleIntervalSeconds = 91;
   storedSnapshot.brainConfig.sharedCPUOvercommitPermille = 1500;
   storedSnapshot.brainConfig.requiredBrainCount = 3;
   storedSnapshot.brainConfig.architecture = MachineCpuArchitecture::x86_64;
   storedSnapshot.brainConfig.bootstrapSshUser = "root"_ctv;
   storedSnapshot.brainConfig.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
   storedSnapshot.brainConfig.remoteProdigyPath = "/opt/prodigy"_ctv;
   storedSnapshot.brainConfig.controlSocketPath = "/run/prodigy/control.sock"_ctv;
   storedSnapshot.brainConfig.vmImageURI = "image://abc"_ctv;
   storedSnapshot.brainConfig.runtimeEnvironment = storedBootState.runtimeEnvironment;
   storedSnapshot.brainConfig.reporter.to = "ops@prodigy.local"_ctv;
   storedSnapshot.brainConfig.reporter.from = "prodigy@prodigy.local"_ctv;
   storedSnapshot.brainConfig.reporter.smtp = "smtp://mail.prodigy.local:587"_ctv;
   storedSnapshot.brainConfig.reporter.password = "smtp-app-password"_ctv;
   suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
         prodigyTestBootstrapSeedSSHPrivateKeyPath(),
         storedSnapshot.brainConfig.bootstrapSshKeyPackage,
         &parseFailure),
      "persistent_snapshot_reads_bootstrap_ssh_key_package");
   suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
         prodigyTestSSHDHostPrivateKeyPath(),
         storedSnapshot.brainConfig.bootstrapSshHostKeyPackage,
         &parseFailure),
      "persistent_snapshot_reads_bootstrap_ssh_host_key_package");

   MachineConfig config = {};
   config.kind = MachineConfig::MachineKind::vm;
   config.slug = "vm-small"_ctv;
   config.nLogicalCores = 4;
   config.nMemoryMB = 8192;
   config.nStorageMB = 102400;
   config.vmImageURI = "image://abc"_ctv;
   config.gcpInstanceTemplate = "tmpl-a"_ctv;
   config.gcpInstanceTemplateSpot = "tmpl-a-spot"_ctv;
   config.providesHostPublic4 = true;
   storedSnapshot.brainConfig.configBySlug.insert_or_assign(config.slug, config);

   ClusterMachine topologyMachine = {};
   topologyMachine.source = ClusterMachineSource::created;
   topologyMachine.backing = ClusterMachineBacking::cloud;
   topologyMachine.kind = config.kind;
   topologyMachine.lifetime = MachineLifetime::owned;
   topologyMachine.isBrain = true;
   topologyMachine.cloud.schema = config.slug;
   topologyMachine.cloud.providerMachineType = "n2-standard-4"_ctv;
   topologyMachine.cloud.cloudID = "789654123000111"_ctv;
   topologyMachine.ssh.address = "10.0.0.10"_ctv;
   topologyMachine.ssh.port = 22;
   topologyMachine.ssh.user = "root"_ctv;
   topologyMachine.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   suite.expect(prodigyReadBootstrapSSHPublicKey(prodigyTestSSHDHostPrivateKeyPath(), topologyMachine.ssh.hostPublicKeyOpenSSH, &parseFailure), "persistent_snapshot_reads_machine_host_public_key");
   prodigyAppendUniqueClusterMachineAddress(topologyMachine.addresses.privateAddresses, "10.0.0.10"_ctv, 24, "10.0.0.1"_ctv);
   topologyMachine.creationTimeMs = 123456789;
   topologyMachine.totalLogicalCores = 4;
   topologyMachine.totalMemoryMB = 8192;
   topologyMachine.totalStorageMB = 102400;
   topologyMachine.hardware.cpu.model = "Intel(R) Xeon(R) Platinum 8488C"_ctv;
   topologyMachine.hardware.cpu.logicalCores = 4;
   topologyMachine.hardware.memory.totalMB = 8192;
   topologyMachine.hardware.inventoryComplete = true;
   MachineDiskHardwareProfile topologyDisk = {};
   topologyDisk.name = "nvme1n1"_ctv;
   topologyDisk.sizeMB = 102400;
   topologyMachine.hardware.disks.push_back(topologyDisk);
   topologyMachine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   topologyMachine.ownedLogicalCores = 2;
   topologyMachine.ownedMemoryMB = 4096;
   topologyMachine.ownedStorageMB = 98304;
   storedSnapshot.topology.machines.push_back(topologyMachine);
   ProdigyPersistentLocalBrainState storedLocalBrainState = {};
   storedLocalBrainState.uuid = (uint128_t(0x1122334455667788ULL) << 64) | uint128_t(0x99AABBCCDDEEFF00ULL);
   storedLocalBrainState.ownerClusterUUID = (uint128_t(0x0102030405060708ULL) << 64) | uint128_t(0x1112131415161718ULL);
   suite.expect(Vault::generateTransportRootCertificateEd25519(
      storedLocalBrainState.transportTLS.clusterRootCertPem,
      storedLocalBrainState.transportTLS.clusterRootKeyPem,
      &parseFailure), "generate_transport_root_certificate");
   suite.expect(Vault::generateTransportNodeCertificateEd25519(
      storedLocalBrainState.transportTLS.clusterRootCertPem,
      storedLocalBrainState.transportTLS.clusterRootKeyPem,
      storedLocalBrainState.uuid,
      {},
      storedLocalBrainState.transportTLS.localCertPem,
      storedLocalBrainState.transportTLS.localKeyPem,
      &parseFailure), "generate_transport_local_certificate");
   storedLocalBrainState.transportTLS.generation = 7;
   suite.expect(storedLocalBrainState.transportTLSConfigured(), "stored_local_brain_state_transport_tls_configured");
   suite.expect(storedLocalBrainState.canMintTransportTLS(), "stored_local_brain_state_transport_tls_can_mint");

   const uint16_t applicationID = 51000;

   ApplicationTlsVaultFactory storedFactory = {};
   storedFactory.applicationID = applicationID;
   storedFactory.factoryGeneration = 3;
   storedFactory.keySourceMode = 1;
   storedFactory.scheme = uint8_t(CryptoScheme::ed25519);
   storedFactory.defaultLeafValidityDays = 30;
   storedFactory.renewLeadPercent = 15;
   storedFactory.createdAtMs = 123456700;
   storedFactory.updatedAtMs = 123456799;
   suite.expect(generateApplicationTlsFactory(storedFactory, parseFailure), "generate_application_tls_factory");

   ApplicationApiCredentialSet storedCredentialSet = {};
   storedCredentialSet.applicationID = applicationID;
   storedCredentialSet.setGeneration = 9;
   storedCredentialSet.createdAtMs = 123456701;
   storedCredentialSet.updatedAtMs = 123456800;

   ApiCredential storedCredential = {};
   storedCredential.name.assign("telnyx_bearer"_ctv);
   storedCredential.provider.assign("telnyx"_ctv);
   storedCredential.generation = 2;
   storedCredential.material.assign("secret-token"_ctv);
   storedCredentialSet.credentials.push_back(storedCredential);

   DeploymentPlan storedPlan = {};
   storedPlan.config.applicationID = applicationID;
   storedPlan.config.versionID = 77;
   storedPlan.config.filesystemMB = 128;
   storedPlan.config.storageMB = 256;
   storedPlan.config.memoryMB = 512;
   storedPlan.config.nLogicalCores = 2;
   storedPlan.config.msTilHealthy = 1000;
   storedPlan.config.sTilHealthcheck = 5;
   storedPlan.config.sTilKillable = 30;
   storedPlan.minimumSubscriberCapacity = 1;
   storedPlan.isStateful = false;
   storedPlan.stateless.nBase = 2;
   storedPlan.stateless.maxPerRackRatio = 0.6f;
   storedPlan.stateless.maxPerMachineRatio = 0.5f;
   storedPlan.canaryCount = 1;
   storedPlan.canariesMustLiveForMinutes = 5;
   storedPlan.moveConstructively = true;
   storedPlan.requiresDatacenterUniqueTag = true;
   storedPlan.hasTlsIssuancePolicy = true;
   storedPlan.tlsIssuancePolicy.applicationID = applicationID;
   storedPlan.tlsIssuancePolicy.enablePerContainerLeafs = true;
   storedPlan.tlsIssuancePolicy.identityNames.push_back("ingress"_ctv);
   storedPlan.hasApiCredentialPolicy = true;
   storedPlan.apiCredentialPolicy.applicationID = applicationID;
   storedPlan.apiCredentialPolicy.requiredCredentialNames.push_back("telnyx_bearer"_ctv);

   storedSnapshot.masterAuthority.tlsVaultFactoriesByApp.insert_or_assign(applicationID, storedFactory);
   storedSnapshot.masterAuthority.apiCredentialSetsByApp.insert_or_assign(applicationID, storedCredentialSet);
   storedSnapshot.masterAuthority.reservedApplicationIDsByName.insert_or_assign("PersistentApp"_ctv, applicationID);
   storedSnapshot.masterAuthority.reservedApplicationNamesByID.insert_or_assign(applicationID, "PersistentApp"_ctv);
   ApplicationServiceIdentity storedService = {};
   storedService.applicationID = applicationID;
   storedService.serviceName.assign("clients"_ctv);
   storedService.serviceSlot = 1;
   storedService.kind = ApplicationServiceIdentity::Kind::stateful;
   storedSnapshot.masterAuthority.reservedApplicationServices.push_back(storedService);
   ApplicationServiceIdentity storedSiblingService = {};
   storedSiblingService.applicationID = applicationID;
   storedSiblingService.serviceName.assign("siblings"_ctv);
   storedSiblingService.serviceSlot = 2;
   storedSiblingService.kind = ApplicationServiceIdentity::Kind::stateful;
   storedSnapshot.masterAuthority.reservedApplicationServices.push_back(storedSiblingService);
   storedSnapshot.masterAuthority.nextReservableApplicationID = uint16_t(applicationID + 1);
   storedSnapshot.masterAuthority.deploymentPlans.insert_or_assign(storedPlan.config.deploymentID(), storedPlan);
   storedSnapshot.masterAuthority.failedDeployments.insert_or_assign(storedPlan.config.deploymentID(), "healthcheck timeout"_ctv);
   storedSnapshot.masterAuthority.runtimeState.generation = 19;
   storedSnapshot.masterAuthority.runtimeState.nextMintedClientTlsGeneration = 123;
   prodigyBuildTransportTLSAuthority(storedLocalBrainState, storedSnapshot.masterAuthority.runtimeState.transportTLSAuthority);
   storedSnapshot.masterAuthority.runtimeState.updateSelf.state = 2;
   storedSnapshot.masterAuthority.runtimeState.updateSelf.expectedEchos = 3;
   storedSnapshot.masterAuthority.runtimeState.updateSelf.bundleEchos = 2;
   storedSnapshot.masterAuthority.runtimeState.updateSelf.relinquishEchos = 1;
   storedSnapshot.masterAuthority.runtimeState.updateSelf.plannedMasterPeerKey = storedLocalBrainState.uuid + 1;
   storedSnapshot.masterAuthority.runtimeState.updateSelf.pendingDesignatedMasterPeerKey = storedLocalBrainState.uuid + 2;
   storedSnapshot.masterAuthority.runtimeState.updateSelf.useStagedBundleOnly = true;
   storedSnapshot.masterAuthority.runtimeState.updateSelf.bundleBlob.assign("bundle-bytes"_ctv);
   storedSnapshot.masterAuthority.runtimeState.updateSelf.bundleEchoPeerKeys.push_back(storedLocalBrainState.uuid + 3);
   storedSnapshot.masterAuthority.runtimeState.updateSelf.relinquishEchoPeerKeys.push_back(storedLocalBrainState.uuid + 4);
   ProdigyPersistentUpdateSelfFollowerBoot followerBoot = {};
   followerBoot.peerKey = storedLocalBrainState.uuid + 5;
   followerBoot.bootNs = 444;
   storedSnapshot.masterAuthority.runtimeState.updateSelf.followerBootNsByPeerKey.push_back(followerBoot);
   storedSnapshot.masterAuthority.runtimeState.updateSelf.followerRebootedPeerKeys.push_back(storedLocalBrainState.uuid + 6);
   storedSnapshot.masterAuthority.runtimeState.nextPendingAddMachinesOperationID = 9;
   ProdigyPendingAddMachinesOperation pendingAddMachinesOperation = {};
   pendingAddMachinesOperation.operationID = 7;
   pendingAddMachinesOperation.request.bootstrapSshUser.assign("root"_ctv);
   pendingAddMachinesOperation.request.bootstrapSshPrivateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
         prodigyTestClientSSHPrivateKeyPath(),
         pendingAddMachinesOperation.request.bootstrapSshKeyPackage,
         &parseFailure),
      "persistent_snapshot_reads_pending_bootstrap_ssh_key_package");
   pendingAddMachinesOperation.request.bootstrapSshHostKeyPackage = storedSnapshot.brainConfig.bootstrapSshHostKeyPackage;
   pendingAddMachinesOperation.request.remoteProdigyPath.assign("/usr/local/bin/prodigy"_ctv);
   pendingAddMachinesOperation.request.controlSocketPath.assign("/run/prodigy/control.sock"_ctv);
   pendingAddMachinesOperation.request.clusterUUID = 0x22002200;
   pendingAddMachinesOperation.plannedTopology = storedSnapshot.topology;
   pendingAddMachinesOperation.plannedTopology.machines.push_back(ClusterMachine {});
   ClusterMachine& plannedMachine = pendingAddMachinesOperation.plannedTopology.machines.back();
   plannedMachine.source = ClusterMachineSource::created;
   plannedMachine.backing = ClusterMachineBacking::cloud;
   plannedMachine.kind = config.kind;
   plannedMachine.lifetime = MachineLifetime::owned;
   plannedMachine.isBrain = true;
   plannedMachine.hasCloud = true;
   plannedMachine.cloud.schema.assign(config.slug);
   plannedMachine.cloud.providerMachineType.assign("n2-standard-4"_ctv);
   plannedMachine.uuid = storedLocalBrainState.uuid + 12;
   prodigyAppendUniqueClusterMachineAddress(plannedMachine.addresses.privateAddresses, "10.0.0.12"_ctv, 24, "10.0.0.1"_ctv);
   plannedMachine.ssh.address.assign("10.0.0.12"_ctv);
   plannedMachine.ssh.port = 22;
   plannedMachine.ssh.user.assign("root"_ctv);
   plannedMachine.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   plannedMachine.ssh.hostPublicKeyOpenSSH = storedSnapshot.brainConfig.bootstrapSshHostKeyPackage.publicKeyOpenSSH;
   plannedMachine.cloud.cloudID.assign("789654123000112"_ctv);
   pendingAddMachinesOperation.machinesToBootstrap.push_back(plannedMachine);
   pendingAddMachinesOperation.resumeAttempts = 2;
   pendingAddMachinesOperation.updatedAtMs = 123456812;
   pendingAddMachinesOperation.lastFailure.assign("waiting for promotion"_ctv);
   storedSnapshot.masterAuthority.runtimeState.pendingAddMachinesOperations.push_back(pendingAddMachinesOperation);

   ProdigyMetricSample metricA = {};
   metricA.ms = 1700000001000;
   metricA.deploymentID = storedPlan.config.deploymentID();
   metricA.containerUUID = storedLocalBrainState.uuid + 10;
   metricA.metricKey = ProdigyMetrics::runtimeContainerCpuUtilPctKey();
   metricA.value = 42.5f;
   storedSnapshot.metricSamples.push_back(metricA);

   ProdigyMetricSample metricB = {};
   metricB.ms = 1700000002000;
   metricB.deploymentID = storedPlan.config.deploymentID();
   metricB.containerUUID = storedLocalBrainState.uuid + 11;
   metricB.metricKey = ProdigyMetrics::runtimeContainerMemoryUtilPctKey();
   metricB.value = 64.0f;
   storedSnapshot.metricSamples.push_back(metricB);

   ProdigyPersistentBrainSnapshot expectedManagedSnapshot = storedSnapshot;
   prodigyStripManagedCloudBootstrapCredentials(expectedManagedSnapshot.brainConfig.runtimeEnvironment);

   ProdigyPersistentBrainSnapshot captureRichSnapshot = storedSnapshot;
   MachineToolCapture hardwareCapture = {};
   hardwareCapture.tool = "lscpu"_ctv;
   hardwareCapture.phase = "inventory"_ctv;
   hardwareCapture.command = "lscpu --json"_ctv;
   hardwareCapture.output = "cpu capture output that should not persist"_ctv;
   hardwareCapture.exitCode = 0;
   hardwareCapture.attempted = true;
   hardwareCapture.succeeded = true;
   captureRichSnapshot.topology.machines[0].hardware.captures.push_back(hardwareCapture);
   captureRichSnapshot.topology.machines[0].hardware.cpu.captures.push_back(hardwareCapture);

   ProdigyPersistentBrainSnapshot expectedCaptureStrippedSnapshot = captureRichSnapshot;
   prodigyStripManagedCloudBootstrapCredentials(expectedCaptureStrippedSnapshot.brainConfig.runtimeEnvironment);
   prodigyStripMachineHardwareCapturesFromClusterTopology(expectedCaptureStrippedSnapshot.topology);

   {
      ProdigyPersistentBrainSnapshot cachedSnapshot = {};
      ProdigyPersistentBrainSnapshot initialSnapshot = expectedManagedSnapshot;
      prodigyReplaceCachedBrainSnapshot(cachedSnapshot, std::move(initialSnapshot));
      suite.expect(equalBrainSnapshots(expectedManagedSnapshot, cachedSnapshot), "cached_snapshot_replace_initial");

      ProdigyPersistentBrainSnapshot expectedReplacementSnapshot = expectedManagedSnapshot;
      expectedReplacementSnapshot.brainPeers.pop_back();
      expectedReplacementSnapshot.topology.version += 1;
      expectedReplacementSnapshot.masterAuthority.deploymentPlans.clear();
      expectedReplacementSnapshot.masterAuthority.failedDeployments.clear();
      DeploymentPlan replacementPlan = storedPlan;
      replacementPlan.config.applicationID = uint16_t(applicationID + 1);
      replacementPlan.config.versionID += 1;
      expectedReplacementSnapshot.masterAuthority.deploymentPlans.insert_or_assign(replacementPlan.config.deploymentID(), replacementPlan);
      expectedReplacementSnapshot.masterAuthority.failedDeployments.insert_or_assign(replacementPlan.config.deploymentID(), "replacement failure"_ctv);
      expectedReplacementSnapshot.masterAuthority.runtimeState.generation += 1;
      expectedReplacementSnapshot.metricSamples.clear();
      expectedReplacementSnapshot.metricSamples.push_back(metricB);

      ProdigyPersistentBrainSnapshot replacementSnapshot = expectedReplacementSnapshot;
      prodigyReplaceCachedBrainSnapshot(cachedSnapshot, std::move(replacementSnapshot));
      suite.expect(equalBrainSnapshots(expectedReplacementSnapshot, cachedSnapshot), "cached_snapshot_replace_overwrites_previous");
      suite.expect(
         cachedSnapshot.masterAuthority.deploymentPlans.contains(storedPlan.config.deploymentID()) == false,
         "cached_snapshot_replace_drops_previous_deployment_plan");
   }

   {
      ProdigyPersistentBrainSnapshot publicSnapshot = {};
      ProdigyPersistentBrainSnapshotSecrets extractedSecrets = {};
      ProdigyPersistentBrainSnapshot extractionSource = expectedManagedSnapshot;
      prodigyExtractPersistentBrainSnapshotSecrets(std::move(extractionSource), publicSnapshot, extractedSecrets);

      suite.expect(publicSnapshot.topology == expectedManagedSnapshot.topology, "extract_snapshot_secrets_preserves_topology");
      suite.expect(
         equalMapBySerializedValue(publicSnapshot.masterAuthority.deploymentPlans, expectedManagedSnapshot.masterAuthority.deploymentPlans),
         "extract_snapshot_secrets_preserves_deployment_plans");
      suite.expect(
         extractedSecrets.bootstrapSshPrivateKeyOpenSSH.equals(expectedManagedSnapshot.brainConfig.bootstrapSshKeyPackage.privateKeyOpenSSH),
         "extract_snapshot_secrets_captures_bootstrap_private_key");
      suite.expect(
         extractedSecrets.bootstrapSshHostPrivateKeyOpenSSH.equals(expectedManagedSnapshot.brainConfig.bootstrapSshHostKeyPackage.privateKeyOpenSSH),
         "extract_snapshot_secrets_captures_bootstrap_host_private_key");
      suite.expect(
         extractedSecrets.reporterPassword.equals(expectedManagedSnapshot.brainConfig.reporter.password),
         "extract_snapshot_secrets_captures_reporter_password");
      suite.expect(publicSnapshot.brainConfig.bootstrapSshKeyPackage.privateKeyOpenSSH.size() == 0, "extract_snapshot_secrets_scrubs_bootstrap_private_key");
      suite.expect(publicSnapshot.brainConfig.bootstrapSshHostKeyPackage.privateKeyOpenSSH.size() == 0, "extract_snapshot_secrets_scrubs_bootstrap_host_private_key");
      suite.expect(publicSnapshot.brainConfig.reporter.password.size() == 0, "extract_snapshot_secrets_scrubs_reporter_password");

      auto publicFactoryIt = publicSnapshot.masterAuthority.tlsVaultFactoriesByApp.find(applicationID);
      suite.expect(publicFactoryIt != publicSnapshot.masterAuthority.tlsVaultFactoriesByApp.end(), "extract_snapshot_secrets_keeps_tls_factory");
      if (publicFactoryIt != publicSnapshot.masterAuthority.tlsVaultFactoriesByApp.end())
      {
         suite.expect(publicFactoryIt->second.rootKeyPem.size() == 0, "extract_snapshot_secrets_scrubs_tls_root_key");
         suite.expect(publicFactoryIt->second.intermediateKeyPem.size() == 0, "extract_snapshot_secrets_scrubs_tls_intermediate_key");
      }

      auto secretFactoryIt = extractedSecrets.tlsVaultFactorySecretsByApp.find(applicationID);
      suite.expect(secretFactoryIt != extractedSecrets.tlsVaultFactorySecretsByApp.end(), "extract_snapshot_secrets_captures_tls_factory_keys");
      if (secretFactoryIt != extractedSecrets.tlsVaultFactorySecretsByApp.end())
      {
         suite.expect(secretFactoryIt->second.rootKeyPem.equals(storedFactory.rootKeyPem), "extract_snapshot_secrets_captures_tls_root_key");
         suite.expect(secretFactoryIt->second.intermediateKeyPem.equals(storedFactory.intermediateKeyPem), "extract_snapshot_secrets_captures_tls_intermediate_key");
      }

      auto publicCredentialIt = publicSnapshot.masterAuthority.apiCredentialSetsByApp.find(applicationID);
      suite.expect(publicCredentialIt != publicSnapshot.masterAuthority.apiCredentialSetsByApp.end(), "extract_snapshot_secrets_keeps_api_credential_set");
      if (publicCredentialIt != publicSnapshot.masterAuthority.apiCredentialSetsByApp.end())
      {
         suite.expect(publicCredentialIt->second.credentials.size() == 1, "extract_snapshot_secrets_keeps_api_credential_entries");
         if (publicCredentialIt->second.credentials.size() == 1)
         {
            suite.expect(publicCredentialIt->second.credentials[0].material.size() == 0, "extract_snapshot_secrets_scrubs_api_credential_material");
         }
      }

      auto secretCredentialIt = extractedSecrets.apiCredentialSecretsByApp.find(applicationID);
      suite.expect(secretCredentialIt != extractedSecrets.apiCredentialSecretsByApp.end(), "extract_snapshot_secrets_captures_api_credential_material");
      if (secretCredentialIt != extractedSecrets.apiCredentialSecretsByApp.end())
      {
         suite.expect(secretCredentialIt->second.credentials.size() == 1, "extract_snapshot_secrets_captures_api_credential_entries");
         if (secretCredentialIt->second.credentials.size() == 1)
         {
            suite.expect(secretCredentialIt->second.credentials[0].material.equals(storedCredential.material), "extract_snapshot_secrets_captures_api_credential_value");
         }
      }
   }

   String localBrainStateJSON = {};
   renderProdigyPersistentLocalBrainStateJSON(storedLocalBrainState, localBrainStateJSON);
   suite.expect(localBrainStateJSON.size() > 0, "render_local_brain_state_json_nonempty");
   suite.expect(stringContains(localBrainStateJSON, "\"ownerClusterUUID\":"), "render_local_brain_state_json_owner_cluster_uuid");
   suite.expect(stringContains(localBrainStateJSON, "\"generation\":7"), "render_local_brain_state_json_generation");

   ProdigyPersistentLocalBrainState parsedLocalBrainState = {};
   suite.expect(parseProdigyPersistentLocalBrainStateJSON(localBrainStateJSON, parsedLocalBrainState, &parseFailure), "parse_local_brain_state_json");
   suite.expect(equalLocalBrainStates(storedLocalBrainState, parsedLocalBrainState), "parse_local_brain_state_json_roundtrip");

   {
      ProdigyPersistentLocalBrainState backfilledLocalBrainState = {};
      backfilledLocalBrainState.uuid = storedLocalBrainState.uuid;
      bool ownerBackfilled = false;
      prodigyBackfillLocalBrainOwnerClusterUUID(backfilledLocalBrainState, storedSnapshot, &ownerBackfilled);
      suite.expect(ownerBackfilled, "backfill_local_brain_owner_cluster_uuid");
      suite.expect(backfilledLocalBrainState.ownerClusterUUID == storedSnapshot.brainConfig.clusterUUID, "backfill_local_brain_owner_cluster_uuid_value");

      bool ownerChanged = false;
      String ownershipFailure = {};
      suite.expect(prodigyEnsureLocalBrainOwnedByCluster(backfilledLocalBrainState, storedSnapshot.brainConfig.clusterUUID, &ownerChanged, &ownershipFailure), "ensure_local_brain_owned_by_existing_cluster");
      suite.expect(ownerChanged == false, "ensure_local_brain_owned_by_existing_cluster_no_change");
      suite.expect(ownershipFailure.size() == 0, "ensure_local_brain_owned_by_existing_cluster_clears_failure");

      suite.expect(prodigyEnsureLocalBrainOwnedByCluster(backfilledLocalBrainState, storedSnapshot.brainConfig.clusterUUID + 1, &ownerChanged, &ownershipFailure) == false, "ensure_local_brain_owned_by_cluster_rejects_takeover");
      suite.expect(stringContains(ownershipFailure, "refuses takeover"), "ensure_local_brain_owned_by_cluster_rejects_takeover_reason");
   }

   ProdigyTransportTLSBootstrap transportTLSBootstrap = {};
   prodigyBuildTransportTLSBootstrap(parsedLocalBrainState, transportTLSBootstrap);
   suite.expect(transportTLSBootstrap.configured(), "build_transport_tls_bootstrap_configured");
   suite.expect(transportTLSBootstrap.canMintForCluster(), "build_transport_tls_bootstrap_mint_authority");

   X509 *parsedLocalCert = VaultPem::x509FromPem(parsedLocalBrainState.transportTLS.localCertPem);
   uint128_t parsedLocalCertUUID = 0;
   suite.expect(Vault::extractTransportCertificateUUID(parsedLocalCert, parsedLocalCertUUID), "parse_local_brain_state_json_extract_leaf_uuid");
   suite.expect(parsedLocalCertUUID == parsedLocalBrainState.uuid, "parse_local_brain_state_json_leaf_uuid_matches");
   if (parsedLocalCert)
   {
      X509_free(parsedLocalCert);
   }

   {
      ProdigyPersistentStateStore store(dbPath);
      String failure;

      bool saveBoot = store.saveBootState(storedBootState, &failure);
      if (!saveBoot) basics_log("detail save_boot: %s\n", failure.c_str());
      suite.expect(saveBoot, "save_boot");

      bool saveSnapshot = store.saveBrainSnapshot(storedSnapshot, &failure);
      if (!saveSnapshot) basics_log("detail save_snapshot: %s\n", failure.c_str());
      suite.expect(saveSnapshot, "save_snapshot");

      bool saveLocalBrainState = store.saveLocalBrainState(storedLocalBrainState, &failure);
      if (!saveLocalBrainState) basics_log("detail save_local_brain_state: %s\n", failure.c_str());
      suite.expect(saveLocalBrainState, "save_local_brain_state");

      ProdigyPersistentBootState loadedBootState = {};
      bool loadBoot = store.loadBootState(loadedBootState, &failure);
      if (!loadBoot) basics_log("detail load_boot: %s\n", failure.c_str());
      suite.expect(loadBoot, "load_boot");
      suite.expect(equalBootStates(expectedManagedBootState, loadedBootState), "load_boot_roundtrip");
      suite.expect(loadedBootState.runtimeEnvironment.providerCredentialMaterial.size() == 0, "load_boot_scrubs_provider_credential");
      suite.expect(loadedBootState.runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.size() == 0, "load_boot_scrubs_refresh_command");

      ProdigyPersistentBrainSnapshot loadedSnapshot = {};
      bool loadSnapshot = store.loadBrainSnapshot(loadedSnapshot, &failure);
      if (!loadSnapshot) basics_log("detail load_snapshot: %s\n", failure.c_str());
      suite.expect(loadSnapshot, "load_snapshot");
      suite.expect(equalBrainSnapshots(expectedManagedSnapshot, loadedSnapshot), "load_snapshot_roundtrip");
      suite.expect(loadedSnapshot.brainConfig.runtimeEnvironment.providerCredentialMaterial.size() == 0, "load_snapshot_scrubs_provider_credential");
      suite.expect(loadedSnapshot.brainConfig.runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.size() == 0, "load_snapshot_scrubs_refresh_command");

      {
         PersistentStateTestBrain restoredBrain = {};
         restoredBrain.applyPersistentMasterAuthorityPackage(loadedSnapshot.masterAuthority);

         ApplicationServiceIdentity restoredClientsService = {};
         suite.expect(
            restoredBrain.resolveReservedApplicationService(applicationID, "clients"_ctv, restoredClientsService),
            "load_snapshot_restores_clients_service_reservation");
         suite.expect(restoredClientsService.serviceSlot == 1, "load_snapshot_restores_clients_service_slot");
         suite.expect(restoredClientsService.kind == ApplicationServiceIdentity::Kind::stateful, "load_snapshot_restores_clients_service_kind");

         ApplicationServiceIdentity restoredSiblingService = {};
         suite.expect(
            restoredBrain.resolveReservedApplicationService(applicationID, "siblings"_ctv, restoredSiblingService),
            "load_snapshot_restores_siblings_service_reservation");
         suite.expect(restoredSiblingService.serviceSlot == 2, "load_snapshot_restores_siblings_service_slot");
         suite.expect(restoredBrain.takeNextReservableServiceSlot(applicationID) == 3, "load_snapshot_restores_next_reservable_service_slot");
      }

      ProdigyPersistentLocalBrainState loadedLocalBrainState = {};
      bool loadLocalBrainState = store.loadLocalBrainState(loadedLocalBrainState, &failure);
      if (!loadLocalBrainState) basics_log("detail load_local_brain_state: %s\n", failure.c_str());
      suite.expect(loadLocalBrainState, "load_local_brain_state");
      suite.expect(equalLocalBrainStates(storedLocalBrainState, loadedLocalBrainState), "load_local_brain_state_roundtrip");
   }

   {
      String replaceLoopDbPath = dbPath;
      replaceLoopDbPath.append(".replace-loop"_ctv);
      suite.expect(cleanupPersistentStateRoots(replaceLoopDbPath), "cleanup_replace_loop_state_directory_before");

      ProdigyPersistentStateStore store(replaceLoopDbPath);
      String failure = {};
      ProdigyPersistentBrainSnapshot cachedSnapshot = {};
      ProdigyPersistentBrainSnapshot seedSnapshot = expectedManagedSnapshot;
      prodigyReplaceCachedBrainSnapshot(cachedSnapshot, std::move(seedSnapshot));

      bool repeatedSaveReplaceOk = true;
      ProdigyPersistentBrainSnapshot expectedFinalSnapshot = expectedManagedSnapshot;

      for (uint32_t round = 0; round < 24; round += 1)
      {
         ProdigyPersistentBrainSnapshot replacementSnapshot = expectedManagedSnapshot;
         replacementSnapshot.topology.version += uint32_t(round + 1);
         replacementSnapshot.masterAuthority.runtimeState.generation += uint64_t(round + 1);
         replacementSnapshot.masterAuthority.deploymentPlans.clear();
         replacementSnapshot.masterAuthority.failedDeployments.clear();
         replacementSnapshot.metricSamples.clear();

         for (uint32_t planIndex = 0; planIndex < 12; planIndex += 1)
         {
            DeploymentPlan replacementPlan = storedPlan;
            replacementPlan.config.applicationID = uint16_t(applicationID + 1 + ((round + planIndex) % 32));
            replacementPlan.config.versionID += uint64_t((round + 1) * 100 + planIndex + 1);
            String replacementFailure = {};
            replacementFailure.snprintf<"replacement failure round={itoa} plan={itoa}"_ctv>(
               uint64_t(round),
               uint64_t(planIndex));
            replacementSnapshot.masterAuthority.deploymentPlans.insert_or_assign(
               replacementPlan.config.deploymentID(),
               replacementPlan);
            replacementSnapshot.masterAuthority.failedDeployments.insert_or_assign(
               replacementPlan.config.deploymentID(),
               replacementFailure);
         }

         replacementSnapshot.metricSamples.push_back((round % 2) == 0 ? metricA : metricB);
         expectedFinalSnapshot = replacementSnapshot;

         failure.clear();
         if (store.saveBrainSnapshot(replacementSnapshot, &failure) == false)
         {
            basics_log("detail cached_snapshot_replace_after_save_loop round=%u failure=%s\n", round, failure.c_str());
            repeatedSaveReplaceOk = false;
            break;
         }

         prodigyReplaceCachedBrainSnapshot(cachedSnapshot, std::move(replacementSnapshot));
      }

      suite.expect(repeatedSaveReplaceOk, "cached_snapshot_replace_after_save_loop");
      suite.expect(equalBrainSnapshots(expectedFinalSnapshot, cachedSnapshot), "cached_snapshot_replace_after_save_loop_matches_last");

      ProdigyPersistentBrainSnapshot loadedLoopSnapshot = {};
      failure.clear();
      suite.expect(store.loadBrainSnapshot(loadedLoopSnapshot, &failure), "cached_snapshot_replace_after_save_loop_loads_last");
      suite.expect(equalBrainSnapshots(expectedFinalSnapshot, loadedLoopSnapshot), "cached_snapshot_replace_after_save_loop_persists_last");
      suite.expect(cleanupPersistentStateRoots(replaceLoopDbPath), "cleanup_replace_loop_state_directory_after");
   }

   {
      String captureDbPath = dbPath;
      captureDbPath.append(".captures"_ctv);
      suite.expect(cleanupPersistentStateRoots(captureDbPath), "cleanup_capture_state_directory_before");

      String failure = {};
      {
         ProdigyPersistentStateStore store(captureDbPath);
         suite.expect(store.saveBrainSnapshot(captureRichSnapshot, &failure), "save_snapshot_strips_hardware_captures");

         ProdigyPersistentBrainSnapshot loadedCaptureSnapshot = {};
         suite.expect(store.loadBrainSnapshot(loadedCaptureSnapshot, &failure), "load_snapshot_strips_hardware_captures");
         suite.expect(equalBrainSnapshots(expectedCaptureStrippedSnapshot, loadedCaptureSnapshot), "load_snapshot_strips_hardware_captures_roundtrip");
         suite.expect(loadedCaptureSnapshot.topology.machines[0].hardware.captures.empty(), "load_snapshot_strips_machine_hardware_captures");
         suite.expect(loadedCaptureSnapshot.topology.machines[0].hardware.cpu.captures.empty(), "load_snapshot_strips_cpu_hardware_captures");
      }

      String rawCaptureSnapshotRecord = {};
      suite.expect(readRawTidesDBRecord(captureDbPath, "brain"_ctv, "snapshot"_ctv, rawCaptureSnapshotRecord, &failure), "read_raw_capture_snapshot_record");
      suite.expect(stringContains(rawCaptureSnapshotRecord, hardwareCapture.output) == false, "raw_capture_snapshot_record_scrubs_hardware_capture_output");
      suite.expect(cleanupPersistentStateRoots(captureDbPath), "cleanup_capture_state_directory_after");
   }

   {
      String hardwareRichDbPath = dbPath;
      hardwareRichDbPath.append(".hardware-rich"_ctv);
      suite.expect(cleanupPersistentStateRoots(hardwareRichDbPath), "cleanup_hardware_rich_state_directory_before");

      ProdigyPersistentBrainSnapshot hardwareRichSnapshot = storedSnapshot;
      hardwareRichSnapshot.topology.version += 7;
      hardwareRichSnapshot.masterAuthority.runtimeState.generation += 7;

      ClusterMachine& richMachineA = hardwareRichSnapshot.topology.machines[0];
      richMachineA.hardware.cpu.vendor = "AuthenticAMD"_ctv;
      richMachineA.hardware.cpu.model = "AMD Ryzen Threadripper PRO 9965WX 24-Core Processor"_ctv;
      richMachineA.hardware.cpu.architecture = MachineCpuArchitecture::x86_64;
      richMachineA.hardware.cpu.architectureVersion = "x86_64-v4"_ctv;
      richMachineA.hardware.cpu.logicalCores = 48;
      richMachineA.hardware.cpu.physicalCores = 24;
      richMachineA.hardware.cpu.sockets = 1;
      richMachineA.hardware.cpu.numaNodes = 2;
      richMachineA.hardware.cpu.threadsPerCore = 2;
      richMachineA.hardware.cpu.l3CacheMB = 128;
      richMachineA.hardware.cpu.singleThreadScore = 4012;
      richMachineA.hardware.cpu.multiThreadScore = 78210;
      richMachineA.hardware.cpu.isaFeatures.push_back("sse4_2"_ctv);
      richMachineA.hardware.cpu.isaFeatures.push_back("aes"_ctv);
      richMachineA.hardware.cpu.isaFeatures.push_back("sha"_ctv);
      richMachineA.hardware.cpu.isaFeatures.push_back("avx"_ctv);
      richMachineA.hardware.cpu.isaFeatures.push_back("avx2"_ctv);
      richMachineA.hardware.cpu.isaFeatures.push_back("avx_vnni"_ctv);
      richMachineA.hardware.cpu.isaFeatures.push_back("avx512f"_ctv);
      richMachineA.hardware.cpu.isaFeatures.push_back("avx512bw"_ctv);
      richMachineA.hardware.cpu.isaFeatures.push_back("avx512vl"_ctv);
      richMachineA.hardware.cpu.isaFeatures.push_back("avx512vnni"_ctv);
      richMachineA.hardware.collectedAtMs = 1700000003000;
      richMachineA.hardware.inventoryComplete = true;
      richMachineA.hardware.benchmarksComplete = false;
      richMachineA.hardware.benchmarkFailure = "nvidia-smi timed out while collecting retained runtime benchmark telemetry"_ctv;
      MachineGpuHardwareProfile gpuA = {};
      gpuA.vendor = "NVIDIA"_ctv;
      gpuA.model = "GB202GL [RTX PRO 6000 Blackwell Workstation Edition]"_ctv;
      gpuA.busAddress = "0000:f1:00.0"_ctv;
      gpuA.memoryMB = 98304;
      richMachineA.hardware.gpus.push_back(gpuA);

      ProdigyPersistentBrainSnapshot changedHardwareRichSnapshot = hardwareRichSnapshot;
      changedHardwareRichSnapshot.topology.version += 1;
      changedHardwareRichSnapshot.masterAuthority.runtimeState.generation += 1;
      ProdigyMetricSample metricC = metricB;
      metricC.ms = 1700000003000;
      metricC.value = 71.0f;
      changedHardwareRichSnapshot.metricSamples.push_back(metricC);
      changedHardwareRichSnapshot.topology.machines[0].hardware.benchmarkFailure = "follower replay resumed after deferred metadata echo stabilization"_ctv;

      ProdigyPersistentBrainSnapshot expectedChangedHardwareRichSnapshot = changedHardwareRichSnapshot;
      prodigyStripManagedCloudBootstrapCredentials(expectedChangedHardwareRichSnapshot.brainConfig.runtimeEnvironment);
      prodigyStripMachineHardwareCapturesFromClusterTopology(expectedChangedHardwareRichSnapshot.topology);

      String failure = {};
      {
         ProdigyPersistentStateStore store(hardwareRichDbPath);
         suite.expect(store.saveBrainSnapshot(hardwareRichSnapshot, &failure), "save_snapshot_hardware_rich_seed");
         suite.expect(store.saveBrainSnapshot(changedHardwareRichSnapshot, &failure), "save_snapshot_hardware_rich_changed");
      }

      String rawHardwareRichSnapshotRecord = {};
      suite.expect(readRawTidesDBRecord(hardwareRichDbPath, "brain"_ctv, "snapshot"_ctv, rawHardwareRichSnapshotRecord, &failure), "read_raw_hardware_rich_snapshot_record");
      ProdigyPersistentStoredBrainSnapshot storedHardwareRichSnapshotRecord = {};
      suite.expect(BitseryEngine::deserializeSafe(rawHardwareRichSnapshotRecord, storedHardwareRichSnapshotRecord), "deserialize_raw_hardware_rich_snapshot_record");
      suite.expect(storedHardwareRichSnapshotRecord.secretVersion != 0, "hardware_rich_snapshot_record_has_secret_version");

      {
         ProdigyPersistentStateStore store(hardwareRichDbPath);
         suite.expect(store.saveBrainSnapshot(changedHardwareRichSnapshot, &failure), "duplicate_save_snapshot_hardware_rich");
      }

      String rawHardwareRichSnapshotRecordAfterDuplicateSave = {};
      suite.expect(readRawTidesDBRecord(hardwareRichDbPath, "brain"_ctv, "snapshot"_ctv, rawHardwareRichSnapshotRecordAfterDuplicateSave, &failure), "read_raw_hardware_rich_snapshot_record_after_duplicate_save");
      ProdigyPersistentStoredBrainSnapshot storedHardwareRichSnapshotRecordAfterDuplicateSave = {};
      suite.expect(BitseryEngine::deserializeSafe(rawHardwareRichSnapshotRecordAfterDuplicateSave, storedHardwareRichSnapshotRecordAfterDuplicateSave), "deserialize_raw_hardware_rich_snapshot_record_after_duplicate_save");
      suite.expect(
         storedHardwareRichSnapshotRecordAfterDuplicateSave.secretVersion == storedHardwareRichSnapshotRecord.secretVersion,
         "duplicate_save_snapshot_hardware_rich_preserves_secret_version");

      {
         ProdigyPersistentStateStore store(hardwareRichDbPath);
         ProdigyPersistentBrainSnapshot loadedHardwareRichSnapshot = {};
         suite.expect(store.loadBrainSnapshot(loadedHardwareRichSnapshot, &failure), "load_snapshot_hardware_rich_after_changed_save");
         suite.expect(
            equalBrainSnapshots(expectedChangedHardwareRichSnapshot, loadedHardwareRichSnapshot),
            "load_snapshot_hardware_rich_after_changed_save_roundtrip");
      }

      suite.expect(cleanupPersistentStateRoots(hardwareRichDbPath), "cleanup_hardware_rich_state_directory_after");
   }

   {
      String failure = {};
      String secretsDBPath = {};
      resolveProdigyPersistentSecretsDBPath(dbPath, secretsDBPath);

      String rawPublicBootRecord = {};
      suite.expect(readRawTidesDBRecord(dbPath, "boot"_ctv, "local"_ctv, rawPublicBootRecord, &failure), "read_raw_public_boot_record");
      ProdigyPersistentStoredBootState storedBootRecord = {};
      suite.expect(BitseryEngine::deserializeSafe(rawPublicBootRecord, storedBootRecord), "deserialize_raw_public_boot_record");
      suite.expect(storedBootRecord.secretVersion != 0, "raw_public_boot_record_has_secret_version");
      suite.expect(stringContains(rawPublicBootRecord, storedBootState.bootstrapSshKeyPackage.privateKeyOpenSSH) == false, "raw_public_boot_record_scrubs_bootstrap_private_key");
      suite.expect(stringContains(rawPublicBootRecord, storedBootState.bootstrapSshHostKeyPackage.privateKeyOpenSSH) == false, "raw_public_boot_record_scrubs_bootstrap_host_private_key");

      String bootSecretKey = {};
      prodigyBuildPersistentSecretRecordKey("local", storedBootRecord.secretVersion, bootSecretKey);
      String rawBootSecretRecord = {};
      suite.expect(readRawTidesDBRecord(secretsDBPath, "boot"_ctv, bootSecretKey, rawBootSecretRecord, &failure), "read_raw_boot_secret_record");
      suite.expect(stringContains(rawBootSecretRecord, storedBootState.bootstrapSshKeyPackage.privateKeyOpenSSH), "raw_boot_secret_record_keeps_bootstrap_private_key");
      suite.expect(stringContains(rawBootSecretRecord, storedBootState.bootstrapSshHostKeyPackage.privateKeyOpenSSH), "raw_boot_secret_record_keeps_bootstrap_host_private_key");

      String rawPublicSnapshotRecord = {};
      suite.expect(readRawTidesDBRecord(dbPath, "brain"_ctv, "snapshot"_ctv, rawPublicSnapshotRecord, &failure), "read_raw_public_snapshot_record");
      ProdigyPersistentStoredBrainSnapshot storedSnapshotRecord = {};
      suite.expect(BitseryEngine::deserializeSafe(rawPublicSnapshotRecord, storedSnapshotRecord), "deserialize_raw_public_snapshot_record");
      suite.expect(storedSnapshotRecord.secretVersion != 0, "raw_public_snapshot_record_has_secret_version");
      suite.expect(stringContains(rawPublicSnapshotRecord, storedSnapshot.brainConfig.bootstrapSshKeyPackage.privateKeyOpenSSH) == false, "raw_public_snapshot_record_scrubs_bootstrap_private_key");
      suite.expect(stringContains(rawPublicSnapshotRecord, storedSnapshot.brainConfig.bootstrapSshHostKeyPackage.privateKeyOpenSSH) == false, "raw_public_snapshot_record_scrubs_bootstrap_host_private_key");
      suite.expect(stringContains(rawPublicSnapshotRecord, storedSnapshot.brainConfig.reporter.password) == false, "raw_public_snapshot_record_scrubs_reporter_password");
      suite.expect(stringContains(rawPublicSnapshotRecord, storedCredential.material) == false, "raw_public_snapshot_record_scrubs_api_credential_material");
      suite.expect(stringContains(rawPublicSnapshotRecord, storedFactory.rootKeyPem) == false, "raw_public_snapshot_record_scrubs_tls_root_key");
      suite.expect(stringContains(rawPublicSnapshotRecord, storedFactory.intermediateKeyPem) == false, "raw_public_snapshot_record_scrubs_tls_intermediate_key");
      suite.expect(stringContains(rawPublicSnapshotRecord, storedLocalBrainState.transportTLS.clusterRootKeyPem) == false, "raw_public_snapshot_record_scrubs_transport_root_key");
      suite.expect(stringContains(rawPublicSnapshotRecord, pendingAddMachinesOperation.request.bootstrapSshKeyPackage.privateKeyOpenSSH) == false, "raw_public_snapshot_record_scrubs_pending_bootstrap_private_key");

      String snapshotSecretKey = {};
      prodigyBuildPersistentSecretRecordKey("snapshot", storedSnapshotRecord.secretVersion, snapshotSecretKey);
      String rawSnapshotSecretRecord = {};
      suite.expect(readRawTidesDBRecord(secretsDBPath, "brain"_ctv, snapshotSecretKey, rawSnapshotSecretRecord, &failure), "read_raw_snapshot_secret_record");
      suite.expect(stringContains(rawSnapshotSecretRecord, storedSnapshot.brainConfig.bootstrapSshKeyPackage.privateKeyOpenSSH), "raw_snapshot_secret_record_keeps_bootstrap_private_key");
      suite.expect(stringContains(rawSnapshotSecretRecord, storedSnapshot.brainConfig.bootstrapSshHostKeyPackage.privateKeyOpenSSH), "raw_snapshot_secret_record_keeps_bootstrap_host_private_key");
      suite.expect(stringContains(rawSnapshotSecretRecord, storedSnapshot.brainConfig.reporter.password), "raw_snapshot_secret_record_keeps_reporter_password");
      suite.expect(stringContains(rawSnapshotSecretRecord, storedCredential.material), "raw_snapshot_secret_record_keeps_api_credential_material");
      suite.expect(stringContains(rawSnapshotSecretRecord, storedFactory.rootKeyPem), "raw_snapshot_secret_record_keeps_tls_root_key");
      suite.expect(stringContains(rawSnapshotSecretRecord, storedFactory.intermediateKeyPem), "raw_snapshot_secret_record_keeps_tls_intermediate_key");
      suite.expect(stringContains(rawSnapshotSecretRecord, storedLocalBrainState.transportTLS.clusterRootKeyPem), "raw_snapshot_secret_record_keeps_transport_root_key");
      suite.expect(stringContains(rawSnapshotSecretRecord, pendingAddMachinesOperation.request.bootstrapSshKeyPackage.privateKeyOpenSSH), "raw_snapshot_secret_record_keeps_pending_bootstrap_private_key");

      String rawPublicLocalBrainStateRecord = {};
      suite.expect(readRawTidesDBRecord(dbPath, "brain"_ctv, "local_brain_state"_ctv, rawPublicLocalBrainStateRecord, &failure), "read_raw_public_local_brain_state_record");
      ProdigyPersistentStoredLocalBrainState storedLocalRecord = {};
      suite.expect(BitseryEngine::deserializeSafe(rawPublicLocalBrainStateRecord, storedLocalRecord), "deserialize_raw_public_local_brain_state_record");
      suite.expect(storedLocalRecord.secretVersion != 0, "raw_public_local_brain_state_record_has_secret_version");
      suite.expect(stringContains(rawPublicLocalBrainStateRecord, storedLocalBrainState.transportTLS.clusterRootKeyPem) == false, "raw_public_local_brain_state_record_scrubs_cluster_root_key");
      suite.expect(stringContains(rawPublicLocalBrainStateRecord, storedLocalBrainState.transportTLS.localKeyPem) == false, "raw_public_local_brain_state_record_scrubs_local_key");

      String localBrainStateSecretKey = {};
      prodigyBuildPersistentSecretRecordKey("local_brain_state", storedLocalRecord.secretVersion, localBrainStateSecretKey);
      String rawLocalBrainStateSecretRecord = {};
      suite.expect(readRawTidesDBRecord(secretsDBPath, "brain"_ctv, localBrainStateSecretKey, rawLocalBrainStateSecretRecord, &failure), "read_raw_local_brain_state_secret_record");
      suite.expect(stringContains(rawLocalBrainStateSecretRecord, storedLocalBrainState.transportTLS.clusterRootKeyPem), "raw_local_brain_state_secret_record_keeps_cluster_root_key");
      suite.expect(stringContains(rawLocalBrainStateSecretRecord, storedLocalBrainState.transportTLS.localKeyPem), "raw_local_brain_state_secret_record_keeps_local_key");

      {
         ProdigyPersistentStateStore store(dbPath);
         suite.expect(store.saveBootState(storedBootState, &failure), "duplicate_save_boot");
         suite.expect(store.saveBrainSnapshot(storedSnapshot, &failure), "duplicate_save_snapshot");
         suite.expect(store.saveLocalBrainState(storedLocalBrainState, &failure), "duplicate_save_local_brain_state");
      }

      String rawPublicBootRecordAfterDuplicateSave = {};
      suite.expect(readRawTidesDBRecord(dbPath, "boot"_ctv, "local"_ctv, rawPublicBootRecordAfterDuplicateSave, &failure), "read_raw_public_boot_record_after_duplicate_save");
      ProdigyPersistentStoredBootState storedBootRecordAfterDuplicateSave = {};
      suite.expect(BitseryEngine::deserializeSafe(rawPublicBootRecordAfterDuplicateSave, storedBootRecordAfterDuplicateSave), "deserialize_raw_public_boot_record_after_duplicate_save");
      suite.expect(storedBootRecordAfterDuplicateSave.secretVersion == storedBootRecord.secretVersion, "duplicate_save_boot_preserves_secret_version");

      String rawPublicSnapshotRecordAfterDuplicateSave = {};
      suite.expect(readRawTidesDBRecord(dbPath, "brain"_ctv, "snapshot"_ctv, rawPublicSnapshotRecordAfterDuplicateSave, &failure), "read_raw_public_snapshot_record_after_duplicate_save");
      ProdigyPersistentStoredBrainSnapshot storedSnapshotRecordAfterDuplicateSave = {};
      suite.expect(BitseryEngine::deserializeSafe(rawPublicSnapshotRecordAfterDuplicateSave, storedSnapshotRecordAfterDuplicateSave), "deserialize_raw_public_snapshot_record_after_duplicate_save");
      suite.expect(storedSnapshotRecordAfterDuplicateSave.secretVersion == storedSnapshotRecord.secretVersion, "duplicate_save_snapshot_preserves_secret_version");

      String rawPublicLocalBrainStateRecordAfterDuplicateSave = {};
      suite.expect(readRawTidesDBRecord(dbPath, "brain"_ctv, "local_brain_state"_ctv, rawPublicLocalBrainStateRecordAfterDuplicateSave, &failure), "read_raw_public_local_brain_state_record_after_duplicate_save");
      ProdigyPersistentStoredLocalBrainState storedLocalRecordAfterDuplicateSave = {};
      suite.expect(BitseryEngine::deserializeSafe(rawPublicLocalBrainStateRecordAfterDuplicateSave, storedLocalRecordAfterDuplicateSave), "deserialize_raw_public_local_brain_state_record_after_duplicate_save");
      suite.expect(storedLocalRecordAfterDuplicateSave.secretVersion == storedLocalRecord.secretVersion, "duplicate_save_local_brain_state_preserves_secret_version");

      ProdigyPersistentStateStore store(dbPath);

      ProdigyPersistentBootState loadedBootState = {};
      ProdigyPersistentBrainSnapshot loadedSnapshot = {};
      ProdigyPersistentLocalBrainState loadedLocalBrainState = {};

      bool reopenBoot = store.loadBootState(loadedBootState, &failure);
      if (!reopenBoot) basics_log("detail reopen_boot: %s\n", failure.c_str());
      suite.expect(reopenBoot, "reopen_boot");
      suite.expect(equalBootStates(expectedManagedBootState, loadedBootState), "reopen_boot_roundtrip");

      bool reopenSnapshot = store.loadBrainSnapshot(loadedSnapshot, &failure);
      if (!reopenSnapshot) basics_log("detail reopen_snapshot: %s\n", failure.c_str());
      suite.expect(reopenSnapshot, "reopen_snapshot");
      suite.expect(equalBrainSnapshots(expectedManagedSnapshot, loadedSnapshot), "reopen_snapshot_roundtrip");

      bool reopenLocalBrainState = store.loadLocalBrainState(loadedLocalBrainState, &failure);
      if (!reopenLocalBrainState) basics_log("detail reopen_local_brain_state: %s\n", failure.c_str());
      suite.expect(reopenLocalBrainState, "reopen_local_brain_state");
      suite.expect(equalLocalBrainStates(storedLocalBrainState, loadedLocalBrainState), "reopen_local_brain_state_roundtrip");

      bool removeSnapshot = store.removeBrainSnapshot(&failure);
      if (!removeSnapshot) basics_log("detail remove_snapshot: %s\n", failure.c_str());
      suite.expect(removeSnapshot, "remove_snapshot");

      bool missingSnapshot = store.loadBrainSnapshot(loadedSnapshot, &failure);
      suite.expect(missingSnapshot == false, "load_snapshot_missing");
      suite.expect(failure.equals("record not found"_ctv), "load_snapshot_missing_reason");

      uint128_t generatedLocalBrainUUID = 0;
      suite.expect(store.loadOrCreateLocalBrainUUID(generatedLocalBrainUUID, &failure), "load_or_create_local_brain_uuid");
      suite.expect(generatedLocalBrainUUID == storedLocalBrainState.uuid, "load_or_create_local_brain_uuid_reuses_existing");
      suite.expect(failure.size() == 0, "load_or_create_local_brain_uuid_clears_failure");

      ProdigyPersistentLocalBrainState preservedOwnerState = {};
      suite.expect(store.loadLocalBrainState(preservedOwnerState, &failure), "load_local_brain_state_after_load_or_create_uuid");
      suite.expect(preservedOwnerState.ownerClusterUUID == storedLocalBrainState.ownerClusterUUID, "load_or_create_local_brain_uuid_preserves_owner_cluster_uuid");
   }

   {
      char freshScratch[] = "/tmp/nametag-prodigy-persistent-state-fresh-XXXXXX";
      char *freshCreated = mkdtemp(freshScratch);
      suite.expect(freshCreated != nullptr, "fresh_mkdtemp_created");
      if (freshCreated != nullptr)
      {
         String freshPath;
         freshPath.assign(freshCreated);

         ProdigyPersistentStateStore freshStore(freshPath);
         String failure;
         uint128_t firstUUID = 0;
         uint128_t secondUUID = 0;

         suite.expect(freshStore.loadOrCreateLocalBrainUUID(firstUUID, &failure), "fresh_load_or_create_local_brain_uuid");
         suite.expect(firstUUID != 0, "fresh_load_or_create_local_brain_uuid_nonzero");
         suite.expect(failure.size() == 0, "fresh_load_or_create_local_brain_uuid_clears_failure");
         suite.expect(freshStore.loadOrCreateLocalBrainUUID(secondUUID, &failure), "fresh_reopen_local_brain_uuid");
         suite.expect(secondUUID == firstUUID, "fresh_reopen_local_brain_uuid_persists");

         ProdigyPersistentLocalBrainState freshLocalState = {};
         suite.expect(freshStore.loadLocalBrainState(freshLocalState, &failure), "fresh_load_local_brain_state_after_uuid_create");
         suite.expect(freshLocalState.ownerClusterUUID == 0, "fresh_load_local_brain_state_owner_cluster_uuid_zero");

         suite.expect(cleanupPersistentStateRoots(freshPath), "fresh_cleanup_state_directory");
      }
   }

   suite.expect(cleanupPersistentStateRoots(dbPath), "cleanup_state_directory");

   return (suite.failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
