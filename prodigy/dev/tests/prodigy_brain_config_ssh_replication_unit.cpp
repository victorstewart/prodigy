#include <prodigy/prodigy.h>
#include <prodigy/brain/brain.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/dev/tests/prodigy_test_ssh_keys.h>
#include <services/debug.h>

class TestSuite {
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
      failed += 1;
    }
  }
};

class TestBrain : public Brain {
public:

  uint32_t persistCalls = 0;
  uint32_t clusterOwnershipCalls = 0;
  uint128_t lastClaimedClusterUUID = 0;

  void armMachineNeuronControl(Machine *machine) override
  {
    (void)machine;
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

  bool persistLocalRuntimeState(void) override
  {
    persistCalls += 1;
    return true;
  }

  bool claimLocalClusterOwnership(uint128_t clusterUUID, String *failure = nullptr) override
  {
    clusterOwnershipCalls += 1;
    lastClaimedClusterUUID = clusterUUID;
    if (failure != nullptr)
    {
      failure->clear();
    }

    return true;
  }
};

class NoopBrainIaaS : public BrainIaaS {
public:

  void boot(void) override {}

  void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
  {
    (void)coro;
    (void)lifetime;
    (void)config;
    (void)count;
    (void)newMachines;
    error.clear();
  }

  void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines, String& failure) override
  {
    (void)coro;
    (void)metro;
    (void)machines;
  }

  void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains, String& failure) override
  {
    (void)coro;
    (void)selfUUID;
    (void)brains;
    selfIsBrain = false;
  }

  void hardRebootMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    (void)coro;
    (void)cloudID;
    failure.clear();
  }

  void reportHardwareFailure(uint128_t uuid, const String& report) override
  {
    (void)uuid;
    (void)report;
  }

  void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
  {
    (void)coro;
    (void)decommissionedIDs;
  }

  void destroyMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    (void)coro;
    (void)cloudID;
    failure.clear();
  }

  uint32_t supportedMachineKindsMask() const override
  {
    return 0;
  }
};

template <typename... Args>
static Message *buildBrainMessage(String& buffer, BrainTopic topic, Args&&...args)
{
  buffer.clear();
  Message::construct(buffer, topic, std::forward<Args>(args)...);
  return reinterpret_cast<Message *>(buffer.data());
}

static bool readFixtureSSHKeyPackages(Vault::SSHKeyPackage& bootstrapKeyPackage, Vault::SSHKeyPackage& hostKeyPackage, String& failure)
{
  bootstrapKeyPackage.clear();
  hostKeyPackage.clear();
  failure.clear();
  if (prodigyReadSSHKeyPackageFromPrivateKeyPath(prodigyTestBootstrapSeedSSHPrivateKeyPath(), bootstrapKeyPackage, &failure) == false)
  {
    return false;
  }

  if (prodigyReadSSHKeyPackageFromPrivateKeyPath(prodigyTestSSHDHostPrivateKeyPath(), hostKeyPackage, &failure) == false)
  {
    bootstrapKeyPackage.clear();
    return false;
  }

  return true;
}

static void populateBootstrapSSHConfig(BrainConfig& config)
{
  config.clusterUUID = 0x550011;
  config.bootstrapSshUser = "root"_ctv;
  config.bootstrapSshPrivateKeyPath = "/var/lib/prodigy/ssh/bootstrap_ed25519"_ctv;
  config.remoteProdigyPath = "/opt/prodigy"_ctv;
  config.controlSocketPath = "/run/prodigy/control.sock"_ctv;
}

static void testCombinedMasterAuthorityCopiesBootstrapSSHPackages(TestSuite& suite)
{
  TestBrain brain = {};
  NoopBrainIaaS iaas = {};
  BrainView peer = {};
  brain.iaas = &iaas;
  brain.noMasterYet = false;
  peer.connected = true;
  peer.isFixedFile = true;
  peer.fslot = 1;
  peer.registrationFresh = true;
  peer.uuid = uint128_t(0x550013);
  peer.boottimens = 550013;
  peer.existingMasterUUID = peer.uuid;
  peer.isMasterBrain = true;

  BrainConfig replicatedConfig = {};
  populateBootstrapSSHConfig(replicatedConfig);
  replicatedConfig.clusterUUID = 0x550012;
  String failure = {};
  suite.expect(
      readFixtureSSHKeyPackages(replicatedConfig.bootstrapSshKeyPackage, replicatedConfig.bootstrapSshHostKeyPackage, failure),
      "combined_master_authority_reads_bootstrap_key_packages");

  String serialized = {};
  ProdigyMasterAuthorityStateTransition transition;
  transition.runtimeState.generation = 1;
  transition.brainConfig = replicatedConfig;
  BitseryEngine::serialize(serialized, transition);

  String messageBuffer = {};
  Message *message = buildBrainMessage(messageBuffer, BrainTopic::replicateMasterAuthorityState, serialized);
  brain.brainHandler(&peer, message);

  suite.expect(brain.brainConfig.bootstrapSshUser.equals(replicatedConfig.bootstrapSshUser), "combined_master_authority_applies_bootstrap_user");
  suite.expect(brain.brainConfig.bootstrapSshKeyPackage == replicatedConfig.bootstrapSshKeyPackage, "combined_master_authority_applies_bootstrap_key_package");
  suite.expect(brain.brainConfig.bootstrapSshHostKeyPackage == replicatedConfig.bootstrapSshHostKeyPackage, "combined_master_authority_applies_bootstrap_host_key_package");
  suite.expect(brain.clusterOwnershipCalls == 1, "combined_master_authority_claims_cluster_ownership");
  suite.expect(brain.lastClaimedClusterUUID == replicatedConfig.clusterUUID, "combined_master_authority_claims_expected_cluster_uuid");
  suite.expect(brain.persistCalls == 1, "combined_master_authority_persists_runtime_state");
}

int main(void)
{
  TestSuite suite = {};

  testCombinedMasterAuthorityCopiesBootstrapSSHPackages(suite);

  return suite.failed == 0 ? 0 : 1;
}
