#include <prodigy/mothership/mothership.cluster.create.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <services/debug.h>
#include <prodigy/dev/tests/prodigy_test_ssh_keys.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

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
         failed += 1;
      }
   }
};

class FakeProvisioningProgressSink final : public BrainIaaSMachineProvisioningProgressSink
{
public:

   uint32_t calls = 0;
   Vector<MachineProvisioningProgress> lastProgress;

   void reportMachineProvisioningProgress(const Vector<MachineProvisioningProgress>& progress) override
   {
      calls += 1;
      lastProgress = progress;
   }
};

enum class ClusterCreateCall : uint8_t
{
   startTestCluster = 0,
   stopTestCluster = 1,
   prepareProviderBootstrapArtifacts = 2,
   localBootstrap = 3,
   createSeed = 4,
   destroyCreatedSeed = 5,
   remoteBootstrap = 6,
   configure = 7,
   fetchTopology = 8,
   applyAddMachines = 9,
   upsertMachineSchemas = 10
};

static bool equalCallSequence(const Vector<ClusterCreateCall>& lhs, std::initializer_list<ClusterCreateCall> rhs)
{
   if (lhs.size() != rhs.size())
   {
      return false;
   }

   uint32_t index = 0;
   for (ClusterCreateCall expected : rhs)
   {
      if (lhs[index] != expected)
      {
         return false;
      }

      index += 1;
   }

   return true;
}

static MachineConfig makeMachineConfig(const String& slug, MachineConfig::MachineKind kind, uint32_t nLogicalCores, uint32_t nMemoryMB, uint32_t nStorageMB)
{
   MachineConfig config = {};
   config.kind = kind;
   config.slug = slug;
   config.nLogicalCores = nLogicalCores;
   config.nMemoryMB = nMemoryMB;
   config.nStorageMB = nStorageMB;
   if (kind == MachineConfig::MachineKind::vm)
   {
      config.vmImageURI = "image://default"_ctv;
   }
   return config;
}

static MothershipProdigyClusterMachineSchema makeMachineSchemaFromConfig(const MachineConfig& config)
{
   MothershipProdigyClusterMachineSchema schema = {};
   schema.schema = config.slug;
   schema.kind = config.kind;
   schema.ipxeScriptURL = config.ipxeScriptURL;
   schema.vmImageURI = config.vmImageURI;
   schema.gcpInstanceTemplate = config.gcpInstanceTemplate;
   schema.gcpInstanceTemplateSpot = config.gcpInstanceTemplateSpot;
   return schema;
}

static void appendMachineSchema(MothershipProdigyCluster& cluster, const MothershipProdigyClusterMachineSchema& schema)
{
   for (MothershipProdigyClusterMachineSchema& existing : cluster.machineSchemas)
   {
      if (existing.schema.equals(schema.schema) == false)
      {
         continue;
      }

      existing.kind = schema.kind;
      existing.lifetime = schema.lifetime;
      if (schema.ipxeScriptURL.size() > 0) existing.ipxeScriptURL = schema.ipxeScriptURL;
      if (schema.vmImageURI.size() > 0) existing.vmImageURI = schema.vmImageURI;
      if (schema.gcpInstanceTemplate.size() > 0) existing.gcpInstanceTemplate = schema.gcpInstanceTemplate;
      if (schema.gcpInstanceTemplateSpot.size() > 0) existing.gcpInstanceTemplateSpot = schema.gcpInstanceTemplateSpot;
      if (schema.providerMachineType.size() > 0) existing.providerMachineType = schema.providerMachineType;
      if (schema.providerReservationID.size() > 0) existing.providerReservationID = schema.providerReservationID;
      if (schema.region.size() > 0) existing.region = schema.region;
      if (schema.zone.size() > 0) existing.zone = schema.zone;
      existing.budget = schema.budget;
      return;
   }

   cluster.machineSchemas.push_back(schema);
}

static void appendClusterMachineConfig(MothershipProdigyCluster& cluster, const MachineConfig& config)
{
   appendMachineSchema(cluster, makeMachineSchemaFromConfig(config));
}

static MothershipProdigyClusterControl makeUnixControl(const String& path)
{
   return MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = path
   };
}

static bool writeExecutableScript(const std::filesystem::path& path, const char *text)
{
   FILE *file = std::fopen(path.c_str(), "wb");
   if (file == nullptr)
   {
      return false;
   }

   size_t textLength = std::strlen(text);
   bool ok = std::fwrite(text, 1, textLength, file) == textLength;
   ok = std::fclose(file) == 0 && ok;
   if (ok == false)
   {
      return false;
   }

   std::filesystem::permissions(path,
      std::filesystem::perms::owner_read
         | std::filesystem::perms::owner_write
         | std::filesystem::perms::owner_exec,
      std::filesystem::perm_options::replace);
   return true;
}

static NeuronBGPPeerConfig makeBGPConfigPeer(const String& peerAddress, const String& sourceAddress, uint16_t peerASN, const String& md5Password, uint8_t hopLimit)
{
   NeuronBGPPeerConfig peer = {};
   peer.peerASN = peerASN;
   (void)prodigyParseIPAddressText(peerAddress, peer.peerAddress);
   (void)prodigyParseIPAddressText(sourceAddress, peer.sourceAddress);
   peer.md5Password = md5Password;
   peer.hopLimit = hopLimit;
   return peer;
}

static MothershipProdigyClusterMachine makeAdoptedMachine(const String& schema, const String& privateAddress, bool isBrain, ClusterMachineBacking backing = ClusterMachineBacking::owned)
{
   MothershipProdigyClusterMachine machine = {};
   machine.source = MothershipClusterMachineSource::adopted;
   machine.backing = backing;
   machine.kind = MachineConfig::MachineKind::vm;
   machine.lifetime = (backing == ClusterMachineBacking::cloud) ? MachineLifetime::reserved : MachineLifetime::owned;
   machine.isBrain = isBrain;
   machine.ssh.address = privateAddress;
   machine.ssh.user = "root"_ctv;
   machine.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, privateAddress);
   machine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   if (backing == ClusterMachineBacking::cloud)
   {
      machine.cloud.schema = schema;
      machine.cloud.providerMachineType = schema;
      machine.cloud.cloudID = privateAddress;
   }
   return machine;
}

static ClusterMachine makeTopologyMachine(
   const String& schema,
   const String& privateAddress,
   bool isBrain,
   ClusterMachineSource source,
   ClusterMachineBacking backing = ClusterMachineBacking::owned,
   const String& providerMachineType = {})
{
   ClusterMachine machine = {};
   machine.source = source;
   machine.backing = backing;
   machine.kind = MachineConfig::MachineKind::vm;
   if (backing == ClusterMachineBacking::cloud)
   {
      machine.lifetime = (source == ClusterMachineSource::created) ? MachineLifetime::ondemand : MachineLifetime::reserved;
   }
   else
   {
      machine.lifetime = MachineLifetime::owned;
   }
   machine.isBrain = isBrain;
   prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, privateAddress);
   machine.ssh.address = privateAddress;
   machine.ssh.user = "root"_ctv;
   machine.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   machine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
   machine.totalLogicalCores = 4;
   machine.totalMemoryMB = 8192;
   machine.totalStorageMB = 65536;
   machine.ownedLogicalCores = 2;
   machine.ownedMemoryMB = 4096;
   machine.ownedStorageMB = 32768;
   if (backing == ClusterMachineBacking::cloud)
   {
      machine.cloud.schema = schema;
      machine.cloud.providerMachineType = providerMachineType.size() > 0 ? providerMachineType : schema;
      machine.cloud.cloudID = privateAddress;
   }
   return machine;
}

class FakeClusterCreateHooks final : public MothershipClusterCreateHooks
{
public:

   uint32_t startTestClusterCalls = 0;
   uint32_t stopTestClusterCalls = 0;
   uint32_t prepareProviderBootstrapArtifactsCalls = 0;
   uint32_t localBootstrapCalls = 0;
   uint32_t createSeedCalls = 0;
   uint32_t remoteBootstrapCalls = 0;
   uint32_t configureCalls = 0;
   uint32_t fetchTopologyCalls = 0;
   uint32_t addMachinesCalls = 0;
   uint32_t upsertMachineSchemasCalls = 0;
   uint32_t destroyCreatedSeedCalls = 0;

   ProdigyPersistentBootState lastLocalBootState = {};
   CreateMachinesInstruction lastCreateSeedInstruction = {};
   ClusterMachine createdSeedMachine = {};
   ClusterMachine lastDestroyedSeedMachine = {};
   uint128_t lastRemoteSeedClusterUUID = 0;
   ClusterMachine lastRemoteSeedMachine = {};
   AddMachines lastRemoteBootstrapRequest = {};
   ClusterTopology lastRemoteBootstrapTopology = {};
   ProdigyRuntimeEnvironmentConfig lastRemoteRuntimeEnvironment = {};
   BrainConfig lastConfig = {};
   Vector<BrainConfig> configureConfigs;
   AddMachines lastAddMachinesRequest = {};
   Vector<ProdigyManagedMachineSchemaPatch> lastMachineSchemaPatches = {};
   Vector<ClusterCreateCall> callSequence;

   ClusterTopology fetchedTopology = {};
   Vector<ClusterTopology> fetchedTopologySequence;
   ClusterTopology finalTopology = {};
   ProdigyTimingAttribution prepareProviderBootstrapArtifactsTiming = {};
   ProdigyTimingAttribution createSeedTiming = {};
   ProdigyTimingAttribution remoteBootstrapTiming = {};
   ProdigyTimingAttribution addMachinesTiming = {};
   ProdigyTimingAttribution upsertMachineSchemasTiming = {};
   bool failBootstrapRemoteSeed = false;
   bool failStartTestCluster = false;
   bool failConfigureSeedCluster = false;
   bool failFetchSeedTopology = false;
   bool failApplyAddMachines = false;
   bool failUpsertMachineSchemas = false;
   bool failDestroyCreatedSeed = false;
   bool failPrepareProviderBootstrapArtifacts = false;

   bool startTestCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr) override
   {
      (void)cluster;
      startTestClusterCalls += 1;
      callSequence.push_back(ClusterCreateCall::startTestCluster);
      if (failStartTestCluster)
      {
         if (failure) failure->assign("start test cluster failed"_ctv);
         return false;
      }

      if (failure) failure->clear();
      return true;
   }

   bool stopTestCluster(const MothershipProdigyCluster& cluster, String *failure = nullptr) override
   {
      (void)cluster;
      stopTestClusterCalls += 1;
      callSequence.push_back(ClusterCreateCall::stopTestCluster);
      if (failure) failure->clear();
      return true;
   }

   bool prepareProviderBootstrapArtifacts(const MothershipProdigyCluster& cluster, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) override
   {
      (void)cluster;
      (void)timingAttribution;
      prepareProviderBootstrapArtifactsCalls += 1;
      callSequence.push_back(ClusterCreateCall::prepareProviderBootstrapArtifacts);
      if (timingAttribution != nullptr)
      {
         *timingAttribution = prepareProviderBootstrapArtifactsTiming;
      }
      if (failPrepareProviderBootstrapArtifacts)
      {
         if (failure) failure->assign("prepare provider bootstrap artifacts failed"_ctv);
         return false;
      }

      if (failure) failure->clear();
      return true;
   }

   bool bootstrapLocalSeed(const ProdigyPersistentBootState& bootState, String *failure = nullptr) override
   {
      localBootstrapCalls += 1;
      lastLocalBootState = bootState;
      callSequence.push_back(ClusterCreateCall::localBootstrap);
      if (failure) failure->clear();
      return true;
   }

   bool createSeedMachine(const MothershipProdigyCluster& cluster, const CreateMachinesInstruction& instruction, ClusterMachine& seedMachine, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) override
   {
      (void)cluster;
      (void)timingAttribution;
      createSeedCalls += 1;
      lastCreateSeedInstruction = instruction;
      seedMachine = createdSeedMachine;
      callSequence.push_back(ClusterCreateCall::createSeed);
      if (timingAttribution != nullptr)
      {
         *timingAttribution = createSeedTiming;
      }
      if (failure) failure->clear();
      return true;
   }

   bool destroyCreatedSeedMachine(const MothershipProdigyCluster& cluster, const ClusterMachine& seedMachine, String *failure = nullptr) override
   {
      (void)cluster;
      destroyCreatedSeedCalls += 1;
      lastDestroyedSeedMachine = seedMachine;
      callSequence.push_back(ClusterCreateCall::destroyCreatedSeed);
      if (failDestroyCreatedSeed)
      {
         if (failure) failure->assign("destroy seed failed"_ctv);
         return false;
      }

      if (failure) failure->clear();
      return true;
   }

   bool bootstrapRemoteSeed(const MothershipProdigyCluster& cluster, const ClusterMachine& seedMachine, const AddMachines& request, const ClusterTopology& topology, const ProdigyRuntimeEnvironmentConfig& runtimeEnvironment, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) override
   {
      (void)timingAttribution;
      remoteBootstrapCalls += 1;
      lastRemoteSeedClusterUUID = cluster.clusterUUID;
      lastRemoteSeedMachine = seedMachine;
      lastRemoteBootstrapRequest = request;
      lastRemoteBootstrapTopology = topology;
      lastRemoteRuntimeEnvironment = runtimeEnvironment;
      callSequence.push_back(ClusterCreateCall::remoteBootstrap);
      if (timingAttribution != nullptr)
      {
         *timingAttribution = remoteBootstrapTiming;
      }
      if (failBootstrapRemoteSeed)
      {
         if (failure) failure->assign("bootstrap remote seed failed"_ctv);
         return false;
      }

      if (failure) failure->clear();
      return true;
   }

   bool configureSeedCluster(const MothershipProdigyCluster& cluster, const BrainConfig& config, String *failure = nullptr) override
   {
      (void)cluster;
      configureCalls += 1;
      lastConfig = config;
      configureConfigs.push_back(config);
      callSequence.push_back(ClusterCreateCall::configure);
      if (failConfigureSeedCluster)
      {
         if (failure) failure->assign("configure seed failed"_ctv);
         return false;
      }

      if (failure) failure->clear();
      return true;
   }

   bool fetchSeedTopology(const MothershipProdigyCluster& cluster, ClusterTopology& topology, String *failure = nullptr) override
   {
      (void)cluster;
      fetchTopologyCalls += 1;
      if (fetchedTopologySequence.empty() == false)
      {
         uint32_t fetchIndex = fetchTopologyCalls - 1;
         if (fetchIndex >= fetchedTopologySequence.size())
         {
            fetchIndex = fetchedTopologySequence.size() - 1;
         }

         topology = fetchedTopologySequence[fetchIndex];
      }
      else
      {
         topology = fetchedTopology;
      }
      callSequence.push_back(ClusterCreateCall::fetchTopology);
      if (failFetchSeedTopology)
      {
         if (failure) failure->assign("fetch seed topology failed"_ctv);
         return false;
      }

      if (failure) failure->clear();
      return true;
   }

   bool applyAddMachines(const MothershipProdigyCluster& cluster, const AddMachines& request, ClusterTopology& topology, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) override
   {
      (void)cluster;
      (void)timingAttribution;
      addMachinesCalls += 1;
      lastAddMachinesRequest = request;
      topology = finalTopology;
      callSequence.push_back(ClusterCreateCall::applyAddMachines);
      if (timingAttribution != nullptr)
      {
         *timingAttribution = addMachinesTiming;
      }
      if (failApplyAddMachines)
      {
         if (failure) failure->assign("apply addMachines failed"_ctv);
         return false;
      }

      if (failure) failure->clear();
      return true;
   }

   bool upsertMachineSchemas(const MothershipProdigyCluster& cluster, const Vector<ProdigyManagedMachineSchemaPatch>& patches, ClusterTopology& topology, ProdigyTimingAttribution *timingAttribution = nullptr, String *failure = nullptr) override
   {
      (void)cluster;
      (void)timingAttribution;
      upsertMachineSchemasCalls += 1;
      lastMachineSchemaPatches = patches;
      topology = finalTopology;
      callSequence.push_back(ClusterCreateCall::upsertMachineSchemas);
      if (timingAttribution != nullptr)
      {
         *timingAttribution = upsertMachineSchemasTiming;
      }
      if (failUpsertMachineSchemas)
      {
         if (failure) failure->assign("upsert machine schemas failed"_ctv);
         return false;
      }

      if (failure) failure->clear();
      return true;
   }
};

class FakeProvisionBrainIaaS final : public BrainIaaS
{
public:

   bool autoProvision = true;
   uint32_t kindsMask = 2u;
   uint32_t spinCalls = 0;
   uint32_t destroyCalls = 0;
   String providerError;
   Vector<Machine *> snapshotsToReturn;
   Vector<MachineProvisioningProgress> progressToEmit;
   Vector<String> destroyedCloudIDs;
   Vector<String> ensuredClusterUUIDs;
   Vector<String> ensuredCloudIDs;
   BrainIaaSMachineProvisioningProgressSink *progressSink = nullptr;

   void boot(void) override
   {
   }

   void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
   {
      (void)coro;
      (void)lifetime;
      (void)config;
      (void)count;

      spinCalls += 1;
      if (progressSink != nullptr && progressToEmit.empty() == false)
      {
         progressSink->reportMachineProvisioningProgress(progressToEmit);
      }
      error = providerError;
      for (Machine *snapshot : snapshotsToReturn)
      {
         newMachines.insert(snapshot);
      }
   }

   void configureProvisioningProgressSink(BrainIaaSMachineProvisioningProgressSink *sink) override
   {
      progressSink = sink;
   }

   void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
   {
      (void)coro;
      (void)metro;
      (void)machines;
   }

   void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
   {
      (void)coro;
      (void)selfUUID;
      (void)brains;
      selfIsBrain = false;
   }

   void hardRebootMachine(uint128_t uuid) override
   {
      (void)uuid;
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

   void destroyMachine(Machine *machine) override
   {
      destroyCalls += 1;
      if (machine != nullptr)
      {
         destroyedCloudIDs.push_back(machine->cloudID);
      }
   }

   bool ensureProdigyMachineTags(const String& clusterUUID, Machine *machine, String& error) override
   {
      error.clear();
      ensuredClusterUUIDs.push_back(clusterUUID);
      ensuredCloudIDs.push_back(machine ? machine->cloudID : ""_ctv);
      return true;
   }

   uint32_t supportedMachineKindsMask() const override
   {
      return kindsMask;
   }

   bool supportsAutoProvision() const override
   {
      return autoProvision;
   }
};

static Machine *makeMachineSnapshot(const String& schema, const String& privateAddress, const String& cloudID)
{
   Machine *snapshot = new Machine();
   snapshot->slug = schema;
   snapshot->type = schema;
   snapshot->cloudID = cloudID;
   snapshot->sshAddress = privateAddress;
   snapshot->sshUser = "root"_ctv;
   snapshot->sshPrivateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   snapshot->privateAddress = privateAddress;
   snapshot->publicAddress = privateAddress;
   String privateAddressText = {};
   privateAddressText.assign(privateAddress);
   snapshot->private4 = IPAddress(privateAddressText.c_str(), false).v4;
   snapshot->uuid = 12345;
   snapshot->rackUUID = 7;
   snapshot->creationTimeMs = 111;
   snapshot->totalLogicalCores = 4;
   snapshot->totalMemoryMB = 8192;
   snapshot->totalStorageMB = 65536;
   return snapshot;
}

static String renderClusterUUIDHex(uint128_t clusterUUID)
{
   String rendered = {};
   rendered.assignItoh(clusterUUID);
   return rendered;
}

int main(void)
{
   TestSuite suite;

   char scratch[] = "/tmp/nametag-mothership-cluster-create-XXXXXX";
   char *created = mkdtemp(scratch);
   suite.expect(created != nullptr, "mkdtemp_created");
   if (created == nullptr)
   {
      return EXIT_FAILURE;
   }

   std::filesystem::path fakeBinDir = std::filesystem::path(created) / "fake-bin";
   std::error_code pathError = {};
   std::filesystem::create_directories(fakeBinDir, pathError);
   suite.expect(!pathError, "create_fake_bin_dir");

   std::filesystem::path fakeAzPath = fakeBinDir / "az";
   suite.expect(writeExecutableScript(fakeAzPath,
      "#!/usr/bin/env bash\n"
      "set -e\n"
      "if [ \"$1\" = \"account\" ] && [ \"$2\" = \"get-access-token\" ]; then\n"
      "  printf 'azure-token\\n'\n"
      "  exit 0\n"
      "fi\n"
      "printf 'unexpected az args: %s\\n' \"$*\" >&2\n"
      "exit 9\n"),
      "write_fake_az");

   std::string originalPath = [] () -> std::string {
      const char *value = std::getenv("PATH");
      return value ? std::string(value) : std::string();
   }();
   std::string fakePath = fakeBinDir.string();
   if (originalPath.empty() == false)
   {
      fakePath += ":";
      fakePath += originalPath;
   }
   suite.expect(::setenv("PATH", fakePath.c_str(), 1) == 0, "set_fake_path");

   {
      FakeProvisionBrainIaaS iaas;
      ClusterMachine cloudMachine = makeTopologyMachine("aws-brain-vm"_ctv, "10.7.0.10"_ctv, true, ClusterMachineSource::adopted, ClusterMachineBacking::cloud);
      cloudMachine.cloud.cloudID = "i-tagged-seed"_ctv;

      String failure = {};
      bool ok = prodigyEnsureCloudMachineTagged(iaas, 0x1234, cloudMachine, &failure);
      suite.expect(ok, "ensure_cloud_machine_tagged_ok");
      suite.expect(failure.size() == 0, "ensure_cloud_machine_tagged_no_failure");
      suite.expect(iaas.ensuredClusterUUIDs.size() == 1, "ensure_cloud_machine_tagged_calls_provider_once");
      suite.expect(iaas.ensuredCloudIDs.size() == 1, "ensure_cloud_machine_tagged_records_cloud_id");
      suite.expect(iaas.ensuredCloudIDs[0].equals("i-tagged-seed"_ctv), "ensure_cloud_machine_tagged_expected_cloud_id");
      suite.expect(iaas.ensuredClusterUUIDs[0].equals(renderClusterUUIDHex(0x1234)), "ensure_cloud_machine_tagged_expected_cluster_uuid");

      ClusterMachine ownedMachine = makeTopologyMachine("owned-brain"_ctv, "10.7.0.11"_ctv, true, ClusterMachineSource::adopted, ClusterMachineBacking::owned);
      ok = prodigyEnsureCloudMachineTagged(iaas, 0x1234, ownedMachine, &failure);
      suite.expect(ok, "ensure_cloud_machine_tagged_skips_owned");
      suite.expect(iaas.ensuredClusterUUIDs.size() == 1, "ensure_cloud_machine_tagged_owned_no_extra_provider_call");

      failure.clear();
      ok = prodigyEnsureCloudMachineTagged(iaas, 0, cloudMachine, &failure);
      suite.expect(ok == false, "ensure_cloud_machine_tagged_requires_cluster_uuid");
      suite.expect(failure.equals("clusterUUID required for cloud machine tagging"_ctv), "ensure_cloud_machine_tagged_requires_cluster_uuid_reason");
   }

   {
      MothershipProdigyCluster cluster = {};
      cluster.name = "seed-provision"_ctv;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-brain-vm"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));

      CreateMachinesInstruction instruction = {};
      instruction.kind = MachineConfig::MachineKind::vm;
      instruction.lifetime = MachineLifetime::ondemand;
      instruction.backing = ClusterMachineBacking::cloud;
      instruction.cloud.schema = "aws-brain-vm"_ctv;
      instruction.cloud.providerMachineType = "c7i.large"_ctv;
      instruction.count = 1;
      instruction.isBrain = true;

      FakeProvisionBrainIaaS iaas;
      FakeProvisioningProgressSink progressSink;
      MachineProvisioningProgress progress = {};
      progress.cloud.schema = "aws-brain-vm"_ctv;
      progress.cloud.providerMachineType = "c7i.large"_ctv;
      progress.cloud.cloudID = "i-0seed"_ctv;
      progress.ssh.address = "44.0.0.10"_ctv;
      progress.ssh.port = 22;
      progress.ssh.user = "root"_ctv;
      progress.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
      prodigyAppendUniqueClusterMachineAddress(progress.addresses.privateAddresses, "10.8.0.10"_ctv);
      prodigyAppendUniqueClusterMachineAddress(progress.addresses.publicAddresses, "44.0.0.10"_ctv);
      progress.providerName = "seed-0"_ctv;
      progress.status = "waiting-for-running"_ctv;
      iaas.progressToEmit.push_back(progress);
      iaas.snapshotsToReturn.push_back(makeMachineSnapshot("aws-brain-vm"_ctv, "10.8.0.10"_ctv, "i-0seed"_ctv));

      ClusterMachine seedMachine = {};
      ProdigyTimingAttribution timingAttribution = {};
      String failure;
      bool ok = mothershipProvisionCreatedSeedMachine(cluster, instruction, iaas, seedMachine, &progressSink, &timingAttribution, &failure);
      suite.expect(ok, "seed_provision_ok");
      suite.expect(failure.size() == 0, "seed_provision_no_failure");
      suite.expect(iaas.spinCalls == 1, "seed_provision_spin_called");
      suite.expect(iaas.destroyCalls == 0, "seed_provision_no_destroy");
      suite.expect(progressSink.calls == 1, "seed_provision_progress_called");
      suite.expect(progressSink.lastProgress.size() == 1, "seed_provision_progress_count");
      suite.expect(progressSink.lastProgress[0].cloud.cloudID.equals("i-0seed"_ctv), "seed_provision_progress_cloud_id");
      suite.expect(seedMachine.source == ClusterMachineSource::created, "seed_provision_source_created");
      suite.expect(seedMachine.isBrain, "seed_provision_is_brain");
      suite.expect(seedMachine.cloud.schema.equals("aws-brain-vm"_ctv), "seed_provision_machine_schema");
      suite.expect(seedMachine.cloud.providerMachineType.equals("c7i.large"_ctv), "seed_provision_provider_machine_type");
      suite.expect(seedMachine.cloud.cloudID.equals("i-0seed"_ctv), "seed_provision_cloud_id");
      suite.expect(seedMachine.ssh.address.equals("10.8.0.10"_ctv), "seed_provision_ssh_address");
      suite.expect(seedMachine.totalLogicalCores == 4, "seed_provision_total_cores_from_snapshot");
      suite.expect(seedMachine.totalMemoryMB == 8192, "seed_provision_total_memory_from_snapshot");
      suite.expect(seedMachine.totalStorageMB == 65536, "seed_provision_total_storage_from_snapshot");
      suite.expect(seedMachine.ownedLogicalCores > 0, "seed_provision_owned_cores_resolved");
      suite.expect(seedMachine.ownedMemoryMB > 0, "seed_provision_owned_memory_resolved");
      suite.expect(seedMachine.ownedStorageMB > 0, "seed_provision_owned_storage_resolved");
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
      suite.expect(timingAttribution.providerWaitNs <= prodigyTimingAttributionTotalNs(timingAttribution), "seed_provision_timing_provider_wait_bounded");
#endif
   }

   {
      MothershipProdigyCluster cluster = {};
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-brain-vm"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));

      CreateMachinesInstruction instruction = {};
      instruction.kind = MachineConfig::MachineKind::vm;
      instruction.lifetime = MachineLifetime::ondemand;
      instruction.backing = ClusterMachineBacking::cloud;
      instruction.cloud.schema = "aws-brain-vm"_ctv;
      instruction.cloud.providerMachineType = "c7i.large"_ctv;

      FakeProvisionBrainIaaS iaas;
      iaas.autoProvision = false;

      ClusterMachine seedMachine = {};
      String failure;
      bool ok = mothershipProvisionCreatedSeedMachine(cluster, instruction, iaas, seedMachine, nullptr, nullptr, &failure);
      suite.expect(!ok, "seed_provision_rejects_missing_auto_provision");
      suite.expect(failure.equals("current runtime environment does not support automatic machine provisioning"_ctv), "seed_provision_missing_auto_provision_failure");
   }

   {
      MothershipProdigyCluster cluster = {};
      cluster.name = "local-dev"_ctv;
      cluster.clusterUUID = 0x1001;
      cluster.deploymentMode = MothershipClusterDeploymentMode::local;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/local.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("local-dev"_ctv, MachineConfig::MachineKind::bareMetal, 8, 16384, 131072));
      cluster.bgp.specified = true;
      cluster.desiredEnvironment = ProdigyEnvironmentKind::dev;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();

      FakeClusterCreateHooks hooks;
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("local-dev"_ctv, "10.0.0.10"_ctv, true, ClusterMachineSource::adopted));

      String failure;
      suite.expect(
         prodigyReadSSHKeyPackageFromPrivateKeyPath(
            cluster.bootstrapSshPrivateKeyPath,
            cluster.bootstrapSshKeyPackage,
            &failure),
         "create_local_reads_bootstrap_ssh_key_package");
      suite.expect(
         prodigyReadSSHKeyPackageFromPrivateKeyPath(
            prodigyTestSSHDHostPrivateKeyPath(),
            cluster.bootstrapSshHostKeyPackage,
            &failure),
         "create_local_reads_bootstrap_ssh_host_key_package");
      failure.clear();
      bool ok = mothershipStandUpCluster(cluster, nullptr, hooks, nullptr, &failure);
      suite.expect(ok, "create_local_flow_ok");
      suite.expect(failure.size() == 0, "create_local_flow_no_failure");
      suite.expect(hooks.localBootstrapCalls == 1, "create_local_bootstraps_local_seed");
      suite.expect(hooks.createSeedCalls == 0, "create_local_no_provider_seed");
      suite.expect(hooks.remoteBootstrapCalls == 0, "create_local_no_remote_bootstrap");
      suite.expect(hooks.configureCalls == 1, "create_local_configures_seed");
      suite.expect(hooks.fetchTopologyCalls == 1, "create_local_fetches_topology");
      suite.expect(hooks.addMachinesCalls == 0, "create_local_no_addmachines");
      suite.expect(hooks.lastLocalBootState.bootstrapConfig.nodeRole == ProdigyBootstrapNodeRole::brain, "create_local_boot_role_brain");
      suite.expect(hooks.lastLocalBootState.bootstrapConfig.controlSocketPath == "/run/prodigy/local.sock"_ctv, "create_local_boot_control_path");
      suite.expect(hooks.lastLocalBootState.bootstrapSshUser.equals(cluster.bootstrapSshUser), "create_local_boot_ssh_user");
      suite.expect(hooks.lastLocalBootState.bootstrapSshKeyPackage == cluster.bootstrapSshKeyPackage, "create_local_boot_ssh_key_package");
      suite.expect(hooks.lastLocalBootState.bootstrapSshHostKeyPackage == cluster.bootstrapSshHostKeyPackage, "create_local_boot_ssh_host_key_package");
      suite.expect(hooks.lastLocalBootState.bootstrapSshPrivateKeyPath.equals(cluster.bootstrapSshPrivateKeyPath), "create_local_boot_ssh_private_key_path");
      suite.expect(hooks.lastLocalBootState.runtimeEnvironment.kind == ProdigyEnvironmentKind::dev, "create_local_boot_env");
      suite.expect(hooks.lastLocalBootState.runtimeEnvironment.bgp.specified, "create_local_boot_env_bgp_specified");
      suite.expect(hooks.lastLocalBootState.runtimeEnvironment.bgp.config.enabled == false, "create_local_boot_env_bgp_disabled");
      suite.expect(hooks.lastConfig.runtimeEnvironment.bgp.specified, "create_local_config_bgp_specified");
      suite.expect(hooks.lastConfig.runtimeEnvironment.bgp.config.enabled == false, "create_local_config_bgp_disabled");
      suite.expect(hooks.lastConfig.clusterUUID == cluster.clusterUUID, "create_local_config_cluster_uuid");
      suite.expect(hooks.lastConfig.configBySlug.find("local-dev"_ctv) != hooks.lastConfig.configBySlug.end(), "create_local_config_contains_machine_schema");
      suite.expect(cluster.topology == hooks.fetchedTopology, "create_local_topology_persisted");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::localBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::fetchTopology
      }), "create_local_call_sequence");
   }

   {
      MothershipProdigyCluster cluster = {};
      cluster.name = "local-minimal"_ctv;
      cluster.clusterUUID = 0x1002;
      cluster.deploymentMode = MothershipClusterDeploymentMode::local;
      cluster.includeLocalMachine = true;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/local-minimal.sock"_ctv));

      FakeClusterCreateHooks hooks;
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("local-minimal"_ctv, "10.0.0.11"_ctv, true, ClusterMachineSource::adopted));

      String failure;
      bool ok = mothershipStandUpCluster(cluster, nullptr, hooks, nullptr, &failure);
      suite.expect(ok, "create_local_minimal_flow_ok");
      suite.expect(failure.size() == 0, "create_local_minimal_no_failure");
      suite.expect(hooks.localBootstrapCalls == 1, "create_local_minimal_bootstraps_local_seed");
      suite.expect(hooks.configureCalls == 1, "create_local_minimal_always_configures_seed");
      suite.expect(hooks.lastConfig.clusterUUID == cluster.clusterUUID, "create_local_minimal_config_cluster_uuid");
      suite.expect(hooks.lastConfig.datacenterFragment == cluster.datacenterFragment, "create_local_minimal_config_fragment");
      suite.expect(hooks.lastConfig.autoscaleIntervalSeconds == cluster.autoscaleIntervalSeconds, "create_local_minimal_config_autoscale_interval");
      suite.expect(hooks.lastConfig.sharedCPUOvercommitPermille == cluster.sharedCPUOvercommitPermille, "create_local_minimal_config_shared_cpu_overcommit");
      suite.expect(cluster.environmentConfigured, "create_local_minimal_environment_configured");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::localBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::fetchTopology
      }), "create_local_minimal_call_sequence");
   }

   {
      MothershipProdigyCluster cluster = {};
      cluster.name = "test-local"_ctv;
      cluster.clusterUUID = 0x5555;
      cluster.deploymentMode = MothershipClusterDeploymentMode::test;
      cluster.nBrains = 2;
      cluster.sharedCPUOvercommitPermille = 1500;
      cluster.test.specified = true;
      cluster.test.workspaceRoot = "/tmp/test-local"_ctv;
      cluster.test.machineCount = 3;
      cluster.test.brainBootstrapFamily = MothershipClusterTestBootstrapFamily::private6;
      cluster.test.interContainerMTU = 9000;
      cluster.test.host.mode = MothershipClusterTestHostMode::local;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/test-local.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("bootstrap"_ctv, MachineConfig::MachineKind::bareMetal, 8, 16384, 262144));
      cluster.desiredEnvironment = ProdigyEnvironmentKind::dev;
      cluster.bgp.specified = true;
      cluster.bgp.config.enabled = false;

      FakeClusterCreateHooks hooks = {};
      hooks.fetchedTopology.version = 11;
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:10::a"_ctv, true, ClusterMachineSource::adopted));
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:10::b"_ctv, true, ClusterMachineSource::adopted));
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:10::c"_ctv, false, ClusterMachineSource::adopted));

      String failure = {};
      bool ok = mothershipStandUpCluster(cluster, nullptr, hooks, nullptr, &failure);
      suite.expect(ok, "create_test_flow_ok");
      suite.expect(failure.size() == 0, "create_test_flow_no_failure");
      suite.expect(hooks.startTestClusterCalls == 1, "create_test_starts_runner");
      suite.expect(hooks.stopTestClusterCalls == 0, "create_test_no_cleanup_on_success");
      suite.expect(hooks.localBootstrapCalls == 0, "create_test_no_local_seed_bootstrap");
      suite.expect(hooks.remoteBootstrapCalls == 0, "create_test_no_remote_seed_bootstrap");
      suite.expect(hooks.configureCalls == 1, "create_test_configures_cluster");
      suite.expect(hooks.fetchTopologyCalls == 1, "create_test_fetches_topology");
      suite.expect(hooks.addMachinesCalls == 0, "create_test_no_addmachines");
      suite.expect(cluster.topology == hooks.fetchedTopology, "create_test_topology_persisted");
      suite.expect(cluster.environmentConfigured, "create_test_environment_configured");
      suite.expect(hooks.lastConfig.sharedCPUOvercommitPermille == 1500, "create_test_config_shared_cpu_overcommit");
      suite.expect(hooks.lastConfig.runtimeEnvironment.test.enabled, "create_test_runtime_env_test_enabled");
      suite.expect(hooks.lastConfig.runtimeEnvironment.test.interContainerMTU == 9000, "create_test_runtime_env_inter_container_mtu");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::startTestCluster,
         ClusterCreateCall::configure,
         ClusterCreateCall::fetchTopology
      }), "create_test_call_sequence");
   }

   {
      MothershipProdigyCluster cluster = {};
      cluster.name = "test-topology-retry"_ctv;
      cluster.clusterUUID = 0x5556;
      cluster.deploymentMode = MothershipClusterDeploymentMode::test;
      cluster.nBrains = 2;
      cluster.test.specified = true;
      cluster.test.workspaceRoot = "/tmp/test-topology-retry"_ctv;
      cluster.test.machineCount = 3;
      cluster.test.host.mode = MothershipClusterTestHostMode::local;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/test-topology-retry.sock"_ctv));

      FakeClusterCreateHooks hooks = {};
      ClusterTopology partialTopology = {};
      partialTopology.version = 1;
      partialTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:20::a"_ctv, true, ClusterMachineSource::adopted));
      ClusterTopology finalTopology = partialTopology;
      finalTopology.version = 2;
      finalTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:20::b"_ctv, true, ClusterMachineSource::adopted));
      finalTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:20::c"_ctv, false, ClusterMachineSource::adopted));
      hooks.fetchedTopologySequence.push_back(partialTopology);
      hooks.fetchedTopologySequence.push_back(finalTopology);

      String failure = {};
      bool ok = mothershipStandUpCluster(cluster, nullptr, hooks, nullptr, &failure);
      suite.expect(ok, "create_test_topology_retry_ok");
      suite.expect(failure.size() == 0, "create_test_topology_retry_no_failure");
      suite.expect(hooks.fetchTopologyCalls == 2, "create_test_topology_retry_fetches_until_ready");
      suite.expect(cluster.topology == finalTopology, "create_test_topology_retry_persists_final_topology");
      suite.expect(hooks.callSequence.size() == 4, "create_test_topology_retry_call_count");
      suite.expect(hooks.callSequence[0] == ClusterCreateCall::startTestCluster, "create_test_topology_retry_starts_runner_first");
      suite.expect(hooks.callSequence[1] == ClusterCreateCall::configure, "create_test_topology_retry_configures_before_fetch");
      suite.expect(hooks.callSequence[2] == ClusterCreateCall::fetchTopology, "create_test_topology_retry_first_fetch");
      suite.expect(hooks.callSequence[3] == ClusterCreateCall::fetchTopology, "create_test_topology_retry_second_fetch");
   }

   {
      MothershipProdigyCluster cluster = {};
      cluster.name = "test-resource-readiness-retry"_ctv;
      cluster.clusterUUID = 0x5557;
      cluster.deploymentMode = MothershipClusterDeploymentMode::test;
      cluster.nBrains = 2;
      cluster.test.specified = true;
      cluster.test.workspaceRoot = "/tmp/test-resource-readiness-retry"_ctv;
      cluster.test.machineCount = 3;
      cluster.test.host.mode = MothershipClusterTestHostMode::local;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/test-resource-readiness-retry.sock"_ctv));

      FakeClusterCreateHooks hooks = {};
      ClusterTopology unreadyTopology = {};
      unreadyTopology.version = 1;
      unreadyTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:21::a"_ctv, true, ClusterMachineSource::adopted));
      unreadyTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:21::b"_ctv, true, ClusterMachineSource::adopted));
      unreadyTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:21::c"_ctv, false, ClusterMachineSource::adopted));
      for (ClusterMachine& machine : unreadyTopology.machines)
      {
         machine.totalLogicalCores = 0;
         machine.totalMemoryMB = 0;
         machine.totalStorageMB = 0;
         machine.ownedLogicalCores = 0;
         machine.ownedMemoryMB = 0;
         machine.ownedStorageMB = 0;
      }

      ClusterTopology readyTopology = {};
      readyTopology.version = 2;
      readyTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:21::a"_ctv, true, ClusterMachineSource::adopted));
      readyTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:21::b"_ctv, true, ClusterMachineSource::adopted));
      readyTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "fd00:21::c"_ctv, false, ClusterMachineSource::adopted));
      hooks.fetchedTopologySequence.push_back(unreadyTopology);
      hooks.fetchedTopologySequence.push_back(readyTopology);

      String failure = {};
      bool ok = mothershipStandUpCluster(cluster, nullptr, hooks, nullptr, &failure);
      suite.expect(ok, "create_test_resource_readiness_retry_ok");
      suite.expect(failure.size() == 0, "create_test_resource_readiness_retry_no_failure");
      suite.expect(hooks.fetchTopologyCalls == 2, "create_test_resource_readiness_retry_fetches_until_ready");
      suite.expect(cluster.topology == readyTopology, "create_test_resource_readiness_retry_persists_ready_topology");
      suite.expect(hooks.callSequence.size() == 4, "create_test_resource_readiness_retry_call_count");
      suite.expect(hooks.callSequence[0] == ClusterCreateCall::startTestCluster, "create_test_resource_readiness_retry_starts_runner_first");
      suite.expect(hooks.callSequence[1] == ClusterCreateCall::configure, "create_test_resource_readiness_retry_configures_before_fetch");
      suite.expect(hooks.callSequence[2] == ClusterCreateCall::fetchTopology, "create_test_resource_readiness_retry_first_fetch");
      suite.expect(hooks.callSequence[3] == ClusterCreateCall::fetchTopology, "create_test_resource_readiness_retry_second_fetch");
   }

   {
      MothershipProdigyCluster cluster = {};
      cluster.name = "test-failure"_ctv;
      cluster.clusterUUID = 0x7777;
      cluster.deploymentMode = MothershipClusterDeploymentMode::test;
      cluster.nBrains = 1;
      cluster.test.specified = true;
      cluster.test.workspaceRoot = "/tmp/test-failure"_ctv;
      cluster.test.machineCount = 1;
      cluster.test.host.mode = MothershipClusterTestHostMode::local;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/test-failure.sock"_ctv));

      FakeClusterCreateHooks hooks = {};
      hooks.failConfigureSeedCluster = true;

      String failure = {};
      bool ok = mothershipStandUpCluster(cluster, nullptr, hooks, nullptr, &failure);
      suite.expect(ok == false, "create_test_failure_propagates");
      suite.expect(hooks.startTestClusterCalls == 1, "create_test_failure_starts_runner");
      suite.expect(hooks.stopTestClusterCalls == 1, "create_test_failure_cleans_runner");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::startTestCluster,
         ClusterCreateCall::configure,
         ClusterCreateCall::stopTestCluster
      }), "create_test_failure_call_sequence");
   }

   {
      MothershipProdigyCluster currentCluster = {};
      currentCluster.name = "test-resize-current"_ctv;
      currentCluster.clusterUUID = 0x7788;
      currentCluster.deploymentMode = MothershipClusterDeploymentMode::test;
      currentCluster.nBrains = 3;
      currentCluster.test.specified = true;
      currentCluster.test.workspaceRoot = "/tmp/test-resize-current"_ctv;
      currentCluster.test.machineCount = 3;
      currentCluster.test.host.mode = MothershipClusterTestHostMode::local;
      currentCluster.controls.push_back(makeUnixControl("/run/prodigy/test-resize.sock"_ctv));

      MothershipProdigyCluster desiredCluster = currentCluster;
      desiredCluster.name = "test-resize-desired"_ctv;
      desiredCluster.test.workspaceRoot = "/tmp/test-resize-desired"_ctv;
      desiredCluster.test.machineCount = 4;
      appendClusterMachineConfig(desiredCluster, makeMachineConfig("bootstrap"_ctv, MachineConfig::MachineKind::bareMetal, 8, 16384, 262144));
      desiredCluster.desiredEnvironment = ProdigyEnvironmentKind::dev;

      ClusterTopology currentTopology = {};
      currentTopology.version = 9;
      currentTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "10.44.0.1"_ctv, true, ClusterMachineSource::adopted));
      currentTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "10.44.0.2"_ctv, true, ClusterMachineSource::adopted));
      currentTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "10.44.0.3"_ctv, true, ClusterMachineSource::adopted));

      FakeClusterCreateHooks hooks = {};
      hooks.fetchedTopology.version = 10;
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "10.44.0.1"_ctv, true, ClusterMachineSource::adopted));
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "10.44.0.2"_ctv, true, ClusterMachineSource::adopted));
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "10.44.0.3"_ctv, true, ClusterMachineSource::adopted));
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "10.44.0.4"_ctv, false, ClusterMachineSource::adopted));

      bool changed = false;
      String failure = {};
      bool ok = mothershipRestartTestClusterToDesiredShape(currentCluster, desiredCluster, currentTopology, hooks, changed, &failure);
      suite.expect(ok, "create_test_resize_restart_ok");
      suite.expect(failure.size() == 0, "create_test_resize_restart_no_failure");
      suite.expect(changed, "create_test_resize_restart_changed");
      suite.expect(hooks.stopTestClusterCalls == 1, "create_test_resize_restart_stops_runner");
      suite.expect(hooks.startTestClusterCalls == 1, "create_test_resize_restart_starts_runner");
      suite.expect(hooks.configureCalls == 1, "create_test_resize_restart_configures_cluster");
      suite.expect(hooks.fetchTopologyCalls == 1, "create_test_resize_restart_fetches_topology");
      suite.expect(desiredCluster.topology == hooks.fetchedTopology, "create_test_resize_restart_persists_topology");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::stopTestCluster,
         ClusterCreateCall::startTestCluster,
         ClusterCreateCall::configure,
         ClusterCreateCall::fetchTopology
      }), "create_test_resize_restart_call_sequence");
   }

   {
      MothershipProdigyCluster currentCluster = {};
      currentCluster.name = "test-resize-noop"_ctv;
      currentCluster.clusterUUID = 0x7789;
      currentCluster.deploymentMode = MothershipClusterDeploymentMode::test;
      currentCluster.nBrains = 3;
      currentCluster.test.specified = true;
      currentCluster.test.workspaceRoot = "/tmp/test-resize-noop"_ctv;
      currentCluster.test.machineCount = 3;
      currentCluster.test.host.mode = MothershipClusterTestHostMode::local;

      MothershipProdigyCluster desiredCluster = currentCluster;

      ClusterTopology currentTopology = {};
      currentTopology.version = 12;
      currentTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "10.45.0.1"_ctv, true, ClusterMachineSource::adopted));
      currentTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "10.45.0.2"_ctv, true, ClusterMachineSource::adopted));
      currentTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "10.45.0.3"_ctv, true, ClusterMachineSource::adopted));

      FakeClusterCreateHooks hooks = {};
      bool changed = false;
      String failure = {};
      bool ok = mothershipRestartTestClusterToDesiredShape(currentCluster, desiredCluster, currentTopology, hooks, changed, &failure);
      suite.expect(ok, "create_test_resize_noop_ok");
      suite.expect(failure.size() == 0, "create_test_resize_noop_no_failure");
      suite.expect(changed == false, "create_test_resize_noop_not_changed");
      suite.expect(hooks.stopTestClusterCalls == 0, "create_test_resize_noop_does_not_stop_runner");
      suite.expect(hooks.startTestClusterCalls == 0, "create_test_resize_noop_does_not_start_runner");
      suite.expect(desiredCluster.topology == currentTopology, "create_test_resize_noop_preserves_topology");
   }

   {
      MothershipProdigyCluster cluster = {};
      cluster.name = "local-with-adopted"_ctv;
      cluster.clusterUUID = 0x1002;
      cluster.deploymentMode = MothershipClusterDeploymentMode::local;
      cluster.includeLocalMachine = true;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/homelab.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("homelab-brain"_ctv, MachineConfig::MachineKind::vm, 8, 16384, 131072));
      appendClusterMachineConfig(cluster, makeMachineConfig("homelab-worker"_ctv, MachineConfig::MachineKind::vm, 4, 8192, 65536));
      cluster.nBrains = 3;
      cluster.sharedCPUOvercommitPermille = 1250;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = "/root/.ssh/homelab"_ctv;
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      cluster.bgp.specified = true;
      cluster.bgp.config.enabled = true;
      cluster.bgp.config.ourBGPID = inet_addr("10.0.0.21");
      cluster.bgp.config.nextHop4 = IPAddress("10.0.0.1", false);
      cluster.bgp.config.nextHop6 = IPAddress("2001:db8::1", true);
      cluster.bgp.config.peers.push_back(makeBGPConfigPeer("169.254.1.1"_ctv, "10.0.0.21"_ctv, 64512, "homelab-md5-v4"_ctv, 2));
      cluster.bgp.config.peers.push_back(makeBGPConfigPeer("2001:19f0:ffff::1"_ctv, "2001:db8::21"_ctv, 64512, "homelab-md5-v6"_ctv, 2));
      cluster.machines.push_back(makeAdoptedMachine("homelab-brain"_ctv, "10.0.0.21"_ctv, true));
      cluster.machines.push_back(makeAdoptedMachine("homelab-brain"_ctv, "10.0.0.22"_ctv, true));
      cluster.machines.push_back(makeAdoptedMachine("homelab-worker"_ctv, "10.0.0.23"_ctv, false));

      FakeClusterCreateHooks hooks;
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("bootstrap"_ctv, "10.0.0.20"_ctv, true, ClusterMachineSource::adopted));
      hooks.finalTopology = hooks.fetchedTopology;
      hooks.finalTopology.machines.push_back(makeTopologyMachine("homelab-brain"_ctv, "10.0.0.21"_ctv, true, ClusterMachineSource::adopted));
      hooks.finalTopology.machines.push_back(makeTopologyMachine("homelab-brain"_ctv, "10.0.0.22"_ctv, true, ClusterMachineSource::adopted));
      hooks.finalTopology.machines.push_back(makeTopologyMachine("homelab-worker"_ctv, "10.0.0.23"_ctv, false, ClusterMachineSource::adopted));

      String failure;
      bool ok = mothershipStandUpCluster(cluster, nullptr, hooks, nullptr, &failure);
      suite.expect(ok, "create_local_hybrid_flow_ok");
      suite.expect(hooks.localBootstrapCalls == 1, "create_local_hybrid_bootstraps_local_seed");
      suite.expect(hooks.lastConfig.clusterUUID == cluster.clusterUUID, "create_local_hybrid_config_cluster_uuid");
      suite.expect(hooks.lastConfig.sharedCPUOvercommitPermille == 1250, "create_local_hybrid_config_shared_cpu_overcommit");
      suite.expect(hooks.lastConfig.runtimeEnvironment.bgp.specified, "create_local_hybrid_config_bgp_specified");
      suite.expect(hooks.lastConfig.runtimeEnvironment.bgp.config.enabled, "create_local_hybrid_config_bgp_enabled");
      suite.expect(hooks.lastConfig.runtimeEnvironment.bgp.config.nextHop4.equals(IPAddress("10.0.0.1", false)), "create_local_hybrid_config_bgp_nextHop4");
      suite.expect(hooks.lastConfig.runtimeEnvironment.bgp.config.peers.size() == 2, "create_local_hybrid_config_bgp_peer_count");
      suite.expect(hooks.addMachinesCalls == 1, "create_local_hybrid_addmachines_called");
      suite.expect(hooks.lastAddMachinesRequest.adoptedMachines.size() == 3, "create_local_hybrid_adds_all_remote_adopted");
      suite.expect(cluster.topology == hooks.finalTopology, "create_local_hybrid_topology_persisted");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::localBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::fetchTopology,
         ClusterCreateCall::applyAddMachines
      }), "create_local_hybrid_call_sequence");
   }

   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::gcp;
      credential.material = "gcp-bootstrap-secret"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-adopted"_ctv;
      cluster.clusterUUID = 0x1003;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::gcp;
      cluster.providerScope = "projects/example"_ctv;
      cluster.providerCredentialName = "gcp-prod"_ctv;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("gcp-brain"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));
      appendClusterMachineConfig(cluster, makeMachineConfig("gcp-worker"_ctv, MachineConfig::MachineKind::vm, 4, 8192, 65536));
      cluster.nBrains = 3;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      cluster.machines.push_back(makeAdoptedMachine("gcp-brain"_ctv, "10.1.0.10"_ctv, true, ClusterMachineBacking::cloud));
      cluster.machines.push_back(makeAdoptedMachine("gcp-brain"_ctv, "10.1.0.11"_ctv, true, ClusterMachineBacking::cloud));
      cluster.machines.push_back(makeAdoptedMachine("gcp-brain"_ctv, "10.1.0.12"_ctv, true, ClusterMachineBacking::cloud));
      cluster.machines.push_back(makeAdoptedMachine("gcp-worker"_ctv, "10.1.0.13"_ctv, false, ClusterMachineBacking::cloud));

      FakeClusterCreateHooks hooks;
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("gcp-brain"_ctv, "10.1.0.10"_ctv, true, ClusterMachineSource::adopted, ClusterMachineBacking::cloud));
      hooks.finalTopology = hooks.fetchedTopology;
      hooks.finalTopology.machines.push_back(makeTopologyMachine("gcp-brain"_ctv, "10.1.0.11"_ctv, true, ClusterMachineSource::adopted, ClusterMachineBacking::cloud));
      hooks.finalTopology.machines.push_back(makeTopologyMachine("gcp-brain"_ctv, "10.1.0.12"_ctv, true, ClusterMachineSource::adopted, ClusterMachineBacking::cloud));
      hooks.finalTopology.machines.push_back(makeTopologyMachine("gcp-worker"_ctv, "10.1.0.13"_ctv, false, ClusterMachineSource::adopted, ClusterMachineBacking::cloud));
      hooks.fetchedTopologySequence.push_back(hooks.fetchedTopology);
      hooks.fetchedTopologySequence.push_back(hooks.finalTopology);

      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, nullptr, &failure);
      suite.expect(ok, "create_remote_adopted_flow_ok");
      suite.expect(hooks.prepareProviderBootstrapArtifactsCalls == 0, "create_remote_adopted_no_gcp_template_prepare");
      suite.expect(hooks.localBootstrapCalls == 0, "create_remote_adopted_no_local_bootstrap");
      suite.expect(hooks.createSeedCalls == 0, "create_remote_adopted_no_provider_seed");
      suite.expect(hooks.remoteBootstrapCalls == 1, "create_remote_adopted_bootstraps_seed_brain");
      suite.expect(hooks.lastRemoteSeedClusterUUID == cluster.clusterUUID, "create_remote_adopted_bootstrap_cluster_uuid");
      suite.expect(hooks.lastRemoteSeedMachine.addresses.privateAddresses.size() == 1 && hooks.lastRemoteSeedMachine.addresses.privateAddresses[0].address == "10.1.0.10"_ctv, "create_remote_adopted_uses_first_brain_seed");
      suite.expect(hooks.lastRemoteBootstrapRequest.controlSocketPath == "/run/prodigy/control.sock"_ctv, "create_remote_adopted_bootstrap_request_control_socket");
      suite.expect(hooks.lastRemoteBootstrapRequest.clusterUUID == cluster.clusterUUID, "create_remote_adopted_bootstrap_request_cluster_uuid");
      suite.expect(hooks.lastRemoteBootstrapRequest.bootstrapSshPrivateKeyPath.equals(prodigyTestBootstrapSeedSSHPrivateKeyPath()), "create_remote_adopted_bootstrap_request_ssh_key");
      suite.expect(hooks.lastRemoteBootstrapTopology.machines.size() == 1, "create_remote_adopted_seed_topology_size");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.kind == ProdigyEnvironmentKind::gcp, "create_remote_adopted_bootstrap_runtime_env_kind");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_adopted_bootstrap_runtime_env_secret_withheld");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.bgp.configured() == false, "create_remote_adopted_bootstrap_runtime_env_no_bgp_override");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.aws.bootstrapLaunchTemplateName.size() == 0, "create_remote_adopted_bootstrap_runtime_env_no_aws_launch_template_name");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.aws.bootstrapLaunchTemplateVersion.size() == 0, "create_remote_adopted_bootstrap_runtime_env_no_aws_launch_template_version");
      suite.expect(hooks.configureConfigs.size() == 1, "create_remote_adopted_configure_count");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_adopted_initial_runtime_env_secret_withheld");
      suite.expect(hooks.lastConfig.runtimeEnvironment.kind == ProdigyEnvironmentKind::gcp, "create_remote_adopted_runtime_env_kind");
      suite.expect(hooks.lastConfig.runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_adopted_runtime_env_secret_withheld");
      suite.expect(hooks.lastConfig.runtimeEnvironment.bgp.configured() == false, "create_remote_adopted_runtime_env_no_bgp_override");
      suite.expect(hooks.lastConfig.runtimeEnvironment.aws.bootstrapLaunchTemplateName.size() == 0, "create_remote_adopted_runtime_env_no_aws_launch_template_name");
      suite.expect(hooks.lastConfig.runtimeEnvironment.aws.bootstrapLaunchTemplateVersion.size() == 0, "create_remote_adopted_runtime_env_no_aws_launch_template_version");
      suite.expect(hooks.lastConfig.clusterUUID == cluster.clusterUUID, "create_remote_adopted_config_cluster_uuid");
      suite.expect(hooks.addMachinesCalls == 1, "create_remote_adopted_addmachines_called");
      suite.expect(hooks.lastAddMachinesRequest.clusterUUID == cluster.clusterUUID, "create_remote_adopted_addmachines_request_cluster_uuid");
      suite.expect(hooks.lastAddMachinesRequest.adoptedMachines.size() == 3, "create_remote_adopted_adds_remaining_adopted");
      suite.expect(cluster.topology == hooks.finalTopology, "create_remote_adopted_topology_persisted");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::remoteBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::fetchTopology,
         ClusterCreateCall::applyAddMachines
      }), "create_remote_adopted_call_sequence");
   }

   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::gcp;
      credential.material = "gcp-bootstrap-secret"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-gcp-managed"_ctv;
      cluster.clusterUUID = 0x1003'1003;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::gcp;
      cluster.providerScope = "projects/example/zones/us-central1-a"_ctv;
      cluster.providerCredentialName = "gcp-prod"_ctv;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      cluster.nBrains = 3;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      cluster.gcp.serviceAccountEmail = "prodigy-brain@example.iam.gserviceaccount.com"_ctv;
      cluster.gcp.network = "global/networks/default"_ctv;
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "gcp-brain-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .vmImageURI = "projects/example/global/images/gcp-brain"_ctv,
         .gcpInstanceTemplate = "managed-template"_ctv,
         .providerMachineType = "e2-medium"_ctv,
         .budget = 3
      });
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "gcp-worker-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::spot,
         .vmImageURI = "projects/example/global/images/gcp-worker"_ctv,
         .gcpInstanceTemplateSpot = "managed-template-spot"_ctv,
         .providerMachineType = "e2-medium"_ctv,
         .budget = 2
      });

      FakeClusterCreateHooks hooks;
      hooks.createdSeedMachine = makeTopologyMachine(
         "gcp-brain-vm"_ctv,
         "10.2.0.20"_ctv,
         true,
         ClusterMachineSource::created,
         ClusterMachineBacking::cloud,
         "e2-medium"_ctv);
      hooks.fetchedTopology.machines.push_back(hooks.createdSeedMachine);
      hooks.finalTopology = hooks.fetchedTopology;

      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, nullptr, &failure);
      suite.expect(ok, "create_remote_gcp_managed_flow_ok");
      suite.expect(hooks.prepareProviderBootstrapArtifactsCalls == 1, "create_remote_gcp_managed_prepares_templates");
      suite.expect(hooks.createSeedCalls == 1, "create_remote_gcp_managed_creates_seed");
      suite.expect(hooks.lastCreateSeedInstruction.count == 1, "create_remote_gcp_managed_seed_count");
      suite.expect(hooks.lastCreateSeedInstruction.isBrain, "create_remote_gcp_managed_seed_is_brain");
      suite.expect(hooks.lastCreateSeedInstruction.cloud.schema == "gcp-brain-vm"_ctv, "create_remote_gcp_managed_seed_schema");
      suite.expect(hooks.lastCreateSeedInstruction.cloud.providerMachineType == "e2-medium"_ctv, "create_remote_gcp_managed_seed_machine_type");
      suite.expect(hooks.remoteBootstrapCalls == 1, "create_remote_gcp_managed_bootstraps_created_seed");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.kind == ProdigyEnvironmentKind::gcp, "create_remote_gcp_managed_bootstrap_runtime_env_kind");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_gcp_managed_bootstrap_runtime_env_secret_withheld");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.size() == 0, "create_remote_gcp_managed_bootstrap_runtime_env_refresh_command_withheld");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint.size() == 0, "create_remote_gcp_managed_bootstrap_runtime_env_refresh_hint_withheld");
      suite.expect(hooks.configureConfigs.size() == 1, "create_remote_gcp_managed_configure_count");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_gcp_managed_runtime_env_secret_withheld");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.size() == 0, "create_remote_gcp_managed_runtime_env_refresh_command_withheld");
      suite.expect(hooks.lastConfig.runtimeEnvironment.kind == ProdigyEnvironmentKind::gcp, "create_remote_gcp_managed_runtime_env_kind");
      suite.expect(hooks.lastConfig.runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_gcp_managed_runtime_env_secret_withheld");
      suite.expect(hooks.lastConfig.runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.size() == 0, "create_remote_gcp_managed_runtime_env_refresh_command_withheld_final");
      suite.expect(hooks.addMachinesCalls == 0, "create_remote_gcp_managed_no_manual_addmachines");
      suite.expect(hooks.fetchTopologyCalls == 0, "create_remote_gcp_managed_skips_seed_topology_fetch");
      suite.expect(hooks.upsertMachineSchemasCalls == 1, "create_remote_gcp_managed_upserts_machine_schemas");
      suite.expect(hooks.lastMachineSchemaPatches.size() == 2, "create_remote_gcp_managed_machine_schema_patch_count");
      suite.expect(hooks.lastMachineSchemaPatches[0].schema == "gcp-brain-vm"_ctv, "create_remote_gcp_managed_first_patch_schema");
      suite.expect(hooks.lastMachineSchemaPatches[0].hasBudget && hooks.lastMachineSchemaPatches[0].budget == 3, "create_remote_gcp_managed_first_patch_budget");
      suite.expect(hooks.lastMachineSchemaPatches[1].schema == "gcp-worker-vm"_ctv, "create_remote_gcp_managed_second_patch_schema");
      suite.expect(hooks.lastMachineSchemaPatches[1].hasBudget && hooks.lastMachineSchemaPatches[1].budget == 2, "create_remote_gcp_managed_second_patch_budget");
      suite.expect(cluster.topology == hooks.finalTopology, "create_remote_gcp_managed_topology_persisted");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::prepareProviderBootstrapArtifacts,
         ClusterCreateCall::createSeed,
         ClusterCreateCall::remoteBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::upsertMachineSchemas
      }), "create_remote_gcp_managed_call_sequence");
   }

   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::aws;
      credential.material = "aws-secret"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-created"_ctv;
      cluster.clusterUUID = 0x1004;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::aws;
      cluster.providerScope = "acct/us-east-1"_ctv;
      cluster.providerCredentialName = "aws-prod"_ctv;
      cluster.aws.instanceProfileName = "prodigy-controller-profile"_ctv;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-brain-vm"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-worker-vm"_ctv, MachineConfig::MachineKind::vm, 8, 32768, 262144));
      cluster.nBrains = 3;
      cluster.sharedCPUOvercommitPermille = 1750;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "aws-brain-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "c7i.large"_ctv,
         .budget = 3
      });
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "aws-worker-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::spot,
         .providerMachineType = "c7i.xlarge"_ctv,
         .budget = 2
      });

      FakeClusterCreateHooks hooks;
      hooks.createdSeedMachine = makeTopologyMachine(
         "aws-brain-vm"_ctv,
         "10.2.0.10"_ctv,
         true,
         ClusterMachineSource::created,
         ClusterMachineBacking::cloud,
         "c7i.large"_ctv);
      hooks.fetchedTopology.machines.push_back(hooks.createdSeedMachine);
      hooks.finalTopology = hooks.fetchedTopology;

      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, nullptr, &failure);
      suite.expect(ok, "create_remote_managed_flow_ok");
      suite.expect(hooks.createSeedCalls == 1, "create_remote_managed_creates_seed");
      suite.expect(hooks.lastCreateSeedInstruction.count == 1, "create_remote_managed_seed_count");
      suite.expect(hooks.lastCreateSeedInstruction.isBrain, "create_remote_managed_seed_is_brain");
      suite.expect(hooks.remoteBootstrapCalls == 1, "create_remote_managed_bootstraps_created_seed");
      suite.expect(hooks.lastRemoteSeedClusterUUID == cluster.clusterUUID, "create_remote_managed_bootstrap_cluster_uuid");
      suite.expect(hooks.lastRemoteBootstrapRequest.clusterUUID == cluster.clusterUUID, "create_remote_managed_bootstrap_request_cluster_uuid");
      suite.expect(hooks.lastRemoteBootstrapTopology.machines.size() == 1, "create_remote_managed_seed_topology_size");
      suite.expect(hooks.lastRemoteBootstrapTopology.machines[0] == hooks.createdSeedMachine, "create_remote_managed_seed_topology_machine");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.kind == ProdigyEnvironmentKind::aws, "create_remote_managed_bootstrap_runtime_env_kind");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_managed_bootstrap_runtime_env_secret_withheld");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.bgp.configured() == false, "create_remote_managed_bootstrap_runtime_env_no_bgp_override");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.aws.bootstrapLaunchTemplateName == "prodigy-bootstrap-us-east-1"_ctv, "create_remote_managed_bootstrap_runtime_env_launch_template_name");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.aws.bootstrapLaunchTemplateVersion == "$Default"_ctv, "create_remote_managed_bootstrap_runtime_env_launch_template_version");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.aws.instanceProfileName.equals(cluster.aws.instanceProfileName), "create_remote_managed_bootstrap_runtime_env_instance_profile_name");
      suite.expect(hooks.configureConfigs.size() == 1, "create_remote_managed_configure_count");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_managed_initial_runtime_env_secret_withheld");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.aws.instanceProfileName.equals(cluster.aws.instanceProfileName), "create_remote_managed_initial_runtime_env_instance_profile_name");
      suite.expect(hooks.lastConfig.runtimeEnvironment.kind == ProdigyEnvironmentKind::aws, "create_remote_managed_runtime_env_kind");
      suite.expect(hooks.lastConfig.runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_managed_runtime_env_secret");
      suite.expect(hooks.lastConfig.runtimeEnvironment.bgp.configured() == false, "create_remote_managed_runtime_env_no_bgp_override");
      suite.expect(hooks.lastConfig.runtimeEnvironment.aws.bootstrapLaunchTemplateName == "prodigy-bootstrap-us-east-1"_ctv, "create_remote_managed_runtime_env_launch_template_name");
      suite.expect(hooks.lastConfig.runtimeEnvironment.aws.bootstrapLaunchTemplateVersion == "$Default"_ctv, "create_remote_managed_runtime_env_launch_template_version");
      suite.expect(hooks.lastConfig.runtimeEnvironment.aws.instanceProfileName.equals(cluster.aws.instanceProfileName), "create_remote_managed_runtime_env_instance_profile_name");
      suite.expect(hooks.lastConfig.clusterUUID == cluster.clusterUUID, "create_remote_managed_config_cluster_uuid");
      suite.expect(hooks.lastConfig.sharedCPUOvercommitPermille == 1750, "create_remote_managed_config_shared_cpu_overcommit");
      suite.expect(hooks.addMachinesCalls == 0, "create_remote_managed_no_manual_addmachines");
      suite.expect(hooks.fetchTopologyCalls == 0, "create_remote_managed_skips_seed_topology_fetch");
      suite.expect(hooks.lastAddMachinesRequest.adoptedMachines.size() == 0, "create_remote_managed_no_adopted");
      suite.expect(hooks.upsertMachineSchemasCalls == 1, "create_remote_managed_upserts_machine_schemas");
      suite.expect(hooks.lastMachineSchemaPatches.size() == 2, "create_remote_managed_machine_schema_patch_count");
      suite.expect(hooks.lastMachineSchemaPatches[0].schema == "aws-brain-vm"_ctv, "create_remote_managed_first_patch_schema");
      suite.expect(hooks.lastMachineSchemaPatches[0].hasBudget && hooks.lastMachineSchemaPatches[0].budget == 3, "create_remote_managed_first_patch_budget");
      suite.expect(hooks.lastMachineSchemaPatches[1].schema == "aws-worker-vm"_ctv, "create_remote_managed_second_patch_schema");
      suite.expect(hooks.lastMachineSchemaPatches[1].hasBudget && hooks.lastMachineSchemaPatches[1].budget == 2, "create_remote_managed_second_patch_budget");
      suite.expect(cluster.topology == hooks.finalTopology, "create_remote_managed_topology_persisted");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::createSeed,
         ClusterCreateCall::remoteBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::upsertMachineSchemas
      }), "create_remote_managed_call_sequence");
   }

   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::azure;
      credential.mode = MothershipProviderCredentialMode::azureCli;
      credential.scope = "subscriptions/sub-prod/resourceGroups/rg-prod/locations/northcentralus"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-azure-managed"_ctv;
      cluster.clusterUUID = 0x1004A;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::azure;
      cluster.providerScope = credential.scope;
      cluster.providerCredentialName = "azure-prod"_ctv;
      cluster.azure.managedIdentityResourceID = "/subscriptions/sub-prod/resourceGroups/rg-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/prodigy-managed"_ctv;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("azure-brain-vm"_ctv, MachineConfig::MachineKind::vm, 2, 8192, 131072));
      cluster.nBrains = 3;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "azure-brain-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "Standard_D2als_v6"_ctv,
         .budget = 3
      });

      FakeClusterCreateHooks hooks;
      hooks.prepareProviderBootstrapArtifactsCalls = 0;
      hooks.createdSeedMachine = makeTopologyMachine(
         "azure-brain-vm"_ctv,
         "10.4.0.10"_ctv,
         true,
         ClusterMachineSource::created,
         ClusterMachineBacking::cloud,
         "Standard_D2als_v6"_ctv);
      hooks.fetchedTopology.machines.push_back(hooks.createdSeedMachine);
      hooks.finalTopology = hooks.fetchedTopology;

      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, nullptr, &failure);
      suite.expect(ok, "create_remote_azure_managed_flow_ok");
      suite.expect(hooks.createSeedCalls == 1, "create_remote_azure_managed_creates_seed");
      suite.expect(hooks.remoteBootstrapCalls == 1, "create_remote_azure_managed_bootstraps_created_seed");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.kind == ProdigyEnvironmentKind::azure, "create_remote_azure_managed_bootstrap_runtime_env_kind");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_azure_managed_bootstrap_runtime_env_secret_withheld");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.azure.bootstrapAccessTokenRefreshCommand.size() == 0, "create_remote_azure_managed_bootstrap_runtime_env_refresh_command_withheld");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.azure.managedIdentityResourceID.equals(cluster.azure.managedIdentityResourceID), "create_remote_azure_managed_bootstrap_runtime_env_identity");
      suite.expect(hooks.configureConfigs.size() == 1, "create_remote_azure_managed_configure_count");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_azure_managed_runtime_env_secret_withheld");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand.size() == 0, "create_remote_azure_managed_runtime_env_refresh_command_withheld");
      suite.expect(hooks.lastConfig.runtimeEnvironment.azure.managedIdentityResourceID.equals(cluster.azure.managedIdentityResourceID), "create_remote_azure_managed_runtime_env_identity");
      suite.expect(hooks.upsertMachineSchemasCalls == 1, "create_remote_azure_managed_upserts_machine_schemas");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::prepareProviderBootstrapArtifacts,
         ClusterCreateCall::createSeed,
         ClusterCreateCall::remoteBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::upsertMachineSchemas
      }), "create_remote_azure_managed_call_sequence");
   }

   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::vultr;
      credential.material = "vultr-secret"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-vultr-bgp"_ctv;
      cluster.clusterUUID = 0x1004'1004;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::vultr;
      cluster.providerScope = "ewr"_ctv;
      cluster.providerCredentialName = "vultr-prod"_ctv;
      cluster.propagateProviderCredentialToProdigy = true;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("vultr-brain-vm"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));
      appendClusterMachineConfig(cluster, makeMachineConfig("vultr-worker-vm"_ctv, MachineConfig::MachineKind::vm, 4, 8192, 65536));
      cluster.nBrains = 3;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      cluster.bgp.specified = true;
      cluster.bgp.config.enabled = true;
      cluster.bgp.config.ourBGPID = inet_addr("10.9.0.21");
      cluster.bgp.config.nextHop4 = IPAddress("10.9.0.1", false);
      cluster.bgp.config.nextHop6 = IPAddress("2001:db8:9::1", true);
      cluster.bgp.config.peers.push_back(makeBGPConfigPeer("169.254.1.1"_ctv, "10.9.0.21"_ctv, 64512, "vultr-md5-v4"_ctv, 2));
      cluster.bgp.config.peers.push_back(makeBGPConfigPeer("2001:19f0:ffff::1"_ctv, "2001:db8:9::21"_ctv, 64512, "vultr-md5-v6"_ctv, 2));
      cluster.machines.push_back(makeAdoptedMachine("vultr-brain-vm"_ctv, "10.9.0.10"_ctv, true, ClusterMachineBacking::cloud));
      cluster.machines.push_back(makeAdoptedMachine("vultr-brain-vm"_ctv, "10.9.0.11"_ctv, true, ClusterMachineBacking::cloud));
      cluster.machines.push_back(makeAdoptedMachine("vultr-brain-vm"_ctv, "10.9.0.12"_ctv, true, ClusterMachineBacking::cloud));
      cluster.machines.push_back(makeAdoptedMachine("vultr-worker-vm"_ctv, "10.9.0.13"_ctv, false, ClusterMachineBacking::cloud));

      FakeClusterCreateHooks hooks;
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("vultr-brain-vm"_ctv, "10.9.0.10"_ctv, true, ClusterMachineSource::adopted, ClusterMachineBacking::cloud));
      hooks.finalTopology = hooks.fetchedTopology;
      hooks.finalTopology.machines.push_back(makeTopologyMachine("vultr-brain-vm"_ctv, "10.9.0.11"_ctv, true, ClusterMachineSource::adopted, ClusterMachineBacking::cloud));
      hooks.finalTopology.machines.push_back(makeTopologyMachine("vultr-brain-vm"_ctv, "10.9.0.12"_ctv, true, ClusterMachineSource::adopted, ClusterMachineBacking::cloud));
      hooks.finalTopology.machines.push_back(makeTopologyMachine("vultr-worker-vm"_ctv, "10.9.0.13"_ctv, false, ClusterMachineSource::adopted, ClusterMachineBacking::cloud));
      hooks.fetchedTopologySequence.push_back(hooks.fetchedTopology);
      hooks.fetchedTopologySequence.push_back(hooks.finalTopology);

      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, nullptr, &failure);
      suite.expect(ok, "create_remote_vultr_bgp_flow_ok");
      suite.expect(hooks.remoteBootstrapCalls == 1, "create_remote_vultr_bgp_bootstraps_seed");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.kind == ProdigyEnvironmentKind::vultr, "create_remote_vultr_bgp_bootstrap_runtime_env_kind");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.bgp.specified, "create_remote_vultr_bgp_bootstrap_runtime_env_bgp_specified");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.bgp.config.enabled, "create_remote_vultr_bgp_bootstrap_runtime_env_bgp_enabled");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.bgp.config.nextHop4.equals(IPAddress("10.9.0.1", false)), "create_remote_vultr_bgp_bootstrap_runtime_env_nextHop4");
      suite.expect(hooks.lastConfig.runtimeEnvironment.kind == ProdigyEnvironmentKind::vultr, "create_remote_vultr_bgp_runtime_env_kind");
      suite.expect(hooks.lastConfig.runtimeEnvironment.bgp.specified, "create_remote_vultr_bgp_runtime_env_bgp_specified");
      suite.expect(hooks.lastConfig.runtimeEnvironment.bgp.config.enabled, "create_remote_vultr_bgp_runtime_env_bgp_enabled");
      suite.expect(hooks.lastConfig.runtimeEnvironment.bgp.config.peers.size() == 2, "create_remote_vultr_bgp_runtime_env_peer_count");
      suite.expect(hooks.fetchTopologyCalls == 1, "create_remote_vultr_bgp_fetches_topology_once");
      suite.expect(cluster.topology == hooks.finalTopology, "create_remote_vultr_bgp_topology_persisted");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::remoteBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::fetchTopology,
         ClusterCreateCall::applyAddMachines,
         ClusterCreateCall::configure
      }), "create_remote_vultr_bgp_call_sequence");
   }

   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::azure;
      credential.material = "azure-secret"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-mixed-adopted-seed"_ctv;
      cluster.clusterUUID = 0x1005;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::azure;
      cluster.providerScope = "subscriptions/sub-prod/resourceGroups/rg-prod/locations/westus"_ctv;
      cluster.providerCredentialName = "azure-prod"_ctv;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      cluster.azure.managedIdentityResourceID = "/subscriptions/sub-prod/resourceGroups/rg-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/prodigy-1005-azure-mi"_ctv;
      appendClusterMachineConfig(cluster, makeMachineConfig("azure-brain-vm"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));
      appendClusterMachineConfig(cluster, makeMachineConfig("azure-worker-vm"_ctv, MachineConfig::MachineKind::vm, 4, 8192, 65536));
      cluster.nBrains = 3;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      cluster.machines.push_back(makeAdoptedMachine("azure-brain-vm"_ctv, "10.3.0.10"_ctv, true, ClusterMachineBacking::cloud));
      cluster.machines.push_back(makeAdoptedMachine("azure-worker-vm"_ctv, "10.3.0.11"_ctv, false, ClusterMachineBacking::cloud));
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "azure-brain-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "Standard_D4s_v5"_ctv,
         .budget = 3
      });
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "azure-worker-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "Standard_D2s_v5"_ctv,
         .budget = 1
      });

      FakeClusterCreateHooks hooks;
      hooks.fetchedTopology.machines.push_back(makeTopologyMachine("azure-brain-vm"_ctv, "10.3.0.10"_ctv, true, ClusterMachineSource::adopted, ClusterMachineBacking::cloud));
      hooks.finalTopology = hooks.fetchedTopology;
      hooks.fetchedTopologySequence.push_back(hooks.fetchedTopology);
      hooks.fetchedTopologySequence.push_back(hooks.finalTopology);

      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, nullptr, &failure);
      suite.expect(ok, "create_remote_hybrid_adopted_seed_flow_ok");
      suite.expect(hooks.prepareProviderBootstrapArtifactsCalls == 1, "create_remote_hybrid_adopted_seed_prepares_identity");
      suite.expect(hooks.createSeedCalls == 0, "create_remote_hybrid_adopted_seed_no_provider_seed");
      suite.expect(hooks.remoteBootstrapCalls == 1, "create_remote_hybrid_adopted_seed_bootstraps_adopted_seed");
      suite.expect(hooks.lastRemoteSeedClusterUUID == cluster.clusterUUID, "create_remote_hybrid_adopted_seed_bootstrap_cluster_uuid");
      suite.expect(hooks.lastRemoteSeedMachine.addresses.privateAddresses.size() == 1 && hooks.lastRemoteSeedMachine.addresses.privateAddresses[0].address == "10.3.0.10"_ctv, "create_remote_hybrid_adopted_seed_first_brain");
      suite.expect(hooks.lastRemoteBootstrapTopology.machines.size() == 1, "create_remote_hybrid_adopted_seed_topology_size");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.kind == ProdigyEnvironmentKind::azure, "create_remote_hybrid_adopted_seed_bootstrap_runtime_env_kind");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_hybrid_adopted_seed_bootstrap_runtime_env_secret_withheld");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.azure.managedIdentityResourceID.equals(cluster.azure.managedIdentityResourceID), "create_remote_hybrid_adopted_seed_bootstrap_runtime_env_identity");
      suite.expect(hooks.configureConfigs.size() == 1, "create_remote_hybrid_adopted_seed_configure_count");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_hybrid_adopted_seed_initial_runtime_env_secret_withheld");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.azure.managedIdentityResourceID.equals(cluster.azure.managedIdentityResourceID), "create_remote_hybrid_adopted_seed_final_runtime_env_identity");
      suite.expect(hooks.lastConfig.clusterUUID == cluster.clusterUUID, "create_remote_hybrid_adopted_seed_config_cluster_uuid");
      suite.expect(hooks.addMachinesCalls == 1, "create_remote_hybrid_adopted_seed_addmachines_called");
      suite.expect(hooks.lastAddMachinesRequest.adoptedMachines.size() == 1, "create_remote_hybrid_adopted_seed_adds_worker");
      suite.expect(hooks.upsertMachineSchemasCalls == 1, "create_remote_hybrid_adopted_seed_upserts_machine_schemas");
      suite.expect(hooks.lastMachineSchemaPatches.size() == 2, "create_remote_hybrid_adopted_seed_patch_count");
      suite.expect(cluster.topology == hooks.finalTopology, "create_remote_hybrid_adopted_seed_topology_persisted");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::prepareProviderBootstrapArtifacts,
         ClusterCreateCall::remoteBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::fetchTopology,
         ClusterCreateCall::applyAddMachines,
         ClusterCreateCall::upsertMachineSchemas
      }), "create_remote_hybrid_adopted_seed_call_sequence");
   }

   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::vultr;
      credential.material = "vultr-secret"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-mixed-created-seed"_ctv;
      cluster.clusterUUID = 0x1006;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::vultr;
      cluster.providerScope = "ewr"_ctv;
      cluster.providerCredentialName = "vultr-prod"_ctv;
      cluster.propagateProviderCredentialToProdigy = true;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("vultr-brain"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));
      appendClusterMachineConfig(cluster, makeMachineConfig("vultr-worker"_ctv, MachineConfig::MachineKind::vm, 4, 8192, 65536));
      cluster.nBrains = 3;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      cluster.machines.push_back(makeAdoptedMachine("vultr-worker"_ctv, "10.4.0.11"_ctv, false));
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "vultr-brain"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "vc2-4c-8gb"_ctv,
         .budget = 3
      });
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "vultr-worker"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "vc2-2c-4gb"_ctv,
         .budget = 2
      });

      FakeClusterCreateHooks hooks;
      hooks.createdSeedMachine = makeTopologyMachine(
         "vultr-brain"_ctv,
         "10.4.0.10"_ctv,
         true,
         ClusterMachineSource::created,
         ClusterMachineBacking::cloud,
         "vc2-4c-8gb"_ctv);
      hooks.fetchedTopology.machines.push_back(hooks.createdSeedMachine);
      hooks.finalTopology = hooks.fetchedTopology;
      hooks.fetchedTopologySequence.push_back(hooks.fetchedTopology);
      hooks.fetchedTopologySequence.push_back(hooks.finalTopology);

      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, nullptr, &failure);
      suite.expect(ok, "create_remote_hybrid_created_seed_flow_ok");
      suite.expect(hooks.createSeedCalls == 1, "create_remote_hybrid_created_seed_creates_seed");
      suite.expect(hooks.remoteBootstrapCalls == 1, "create_remote_hybrid_created_seed_bootstraps_created_seed");
      suite.expect(hooks.lastRemoteSeedClusterUUID == cluster.clusterUUID, "create_remote_hybrid_created_seed_bootstrap_cluster_uuid");
      suite.expect(hooks.lastRemoteBootstrapTopology.machines.size() == 1, "create_remote_hybrid_created_seed_topology_size");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.kind == ProdigyEnvironmentKind::vultr, "create_remote_hybrid_created_seed_bootstrap_runtime_env_kind");
      suite.expect(hooks.lastRemoteRuntimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_hybrid_created_seed_bootstrap_runtime_env_secret_withheld");
      suite.expect(hooks.configureConfigs.size() == 2, "create_remote_hybrid_created_seed_configure_count");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_hybrid_created_seed_initial_runtime_env_secret_withheld");
      suite.expect(hooks.configureConfigs[1].runtimeEnvironment.providerCredentialMaterial.equals("vultr-secret"_ctv), "create_remote_hybrid_created_seed_final_runtime_env_secret");
      suite.expect(hooks.lastConfig.clusterUUID == cluster.clusterUUID, "create_remote_hybrid_created_seed_config_cluster_uuid");
      suite.expect(hooks.addMachinesCalls == 1, "create_remote_hybrid_created_seed_addmachines_called");
      suite.expect(hooks.fetchTopologyCalls == 1, "create_remote_hybrid_created_seed_fetches_topology_once");
      suite.expect(hooks.lastAddMachinesRequest.adoptedMachines.size() == 1, "create_remote_hybrid_created_seed_adds_adopted_worker");
      suite.expect(hooks.upsertMachineSchemasCalls == 1, "create_remote_hybrid_created_seed_upserts_machine_schemas");
      suite.expect(hooks.lastMachineSchemaPatches.size() == 2, "create_remote_hybrid_created_seed_patch_count");
      suite.expect(cluster.topology == hooks.finalTopology, "create_remote_hybrid_created_seed_topology_persisted");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::createSeed,
         ClusterCreateCall::remoteBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::fetchTopology,
         ClusterCreateCall::applyAddMachines,
         ClusterCreateCall::configure,
         ClusterCreateCall::upsertMachineSchemas
      }), "create_remote_hybrid_created_seed_call_sequence");
   }

   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::aws;
      credential.material = "aws-secret"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-created-bootstrap-failure"_ctv;
      cluster.clusterUUID = 0x1101;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::aws;
      cluster.providerScope = "acct/us-east-1"_ctv;
      cluster.providerCredentialName = "aws-prod"_ctv;
      cluster.aws.instanceProfileName = "prodigy-controller-profile"_ctv;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-brain-vm"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));
      cluster.nBrains = 3;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "aws-brain-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "c7i.large"_ctv,
         .budget = 3
      });

      FakeClusterCreateHooks hooks;
      hooks.createdSeedMachine = makeTopologyMachine(
         "aws-brain-vm"_ctv,
         "10.5.0.10"_ctv,
         true,
         ClusterMachineSource::created,
         ClusterMachineBacking::cloud,
         "c7i.large"_ctv);
      hooks.failBootstrapRemoteSeed = true;

      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, nullptr, &failure);
      suite.expect(!ok, "create_remote_managed_bootstrap_failure_rejected");
      suite.expect(failure.equals("bootstrap remote seed failed"_ctv), "create_remote_managed_bootstrap_failure_reason");
      suite.expect(hooks.lastRemoteSeedClusterUUID == cluster.clusterUUID, "create_remote_managed_bootstrap_failure_cluster_uuid");
      suite.expect(hooks.destroyCreatedSeedCalls == 1, "create_remote_managed_bootstrap_failure_destroys_seed");
      suite.expect(hooks.lastDestroyedSeedMachine == hooks.createdSeedMachine, "create_remote_managed_bootstrap_failure_destroyed_expected_seed");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::createSeed,
         ClusterCreateCall::remoteBootstrap,
         ClusterCreateCall::destroyCreatedSeed
      }), "create_remote_managed_bootstrap_failure_call_sequence");
   }

   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::aws;
      credential.material = "aws-secret"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-created-configure-failure"_ctv;
      cluster.clusterUUID = 0x1102;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::aws;
      cluster.providerScope = "acct/us-east-1"_ctv;
      cluster.providerCredentialName = "aws-prod"_ctv;
      cluster.aws.instanceProfileName = "prodigy-controller-profile"_ctv;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-brain-vm"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));
      cluster.nBrains = 3;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "aws-brain-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "c7i.large"_ctv,
         .budget = 3
      });

      FakeClusterCreateHooks hooks;
      hooks.createdSeedMachine = makeTopologyMachine(
         "aws-brain-vm"_ctv,
         "10.5.0.11"_ctv,
         true,
         ClusterMachineSource::created,
         ClusterMachineBacking::cloud,
         "c7i.large"_ctv);
      hooks.failConfigureSeedCluster = true;

      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, nullptr, &failure);
      suite.expect(!ok, "create_remote_managed_configure_failure_rejected");
      suite.expect(failure.equals("configure seed failed"_ctv), "create_remote_managed_configure_failure_reason");
      suite.expect(hooks.configureCalls == 1, "create_remote_managed_configure_failure_configure_count");
      suite.expect(hooks.configureConfigs.size() == 1, "create_remote_managed_configure_failure_records_first_config");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_managed_configure_failure_initial_runtime_env_secret_withheld");
      suite.expect(hooks.lastConfig.clusterUUID == cluster.clusterUUID, "create_remote_managed_configure_failure_cluster_uuid");
      suite.expect(hooks.destroyCreatedSeedCalls == 1, "create_remote_managed_configure_failure_destroys_seed");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::createSeed,
         ClusterCreateCall::remoteBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::destroyCreatedSeed
      }), "create_remote_managed_configure_failure_call_sequence");
   }

   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::aws;
      credential.material = "aws-secret"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-hybrid-fetch-failure"_ctv;
      cluster.clusterUUID = 0x1103;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::aws;
      cluster.providerScope = "acct/us-east-1"_ctv;
      cluster.providerCredentialName = "aws-prod"_ctv;
      cluster.aws.instanceProfileName = "prodigy-controller-profile"_ctv;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-brain-vm"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-worker-vm"_ctv, MachineConfig::MachineKind::vm, 8, 32768, 262144));
      cluster.nBrains = 3;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      cluster.machines.push_back(makeAdoptedMachine("aws-worker-vm"_ctv, "10.5.0.20"_ctv, false, ClusterMachineBacking::cloud));
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "aws-brain-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "c7i.large"_ctv,
         .budget = 3
      });

      FakeClusterCreateHooks hooks;
      hooks.createdSeedMachine = makeTopologyMachine(
         "aws-brain-vm"_ctv,
         "10.5.0.12"_ctv,
         true,
         ClusterMachineSource::created,
         ClusterMachineBacking::cloud,
         "c7i.large"_ctv);
      hooks.failFetchSeedTopology = true;

      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, nullptr, &failure);
      suite.expect(!ok, "create_remote_hybrid_fetch_failure_rejected");
      suite.expect(failure.equals("fetch seed topology failed"_ctv), "create_remote_hybrid_fetch_failure_reason");
      suite.expect(hooks.configureCalls == 1, "create_remote_hybrid_fetch_failure_no_second_configure");
      suite.expect(hooks.configureConfigs.size() == 1, "create_remote_hybrid_fetch_failure_configure_count");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_hybrid_fetch_failure_initial_runtime_env_secret_withheld");
      suite.expect(hooks.lastConfig.clusterUUID == cluster.clusterUUID, "create_remote_hybrid_fetch_failure_cluster_uuid");
      suite.expect(hooks.destroyCreatedSeedCalls == 1, "create_remote_hybrid_fetch_failure_destroys_seed");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::createSeed,
         ClusterCreateCall::remoteBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::fetchTopology,
         ClusterCreateCall::destroyCreatedSeed
      }), "create_remote_hybrid_fetch_failure_call_sequence");
   }

   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::aws;
      credential.material = "aws-secret"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-created-apply-failure"_ctv;
      cluster.clusterUUID = 0x1104;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::aws;
      cluster.providerScope = "acct/us-east-1"_ctv;
      cluster.providerCredentialName = "aws-prod"_ctv;
      cluster.aws.instanceProfileName = "prodigy-controller-profile"_ctv;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-brain-vm"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-worker-vm"_ctv, MachineConfig::MachineKind::vm, 8, 32768, 262144));
      cluster.nBrains = 3;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "aws-brain-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "c7i.large"_ctv,
         .budget = 3
      });
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "aws-worker-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::spot,
         .providerMachineType = "c7i.xlarge"_ctv,
         .budget = 1
      });

      FakeClusterCreateHooks hooks;
      hooks.createdSeedMachine = makeTopologyMachine(
         "aws-brain-vm"_ctv,
         "10.5.0.13"_ctv,
         true,
         ClusterMachineSource::created,
         ClusterMachineBacking::cloud,
         "c7i.large"_ctv);
      hooks.fetchedTopology.machines.push_back(hooks.createdSeedMachine);
      hooks.failUpsertMachineSchemas = true;

      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, nullptr, &failure);
      suite.expect(!ok, "create_remote_managed_upsert_failure_rejected");
      suite.expect(failure.equals("upsert machine schemas failed"_ctv), "create_remote_managed_upsert_failure_reason");
      suite.expect(hooks.configureCalls == 1, "create_remote_managed_upsert_failure_configure_count");
      suite.expect(hooks.configureConfigs.size() == 1, "create_remote_managed_upsert_failure_records_one_config");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.providerCredentialMaterial.size() == 0, "create_remote_managed_upsert_failure_initial_runtime_env_secret_withheld");
      suite.expect(hooks.configureConfigs[0].runtimeEnvironment.aws.instanceProfileName.equals(cluster.aws.instanceProfileName), "create_remote_managed_upsert_failure_runtime_env_instance_profile_name");
      suite.expect(hooks.lastConfig.clusterUUID == cluster.clusterUUID, "create_remote_managed_upsert_failure_cluster_uuid");
      suite.expect(hooks.addMachinesCalls == 0, "create_remote_managed_upsert_failure_no_manual_addmachines");
      suite.expect(hooks.fetchTopologyCalls == 0, "create_remote_managed_upsert_failure_skips_seed_topology_fetch");
      suite.expect(hooks.upsertMachineSchemasCalls == 1, "create_remote_managed_upsert_failure_upsert_called");
      suite.expect(hooks.destroyCreatedSeedCalls == 1, "create_remote_managed_upsert_failure_destroys_seed");
      suite.expect(equalCallSequence(hooks.callSequence, {
         ClusterCreateCall::createSeed,
         ClusterCreateCall::remoteBootstrap,
         ClusterCreateCall::configure,
         ClusterCreateCall::upsertMachineSchemas,
         ClusterCreateCall::destroyCreatedSeed
      }), "create_remote_managed_upsert_failure_call_sequence");
   }

#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
   {
      MothershipProviderCredential credential = {};
      credential.provider = MothershipClusterProvider::aws;
      credential.material = "aws-secret"_ctv;

      MothershipProdigyCluster cluster = {};
      cluster.name = "remote-attribution"_ctv;
      cluster.clusterUUID = 0x1105;
      cluster.deploymentMode = MothershipClusterDeploymentMode::remote;
      cluster.provider = MothershipClusterProvider::aws;
      cluster.providerScope = "acct/us-east-1"_ctv;
      cluster.providerCredentialName = "aws-prod"_ctv;
      cluster.aws.instanceProfileName = "prodigy-controller-profile"_ctv;
      cluster.controls.push_back(makeUnixControl("/run/prodigy/control.sock"_ctv));
      cluster.nBrains = 3;
      cluster.bootstrapSshUser = "root"_ctv;
      cluster.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
      cluster.remoteProdigyPath = "/root/prodigy"_ctv;
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-brain-vm"_ctv, MachineConfig::MachineKind::vm, 4, 16384, 131072));
      appendClusterMachineConfig(cluster, makeMachineConfig("aws-worker-vm"_ctv, MachineConfig::MachineKind::vm, 8, 32768, 262144));
      cluster.machines.push_back(makeAdoptedMachine("aws-worker-vm"_ctv, "10.5.0.30"_ctv, false, ClusterMachineBacking::cloud));
      appendMachineSchema(cluster, MothershipProdigyClusterMachineSchema{
         .schema = "aws-brain-vm"_ctv,
         .kind = MachineConfig::MachineKind::vm,
         .lifetime = MachineLifetime::ondemand,
         .providerMachineType = "c7i.large"_ctv,
         .budget = 3
      });

      FakeClusterCreateHooks hooks;
      hooks.createdSeedMachine = makeTopologyMachine(
         "aws-brain-vm"_ctv,
         "10.5.0.14"_ctv,
         true,
         ClusterMachineSource::created,
         ClusterMachineBacking::cloud,
         "c7i.large"_ctv);
      hooks.fetchedTopology.machines.push_back(hooks.createdSeedMachine);
      hooks.finalTopology.machines.push_back(hooks.createdSeedMachine);
      hooks.finalTopology.machines.push_back(makeAdoptedMachine("aws-worker-vm"_ctv, "10.5.0.30"_ctv, false, ClusterMachineBacking::cloud));
      hooks.createSeedTiming.providerWaitNs = 11;
      hooks.createSeedTiming.runtimeOwnedNs = 7;
      hooks.remoteBootstrapTiming.providerWaitNs = 5;
      hooks.remoteBootstrapTiming.runtimeOwnedNs = 13;
      hooks.addMachinesTiming.providerWaitNs = 17;
      hooks.addMachinesTiming.runtimeOwnedNs = 19;
      hooks.upsertMachineSchemasTiming.providerWaitNs = 23;
      hooks.upsertMachineSchemasTiming.runtimeOwnedNs = 29;

      MothershipClusterCreateTimingSummary timingSummary = {};
      String failure;
      bool ok = mothershipStandUpCluster(cluster, &credential, hooks, &timingSummary, &failure);
      suite.expect(ok, "create_remote_attribution_ok");
      suite.expect(failure.size() == 0, "create_remote_attribution_no_failure");
      suite.expect(timingSummary.prepareProviderBootstrapArtifacts == ProdigyTimingAttribution{}, "create_remote_attribution_no_prepare_stage");
      suite.expect(timingSummary.createSeedMachine == hooks.createSeedTiming, "create_remote_attribution_records_seed_stage");
      suite.expect(timingSummary.bootstrapRemoteSeed == hooks.remoteBootstrapTiming, "create_remote_attribution_records_remote_bootstrap_stage");
      suite.expect(timingSummary.applyAddMachines == hooks.addMachinesTiming, "create_remote_attribution_records_addmachines_stage");
      suite.expect(timingSummary.upsertMachineSchemas == hooks.upsertMachineSchemasTiming, "create_remote_attribution_records_upsert_stage");
      suite.expect(timingSummary.configureSeedCluster.providerWaitNs == 0, "create_remote_attribution_configure_has_no_provider_wait");
      suite.expect(timingSummary.fetchSeedTopology.providerWaitNs == 0, "create_remote_attribution_fetch_has_no_provider_wait");
      suite.expect(
         timingSummary.total.providerWaitNs
            == hooks.createSeedTiming.providerWaitNs
               + hooks.remoteBootstrapTiming.providerWaitNs
               + hooks.addMachinesTiming.providerWaitNs
               + hooks.upsertMachineSchemasTiming.providerWaitNs,
         "create_remote_attribution_total_provider_wait");
      suite.expect(
         timingSummary.total.runtimeOwnedNs
            >= hooks.createSeedTiming.runtimeOwnedNs
               + hooks.remoteBootstrapTiming.runtimeOwnedNs
               + hooks.addMachinesTiming.runtimeOwnedNs
               + hooks.upsertMachineSchemasTiming.runtimeOwnedNs,
         "create_remote_attribution_total_runtime_owned");
   }
#endif

   {
      ClusterTopology topology = {};
      topology.machines.push_back(makeTopologyMachine("created-a"_ctv, "10.6.0.10"_ctv, true, ClusterMachineSource::created, ClusterMachineBacking::cloud));
      topology.machines.back().cloud.cloudID = "i-created-a"_ctv;
      topology.machines.push_back(makeTopologyMachine("created-a-dup"_ctv, "10.6.0.11"_ctv, false, ClusterMachineSource::created, ClusterMachineBacking::cloud));
      topology.machines.back().cloud.cloudID = "i-created-a"_ctv;
      topology.machines.push_back(makeTopologyMachine("adopted-cloud"_ctv, "10.6.0.12"_ctv, true, ClusterMachineSource::adopted, ClusterMachineBacking::cloud));
      topology.machines.back().cloud.cloudID = "i-adopted"_ctv;
      topology.machines.push_back(makeTopologyMachine("owned-created"_ctv, "10.6.0.13"_ctv, false, ClusterMachineSource::created, ClusterMachineBacking::owned));

      FakeProvisionBrainIaaS iaas;
      String failure;
      failure.assign("stale"_ctv);
      mothershipDestroyCreatedClusterMachines(iaas, topology);
      suite.expect(iaas.destroyCalls == 1, "destroy_created_cluster_machines_only_destroys_unique_created_cloud");
      suite.expect(iaas.destroyedCloudIDs.size() == 1, "destroy_created_cluster_machines_tracks_one_id");
      suite.expect(iaas.destroyedCloudIDs[0].equals("i-created-a"_ctv), "destroy_created_cluster_machines_destroys_expected_cloud_id");
   }

   if (originalPath.empty())
   {
      suite.expect(::unsetenv("PATH") == 0, "restore_original_path_empty");
   }
   else
   {
      suite.expect(::setenv("PATH", originalPath.c_str(), 1) == 0, "restore_original_path");
   }

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
