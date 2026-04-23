#include <prodigy/prodigy.h>
#include <services/debug.h>
#include <prodigy/brain/brain.h>
#include <prodigy/containerstore.h>
#include <prodigy/mothership/mothership.deployment.plan.helpers.h>
#include <prodigy/neuron/containers.h>

#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <string_view>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <type_traits>
#include <utility>
#include <unistd.h>
#include <simdjson.h>

class TestBrain final : public BrainBase
{
public:
   Mesh meshStorage = {};
   uint32_t progressCount = 0;
   uint32_t failureCount = 0;
   uint32_t finCount = 0;
   String lastProgressMessage = {};
   String lastFailureMessage = {};

   TestBrain()
   {
      this->mesh = &meshStorage;
   }

   void respinApplication(ApplicationDeployment *deployment) override
   {
      (void)deployment;
   }

   void pushSpinApplicationProgressToMothership(ApplicationDeployment *deployment, const String& message) override
   {
      (void)deployment;
      progressCount += 1;
      lastProgressMessage = message;
   }

   void spinApplicationFailed(ApplicationDeployment *deployment, const String& message) override
   {
      (void)deployment;
      failureCount += 1;
      lastFailureMessage = message;
   }

   void spinApplicationFin(ApplicationDeployment *deployment) override
   {
      (void)deployment;
      finCount += 1;
   }

   void requestMachines(MachineTicket *ticket, ApplicationDeployment *deployment, ApplicationLifetime lifetime, uint32_t nMore) override
   {
      (void)ticket;
      (void)deployment;
      (void)lifetime;
      (void)nMore;
   }
};

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
         dprintf(STDERR_FILENO, "FAIL: %s\n", name);
         failed += 1;
      }
   }
};

class PairingCountingContainerView : public ContainerView
{
public:
   uint32_t advertisementActivations = 0;
   uint32_t subscriptionActivations = 0;

   void advertisementPairing(uint128_t, uint128_t, uint64_t, uint16_t, bool activate) override
   {
      if (activate)
      {
         advertisementActivations += 1;
      }
   }

   void subscriptionPairing(uint128_t, uint128_t, uint64_t, uint16_t, uint16_t, bool activate) override
   {
      if (activate)
      {
         subscriptionActivations += 1;
      }
   }
};

class ScopedFreshRing final
{
public:
   bool hadRing = false;

   ScopedFreshRing()
   {
      hadRing = (Ring::getRingFD() > 0);
      if (hadRing)
      {
         Ring::shutdownForExec();
      }

      Ring::createRing(8, 8, 32, 32, -1, -1, 0);
   }

   ~ScopedFreshRing()
   {
      Ring::shutdownForExec();
      if (hadRing)
      {
         Ring::createRing(8, 8, 32, 32, -1, -1, 0);
      }
   }
};

class ScopedSocketPair final
{
public:
   int left = -1;
   int right = -1;

   ~ScopedSocketPair()
   {
      if (left >= 0)
      {
         close(left);
      }

      if (right >= 0)
      {
         close(right);
      }
   }

   bool create(TestSuite& suite, const char *name)
   {
      int sockets[2] = {-1, -1};
      bool created = (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets) == 0);
      suite.expect(created, name);
      if (created == false)
      {
         if (sockets[0] >= 0)
         {
            close(sockets[0]);
         }

         if (sockets[1] >= 0)
         {
            close(sockets[1]);
         }

         return false;
      }

      left = sockets[0];
      right = sockets[1];
      return true;
   }

   int adoptLeftIntoFixedFileSlot(void)
   {
      if (left < 0)
      {
         return -1;
      }

      int fslot = Ring::adoptProcessFDIntoFixedFileSlot(left);
      if (fslot >= 0)
      {
         left = -1;
      }

      return fslot;
   }
};

static std::filesystem::path filesystemPathFromString(const String& value)
{
   return std::filesystem::path(std::string(reinterpret_cast<const char *>(value.data()), size_t(value.size())));
}

static String stringFromFilesystemPath(const std::filesystem::path& value)
{
   std::string native = value.string();
   String output = {};
   output.assign(native.data(), native.size());
   return output;
}

static bool stringContains(const String& haystack, const char *needle)
{
   std::string_view haystackView(reinterpret_cast<const char *>(haystack.data()), size_t(haystack.size()));
   return haystackView.find(needle) != std::string_view::npos;
}

static uid_t fixtureWritableUserID(void)
{
   if (geteuid() == 0)
   {
      return 65534;
   }

   return geteuid();
}

static gid_t fixtureWritableGroupID(void)
{
   if (geteuid() == 0)
   {
      return 65534;
   }

   return getegid();
}

class TemporaryDirectory
{
public:
   String path = {};

   bool create(void)
   {
      char scratch[] = "/tmp/prodigy-deployments-unit-XXXXXX";
      char *created = ::mkdtemp(scratch);
      if (created == nullptr)
      {
         return false;
      }

      path.assign(created);
      return true;
   }

   ~TemporaryDirectory()
   {
      if (path.size() == 0)
      {
         return;
      }

      std::error_code ignored;
      std::filesystem::remove_all(filesystemPathFromString(path), ignored);
   }
};

static bool writeLaunchMetadataFixture(const String& artifactRoot, const char *metadataJSON)
{
   String metadataDir = {};
   metadataDir.assign(artifactRoot);
   metadataDir.append("/.prodigy-private"_ctv);

   std::error_code createError;
   std::filesystem::create_directories(filesystemPathFromString(metadataDir), createError);
   if (createError)
   {
      return false;
   }

   String metadataPath = {};
   metadataPath.assign(metadataDir);
   metadataPath.append("/launch.metadata"_ctv);

   String payload = {};
   payload.assign(metadataJSON);
   return Filesystem::openWriteAtClose(-1, metadataPath, payload) >= 0;
}

static bool writeFileFixture(const std::filesystem::path& path, const char *payloadText)
{
   std::error_code createError;
   std::filesystem::create_directories(path.parent_path(), createError);
   if (createError)
   {
      return false;
   }

   String targetPath = stringFromFilesystemPath(path);
   String payload = {};
   payload.assign(payloadText);
   return Filesystem::openWriteAtClose(-1, targetPath, payload) >= 0;
}

static bool writeFileFixture(const std::filesystem::path& path, const String& payload)
{
   std::error_code createError;
   std::filesystem::create_directories(path.parent_path(), createError);
   if (createError)
   {
      return false;
   }

   String targetPath = stringFromFilesystemPath(path);
   return Filesystem::openWriteAtClose(-1, targetPath, payload) >= 0;
}

static String repeatedString(uint64_t bytes, char fill)
{
   std::string text(size_t(bytes), fill);
   String output = {};
   output.assign(text.data(), text.size());
   return output;
}

static bool createDirectoryFixture(const std::filesystem::path& path)
{
   std::error_code error;
   std::filesystem::create_directories(path, error);
   return error.value() == 0;
}

static bool createSymlinkFixture(const std::filesystem::path& target, const std::filesystem::path& linkPath)
{
   std::error_code error;
   std::filesystem::create_symlink(target, linkPath, error);
   return error.value() == 0;
}

static bool makeFileExecutableFixture(const std::filesystem::path& path)
{
   std::error_code error;
   std::filesystem::permissions(
      path,
      std::filesystem::perms::owner_exec
         | std::filesystem::perms::group_exec
         | std::filesystem::perms::others_exec,
      std::filesystem::perm_options::add,
      error);
   return error.value() == 0;
}

static MachineCpuArchitecture alternateSupportedArchitecture(MachineCpuArchitecture architecture)
{
   if (architecture == MachineCpuArchitecture::x86_64)
   {
      return MachineCpuArchitecture::aarch64;
   }

   if (architecture == MachineCpuArchitecture::aarch64)
   {
      return MachineCpuArchitecture::x86_64;
   }

   return MachineCpuArchitecture::unknown;
}

static void seedCommonPlan(ApplicationDeployment& deployment, bool isStateful)
{
   deployment.plan.isStateful = isStateful;
   deployment.plan.config.applicationID = 999;
   deployment.plan.config.versionID = 1;
   deployment.plan.config.nLogicalCores = 2;
   deployment.plan.config.memoryMB = 512;
   deployment.plan.config.filesystemMB = 64;
   deployment.plan.config.storageMB = 64;
   deployment.plan.stateless.maxPerRackRatio = 1.0f;
   deployment.plan.stateless.maxPerMachineRatio = 1.0f;
}

static void markNeuronControlActive(Machine& machine, int fslot)
{
   machine.neuron.isFixedFile = true;
   machine.neuron.fslot = fslot;
   machine.neuron.connected = true;
}

static bool armNeuronControlStream(Machine& machine, ScopedSocketPair& sockets)
{
   machine.neuron.machine = &machine;
   machine.neuron.fd = -1;
   machine.neuron.isFixedFile = true;
   machine.neuron.fslot = sockets.adoptLeftIntoFixedFileSlot();
   machine.neuron.connected = (machine.neuron.fslot >= 0);
   return machine.neuron.connected;
}

template <typename Handler>
static void forEachMessageInBuffer(String& buffer, Handler&& handler)
{
   uint8_t *cursor = buffer.data();
   uint8_t *end = buffer.data() + buffer.size();

   while (cursor < end)
   {
      Message *message = reinterpret_cast<Message *>(cursor);
      if (message->size == 0)
      {
         break;
      }

      handler(message);
      cursor += message->size;
   }
}

int main(void)
{
   TestSuite suite;

   {
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);
      deployment.state = DeploymentState::running;

      PairingCountingContainerView advertiser;
      PairingCountingContainerView subscriber;
      const uint64_t service = (uint64_t(777) << 48) | uint64_t(1);
      const uint16_t port = 9191;

      advertiser.uuid = uint128_t(0x777001);
      advertiser.deploymentID = deployment.plan.config.deploymentID();
      advertiser.applicationID = deployment.plan.config.applicationID;
      advertiser.lifetime = ApplicationLifetime::base;
      advertiser.state = ContainerState::scheduled;
      advertiser.advertisements.emplace(service, Advertisement(service, ContainerState::scheduled, ContainerState::destroying, port));
      advertiser.advertisingOnPorts.insert(port);

      subscriber.uuid = uint128_t(0x777002);
      subscriber.deploymentID = deployment.plan.config.deploymentID();
      subscriber.applicationID = deployment.plan.config.applicationID;
      subscriber.lifetime = ApplicationLifetime::base;
      subscriber.state = ContainerState::scheduled;
      subscriber.subscriptions.emplace(service, Subscription(service, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));

      brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
      deployment.containers.insert(&advertiser);
      deployment.containers.insert(&subscriber);

      brain.mesh->advertise(service, &advertiser, port, false);
      brain.mesh->subscribe(service, &subscriber, SubscriptionNature::all, false);

      suite.expect(brain.mesh->pairingSecretFor(&advertiser, &subscriber, service) != 0, "container_healthy_replay_fixture_has_scheduled_pairing");
      suite.expect(advertiser.advertisementActivations == 1, "container_healthy_replay_fixture_schedules_advertiser_pairing_once");
      suite.expect(subscriber.subscriptionActivations == 0, "container_healthy_replay_fixture_does_not_notify_subscriber");
      advertiser.advertisementActivations = 0;
      subscriber.subscriptionActivations = 0;

      deployment.containerIsHealthy(&subscriber);
      suite.expect(advertiser.advertisementActivations == 0, "container_healthy_does_not_replay_scheduled_pairing_to_peer");
      suite.expect(subscriber.subscriptionActivations == 0, "container_healthy_does_not_replay_scheduled_pairing_to_self");

      deployment.containerIsHealthy(&subscriber);
      suite.expect(advertiser.advertisementActivations == 0, "container_duplicate_healthy_does_not_replay_pairing_to_peer");
      suite.expect(subscriber.subscriptionActivations == 0, "container_duplicate_healthy_does_not_replay_pairing_to_self");

      deployment.recoverAfterReboot();
      suite.expect(advertiser.advertisementActivations == 0, "deployment_recover_after_reboot_does_not_replay_pairing_to_peer");
      suite.expect(subscriber.subscriptionActivations == 0, "deployment_recover_after_reboot_does_not_replay_pairing_to_self");

      brain.deployments.erase(deployment.plan.config.deploymentID());
      thisBrain = savedBrain;
   }

   {
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);
      deployment.state = DeploymentState::running;

      PairingCountingContainerView advertiser;
      PairingCountingContainerView subscriber;
      const uint64_t service = (uint64_t(888) << 48) | uint64_t(2);
      const uint16_t port = 9292;

      advertiser.uuid = uint128_t(0x888001);
      advertiser.deploymentID = deployment.plan.config.deploymentID();
      advertiser.applicationID = deployment.plan.config.applicationID;
      advertiser.lifetime = ApplicationLifetime::base;
      advertiser.state = ContainerState::scheduled;
      advertiser.advertisements.emplace(service, Advertisement(service, ContainerState::scheduled, ContainerState::destroying, port));
      advertiser.advertisingOnPorts.insert(port);

      subscriber.uuid = uint128_t(0x888002);
      subscriber.deploymentID = deployment.plan.config.deploymentID();
      subscriber.applicationID = deployment.plan.config.applicationID;
      subscriber.lifetime = ApplicationLifetime::base;
      subscriber.state = ContainerState::scheduled;
      subscriber.subscriptions.emplace(service, Subscription(service, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));

      deployment.containers.insert(&advertiser);
      deployment.containers.insert(&subscriber);

      brain.mesh->advertise(service, &advertiser, port, false);
      brain.mesh->subscribe(service, &subscriber, SubscriptionNature::all, false);

      suite.expect(brain.mesh->pairingSecretFor(&advertiser, &subscriber, service) != 0, "container_runtime_ready_fixture_has_scheduled_pairing");
      advertiser.advertisementActivations = 0;
      subscriber.subscriptionActivations = 0;

      deployment.containerRuntimeReady(&subscriber);
      suite.expect(subscriber.runtimeReady, "container_runtime_ready_marks_first_peer_ready");
      suite.expect(advertiser.advertisementActivations == 0, "container_runtime_ready_waits_for_advertiser");
      suite.expect(subscriber.subscriptionActivations == 0, "container_runtime_ready_waits_for_peer_listener");

      deployment.containerRuntimeReady(&subscriber);
      suite.expect(advertiser.advertisementActivations == 0, "container_runtime_ready_ignores_duplicate_subscriber");
      suite.expect(subscriber.subscriptionActivations == 0, "container_runtime_ready_duplicate_subscriber_has_no_subscription");

      deployment.containerRuntimeReady(&advertiser);
      suite.expect(advertiser.runtimeReady, "container_runtime_ready_marks_second_peer_ready");
      suite.expect(advertiser.advertisementActivations == 1, "container_runtime_ready_replays_advertiser_pairing_after_both_ready");
      suite.expect(subscriber.subscriptionActivations == 1, "container_runtime_ready_replays_subscriber_pairing_after_both_ready");

      deployment.containerRuntimeReady(&advertiser);
      suite.expect(advertiser.advertisementActivations == 1, "container_runtime_ready_ignores_duplicate_advertiser");
      suite.expect(subscriber.subscriptionActivations == 1, "container_runtime_ready_duplicate_advertiser_has_no_subscription");

      advertiser.runtimeReady = false;
      deployment.containerRuntimeReady(&advertiser);
      suite.expect(advertiser.advertisementActivations == 2, "container_runtime_ready_replays_after_restart_reset");
      suite.expect(subscriber.subscriptionActivations == 2, "container_runtime_ready_replays_subscription_after_restart_reset");

      thisBrain = savedBrain;
   }

   {
      suite.expect(
         prodigyContainerIngressNetkitAttachType() == BPF_NETKIT_PRIMARY,
         "container_netkit_ingress_attach_type_is_primary");
      suite.expect(
         prodigyContainerEgressNetkitAttachType() == BPF_NETKIT_PEER,
         "container_netkit_egress_attach_type_is_peer");
      suite.expect(
         prodigyContainerIngressNetkitAttachType() != prodigyContainerEgressNetkitAttachType(),
         "container_netkit_attach_types_are_distinct");
   }

   {
      Vector<MachineDiskHardwareProfile> disks;

      auto addDisk = [&] (const char *mountPath) -> void {
         MachineDiskHardwareProfile disk = {};
         disk.mountPath.assign(mountPath);
         disks.push_back(std::move(disk));
      };

      addDisk("/");
      addDisk("/boot");
      addDisk("/boot/efi");
      addDisk("/containers");
      addDisk("/containers/data");
      addDisk("/data");
      addDisk("/archive");
      addDisk("/data");

      Vector<String> mountPaths;
      prodigyCollectUniqueContainerStorageMountPaths(disks, mountPaths);

      suite.expect(mountPaths.size() == 2, "storage_mount_inventory_excludes_reserved_paths_and_deduplicates");
      suite.expect(mountPaths.size() == 2 && mountPaths[0] == "/archive"_ctv, "storage_mount_inventory_sorts_mount_paths_0");
      suite.expect(mountPaths.size() == 2 && mountPaths[1] == "/data"_ctv, "storage_mount_inventory_sorts_mount_paths_1");
   }

   {
      Vector<String> mountPaths;
      mountPaths.push_back("/archive"_ctv);
      mountPaths.push_back("/data"_ctv);

      Vector<ProdigyContainerStorageDevicePlan> plans;
      prodigyBuildContainerStorageDevicePlan(mountPaths, "container-uuid"_ctv, 127, plans);
      suite.expect(plans.empty(), "storage_plan_builder_requires_minimum_loop_device_size");

      prodigyBuildContainerStorageDevicePlan(mountPaths, "container-uuid"_ctv, 256, plans);
      suite.expect(plans.size() == 2, "storage_plan_builder_uses_inventory_mount_paths");
      suite.expect(plans.size() == 2 && plans[0].mountPath == "/archive"_ctv, "storage_plan_builder_sets_mount_path_0");
      suite.expect(plans.size() == 2 && plans[1].mountPath == "/data"_ctv, "storage_plan_builder_sets_mount_path_1");
      suite.expect(plans.size() == 2 && plans[0].sizeMB == 128, "storage_plan_builder_splits_target_size_0");
      suite.expect(plans.size() == 2 && plans[1].sizeMB == 128, "storage_plan_builder_splits_target_size_1");
      suite.expect(
         plans.size() == 2 && plans[0].backingFilePath == "/archive/.prodigy/container-storage/container-uuid.btrfs.loop"_ctv,
         "storage_plan_builder_sets_backing_file_path_0");
      suite.expect(
         plans.size() == 2 && plans[1].backingFilePath == "/data/.prodigy/container-storage/container-uuid.btrfs.loop"_ctv,
         "storage_plan_builder_sets_backing_file_path_1");
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "launch_metadata_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         suite.expect(
            writeLaunchMetadataFixture(
               artifactRoot.path,
               R"({
  "execute_path": "/app/hello",
  "execute_args": ["--port", "7777"],
  "execute_env": ["FOO=bar", "BAZ=qux"],
  "execute_cwd": "/app",
  "execute_arch": "x86_64"
})"),
            "launch_metadata_fixture_written");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.plan.config.architecture = MachineCpuArchitecture::x86_64;

         String failure = {};
         bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);

         suite.expect(loaded, "launch_metadata_runtime_loader_accepts_private_blob_metadata");
         suite.expect(failure.size() == 0, "launch_metadata_runtime_loader_success_clears_failure");
         suite.expect(container.executePath == "/app/hello"_ctv, "launch_metadata_runtime_loader_sets_execute_path");
         suite.expect(container.executeArgs.size() == 2, "launch_metadata_runtime_loader_sets_execute_arg_count");
         suite.expect(container.executeArgs.size() == 2 && container.executeArgs[0] == "--port"_ctv, "launch_metadata_runtime_loader_sets_execute_arg_0");
         suite.expect(container.executeArgs.size() == 2 && container.executeArgs[1] == "7777"_ctv, "launch_metadata_runtime_loader_sets_execute_arg_1");
         suite.expect(container.executeEnv.size() == 2, "launch_metadata_runtime_loader_sets_execute_env_count");
         suite.expect(container.executeEnv.size() == 2 && container.executeEnv[0] == "FOO=bar"_ctv, "launch_metadata_runtime_loader_sets_execute_env_0");
         suite.expect(container.executeEnv.size() == 2 && container.executeEnv[1] == "BAZ=qux"_ctv, "launch_metadata_runtime_loader_sets_execute_env_1");
         suite.expect(container.executeCwd == "/app"_ctv, "launch_metadata_runtime_loader_sets_execute_cwd");
         suite.expect(container.executeArchitecture == MachineCpuArchitecture::x86_64, "launch_metadata_runtime_loader_sets_execute_architecture");
         suite.expect(container.executePath.c_str() != nullptr, "launch_metadata_runtime_loader_materializes_execute_path_c_string");
         suite.expect(container.executeCwd.c_str() != nullptr, "launch_metadata_runtime_loader_materializes_execute_cwd_c_string");
         suite.expect(container.executeArgs.size() == 2 && container.executeArgs[0].c_str() != nullptr, "launch_metadata_runtime_loader_materializes_execute_arg_c_string");
         suite.expect(container.executeEnv.size() == 2 && container.executeEnv[0].c_str() != nullptr, "launch_metadata_runtime_loader_materializes_execute_env_c_string");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "launch_metadata_arch_mismatch_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         suite.expect(
            writeLaunchMetadataFixture(
               artifactRoot.path,
               R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
            "launch_metadata_arch_mismatch_fixture_written");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.plan.config.architecture = MachineCpuArchitecture::aarch64;

         String failure = {};
         bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);

         suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_execute_arch_plan_mismatch");
         suite.expect(
            stringContains(failure, "mismatches plan architecture"),
            "launch_metadata_runtime_loader_reports_execute_arch_plan_mismatch");
      }
   }

   {
      MachineCpuArchitecture localArchitecture = nametagCurrentBuildMachineArchitecture();
      MachineCpuArchitecture wrongArchitecture = alternateSupportedArchitecture(localArchitecture);
      suite.expect(
         wrongArchitecture != MachineCpuArchitecture::unknown,
         "launch_metadata_local_arch_mismatch_fixture_has_supported_alternate_architecture");

      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "launch_metadata_local_arch_mismatch_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0 && wrongArchitecture != MachineCpuArchitecture::unknown)
      {
         String wrongArchitectureText = {};
         wrongArchitectureText.assign(machineCpuArchitectureName(wrongArchitecture));

         String metadataJSON = {};
         metadataJSON.assign(
            "{\n"
            "  \"execute_path\": \"/app/hello\",\n"
            "  \"execute_args\": [],\n"
            "  \"execute_env\": [],\n"
            "  \"execute_cwd\": \"/\",\n"
            "  \"execute_arch\": \""_ctv);
         metadataJSON.append(wrongArchitectureText);
         metadataJSON.append("\"\n}\n"_ctv);
         suite.expect(
            writeLaunchMetadataFixture(artifactRoot.path, metadataJSON.c_str()),
            "launch_metadata_local_arch_mismatch_fixture_written");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.plan.config.architecture = MachineCpuArchitecture::unknown;

         String failure = {};
         bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);

         suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_execute_arch_local_machine_mismatch");
         suite.expect(
            stringContains(failure, "mismatches local machine architecture"),
            "launch_metadata_runtime_loader_reports_execute_arch_local_machine_mismatch");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "launch_metadata_symlink_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "launch_metadata_symlink_fixture_private_dir_created");
         suite.expect(
            writeFileFixture(
               artifactRootPath / "outside-launch.metadata",
               "{\n  \"execute_path\": \"/app/hello\",\n  \"execute_args\": [],\n  \"execute_env\": [],\n  \"execute_cwd\": \"/\",\n  \"execute_arch\": \"x86_64\"\n}\n"),
            "launch_metadata_symlink_fixture_outside_metadata_written");
         suite.expect(
            createSymlinkFixture(artifactRootPath / "outside-launch.metadata", artifactRootPath / ".prodigy-private" / "launch.metadata"),
            "launch_metadata_symlink_fixture_symlink_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.plan.config.architecture = MachineCpuArchitecture::x86_64;

         String failure = {};
         bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
         suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_symlinked_launch_metadata");
         suite.expect(
            stringContains(failure, "launch.metadata"),
            "launch_metadata_runtime_loader_reports_symlinked_launch_metadata");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "launch_metadata_non_normalized_execute_path_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         suite.expect(
            writeLaunchMetadataFixture(
               artifactRoot.path,
               R"({
  "execute_path": "/app/../hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
            "launch_metadata_non_normalized_execute_path_fixture_written");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.plan.config.architecture = MachineCpuArchitecture::x86_64;

         String failure = {};
         bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
         suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_non_normalized_execute_path");
         suite.expect(
            stringContains(failure, "must not contain '..' path components"),
            "launch_metadata_runtime_loader_reports_non_normalized_execute_path");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "launch_metadata_non_normalized_execute_cwd_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         suite.expect(
            writeLaunchMetadataFixture(
               artifactRoot.path,
               R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/app//logs",
  "execute_arch": "x86_64"
})"),
            "launch_metadata_non_normalized_execute_cwd_fixture_written");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.plan.config.architecture = MachineCpuArchitecture::x86_64;

         String failure = {};
         bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
         suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_non_normalized_execute_cwd");
         suite.expect(
            stringContains(failure, "must not contain empty path components"),
            "launch_metadata_runtime_loader_reports_non_normalized_execute_cwd");
      }
   }

   {
      TemporaryDirectory workspace;
      suite.expect(workspace.create(), "container_blob_digest_fixture_mkdtemp_created");

      if (workspace.path.size() > 0)
      {
         std::filesystem::path blobPath = filesystemPathFromString(workspace.path) / "container.zst";
         suite.expect(
            writeFileFixture(blobPath, "discombobulator-blob-payload"),
            "container_blob_digest_fixture_written");

         String payload = {};
         payload.assign("discombobulator-blob-payload"_ctv);
         uint64_t expectedBytes = payload.size();
         String expectedDigest = {};
         String digestFailure = {};
         suite.expect(
            prodigyComputeSHA256Hex(payload, expectedDigest, &digestFailure),
            "container_blob_digest_fixture_sha256_computed");
         suite.expect(digestFailure.size() == 0, "container_blob_digest_fixture_sha256_failure_cleared");

         String verificationFailure = {};
         bool verified = ContainerManager::debugVerifyCompressedContainerBlob(
            stringFromFilesystemPath(blobPath),
            expectedDigest,
            expectedBytes,
            &verificationFailure);
         suite.expect(verified, "container_blob_digest_verifier_accepts_matching_sha256");
         suite.expect(verificationFailure.size() == 0, "container_blob_digest_verifier_success_clears_failure");

         String wrongDigest = {};
         wrongDigest.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
         verified = ContainerManager::debugVerifyCompressedContainerBlob(
            stringFromFilesystemPath(blobPath),
            wrongDigest,
            expectedBytes,
            &verificationFailure);
         suite.expect(verified == false, "container_blob_digest_verifier_rejects_mismatched_sha256");
         suite.expect(
            stringContains(verificationFailure, "sha256 mismatch"),
            "container_blob_digest_verifier_reports_mismatched_sha256");

         verified = ContainerManager::debugVerifyCompressedContainerBlob(
            stringFromFilesystemPath(blobPath),
            expectedDigest,
            expectedBytes + 1,
            &verificationFailure);
         suite.expect(verified == false, "container_blob_digest_verifier_rejects_mismatched_size");
         suite.expect(
            stringContains(verificationFailure, "blob size mismatch"),
            "container_blob_digest_verifier_reports_mismatched_size");
      }
   }

   {
      TemporaryDirectory workspace;
      suite.expect(workspace.create(), "container_blob_size_cap_fixture_mkdtemp_created");

      if (workspace.path.size() > 0)
      {
         std::filesystem::path blobPath = filesystemPathFromString(workspace.path) / "container.zst";
         suite.expect(
            writeFileFixture(blobPath, "small-blob"),
            "container_blob_size_cap_fixture_written");

         String verificationFailure = {};
         bool verified = ContainerManager::debugVerifyCompressedContainerBlob(
            stringFromFilesystemPath(blobPath),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv,
            prodigyContainerRuntimeLimits.maxCompressedBlobBytes + 1,
            &verificationFailure);
         suite.expect(verified == false, "container_blob_digest_verifier_rejects_oversized_trusted_blob");
         suite.expect(
            stringContains(verificationFailure, "size exceeds maximum"),
            "container_blob_digest_verifier_reports_oversized_trusted_blob");
      }
   }

   {
      TemporaryDirectory storeRoot;
      suite.expect(storeRoot.create(), "container_store_fixture_mkdtemp_created");

      if (storeRoot.path.size() > 0)
      {
         const uint64_t deploymentID = 987654321ULL;
         String firstPayload = {};
         firstPayload.assign("abcdefghijklmnopqrstuvwxyz0123456789"_ctv);
         String firstDigest = {};
         uint64_t firstBytes = 0;
         String failure = {};

         bool stored = ContainerStore::debugStoreAtRoot(
            storeRoot.path,
            deploymentID,
            firstPayload,
            &firstDigest,
            &firstBytes,
            nullptr,
            nullptr,
            &failure);
         suite.expect(stored, "container_store_debug_store_accepts_initial_blob");
         suite.expect(failure.size() == 0, "container_store_debug_store_initial_success_clears_failure");
         suite.expect(firstBytes == firstPayload.size(), "container_store_debug_store_reports_initial_size");

         String storedPath = ContainerStore::debugPathForContainerImageAtRoot(storeRoot.path, deploymentID);
         suite.expect(Filesystem::fileSize(storedPath) == firstPayload.size(), "container_store_debug_store_writes_initial_exact_size");

         String secondPayload = {};
         secondPayload.assign("tiny"_ctv);
         String secondDigest = {};
         uint64_t secondBytes = 0;
         stored = ContainerStore::debugStoreAtRoot(
            storeRoot.path,
            deploymentID,
            secondPayload,
            &secondDigest,
            &secondBytes,
            nullptr,
            nullptr,
            &failure);
         suite.expect(stored, "container_store_debug_store_overwrites_existing_blob");
         suite.expect(failure.size() == 0, "container_store_debug_store_overwrite_success_clears_failure");
         suite.expect(secondBytes == secondPayload.size(), "container_store_debug_store_reports_overwrite_size");
         suite.expect(Filesystem::fileSize(storedPath) == secondPayload.size(), "container_store_debug_store_overwrite_truncates_to_exact_size");

         String readback = {};
         Filesystem::openReadAtClose(-1, storedPath, readback);
         suite.expect(readback.equals(secondPayload), "container_store_debug_store_overwrite_replaces_payload_without_trailing_bytes");

         String verifyDigest = {};
         uint64_t verifyBytes = 0;
         bool verified = ContainerStore::debugVerifyAtRoot(
            storeRoot.path,
            deploymentID,
            secondDigest,
            secondPayload.size(),
            &verifyDigest,
            &verifyBytes,
            &failure);
         suite.expect(verified, "container_store_debug_verify_accepts_matching_digest_and_size");
         suite.expect(failure.size() == 0, "container_store_debug_verify_success_clears_failure");
         suite.expect(verifyDigest.equals(secondDigest), "container_store_debug_verify_reports_digest");
         suite.expect(verifyBytes == secondPayload.size(), "container_store_debug_verify_reports_size");

         verified = ContainerStore::debugVerifyAtRoot(
            storeRoot.path,
            deploymentID,
            secondDigest,
            secondPayload.size() + 1,
            &verifyDigest,
            &verifyBytes,
            &failure);
         suite.expect(verified == false, "container_store_debug_verify_rejects_mismatched_size");
         suite.expect(stringContains(failure, "blob size mismatch"), "container_store_debug_verify_reports_mismatched_size");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "artifact_shape_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "artifact_shape_fixture_rootfs_created");
         suite.expect(
            writeLaunchMetadataFixture(
               artifactRoot.path,
               R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
            "artifact_shape_fixture_metadata_written");

         String failure = {};
         bool valid = ContainerManager::debugValidateContainerArtifactShape(artifactRoot.path, &failure);
         suite.expect(valid, "artifact_shape_validator_accepts_exact_runtime_shape");
         suite.expect(failure.size() == 0, "artifact_shape_validator_success_clears_failure");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "artifact_shape_missing_rootfs_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         suite.expect(
            writeLaunchMetadataFixture(
               artifactRoot.path,
               R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
            "artifact_shape_missing_rootfs_fixture_metadata_written");

         String failure = {};
         bool valid = ContainerManager::debugValidateContainerArtifactShape(artifactRoot.path, &failure);
         suite.expect(valid == false, "artifact_shape_validator_rejects_missing_rootfs");
         suite.expect(
            stringContains(failure, "missing required top-level rootfs"),
            "artifact_shape_validator_reports_missing_rootfs");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "artifact_shape_extra_entry_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "artifact_shape_extra_entry_fixture_rootfs_created");
         suite.expect(createDirectoryFixture(artifactRootPath / "extra"), "artifact_shape_extra_entry_fixture_extra_created");
         suite.expect(
            writeLaunchMetadataFixture(
               artifactRoot.path,
               R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
            "artifact_shape_extra_entry_fixture_metadata_written");

         String failure = {};
         bool valid = ContainerManager::debugValidateContainerArtifactShape(artifactRoot.path, &failure);
         suite.expect(valid == false, "artifact_shape_validator_rejects_unexpected_top_level_entry");
         suite.expect(
            stringContains(failure, "unexpected top-level artifact entry"),
            "artifact_shape_validator_reports_unexpected_top_level_entry");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "artifact_shape_symlink_metadata_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "artifact_shape_symlink_metadata_fixture_rootfs_created");
         suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "artifact_shape_symlink_metadata_fixture_private_dir_created");
         suite.expect(
            writeFileFixture(artifactRootPath / "outside-launch.metadata", "{}\n"),
            "artifact_shape_symlink_metadata_fixture_outside_metadata_written");
         suite.expect(
            createSymlinkFixture(artifactRootPath / "outside-launch.metadata", artifactRootPath / ".prodigy-private" / "launch.metadata"),
            "artifact_shape_symlink_metadata_fixture_symlink_created");

         String failure = {};
         bool valid = ContainerManager::debugValidateContainerArtifactShape(artifactRoot.path, &failure);
         suite.expect(valid == false, "artifact_shape_validator_rejects_symlinked_launch_metadata");
         suite.expect(
            stringContains(failure, "launch.metadata"),
            "artifact_shape_validator_reports_symlinked_launch_metadata");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "artifact_shape_oversized_metadata_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "artifact_shape_oversized_metadata_fixture_rootfs_created");
         suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "artifact_shape_oversized_metadata_fixture_private_created");

         String oversizedMetadata = repeatedString(prodigyContainerRuntimeLimits.maxLaunchMetadataBytes + 1, 'x');
         suite.expect(
            writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", oversizedMetadata),
            "artifact_shape_oversized_metadata_fixture_metadata_written");

         String failure = {};
         bool valid = ContainerManager::debugValidateContainerArtifactShape(artifactRoot.path, &failure);
         suite.expect(valid == false, "artifact_shape_validator_rejects_oversized_launch_metadata");
         suite.expect(
            stringContains(failure, "exceeds maximum size"),
            "artifact_shape_validator_reports_oversized_launch_metadata");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.plan.config.architecture = MachineCpuArchitecture::x86_64;

         failure.clear();
         bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
         suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_oversized_launch_metadata");
         suite.expect(
            stringContains(failure, "failed to read launch metadata"),
            "launch_metadata_runtime_loader_reports_oversized_launch_metadata");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "launch_metadata_too_many_args_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::string metadata = "{\n"
            "  \"execute_path\": \"/app/hello\",\n"
            "  \"execute_args\": [";
         for (uint32_t i = 0; i < (prodigyContainerRuntimeLimits.maxLaunchMetadataArrayEntries + 1); i += 1)
         {
            if (i > 0)
            {
               metadata += ", ";
            }
            metadata += "\"arg\"";
         }
         metadata += "],\n"
            "  \"execute_env\": [],\n"
            "  \"execute_cwd\": \"/\",\n"
            "  \"execute_arch\": \"x86_64\"\n"
            "}\n";

         String metadataText = {};
         metadataText.assign(metadata.data(), metadata.size());
         suite.expect(
            writeLaunchMetadataFixture(artifactRoot.path, metadataText.c_str()),
            "launch_metadata_too_many_args_fixture_written");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.plan.config.architecture = MachineCpuArchitecture::x86_64;

         String failure = {};
         bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
         suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_too_many_execute_args");
         suite.expect(
            stringContains(failure, "execute_args must contain at most"),
            "launch_metadata_runtime_loader_reports_too_many_execute_args");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "launch_metadata_oversized_env_entry_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         String oversizedEnv = {};
         oversizedEnv.assign("A="_ctv);
         oversizedEnv.append(repeatedString(prodigyContainerRuntimeLimits.maxLaunchMetadataEntryBytes, 'x'));

         String metadata = {};
         metadata.assign(
            "{\n"
            "  \"execute_path\": \"/app/hello\",\n"
            "  \"execute_args\": [],\n"
            "  \"execute_env\": [\""_ctv);
         metadata.append(oversizedEnv);
         metadata.append("\"],\n"
            "  \"execute_cwd\": \"/\",\n"
            "  \"execute_arch\": \"x86_64\"\n"
            "}\n"_ctv);

         suite.expect(
            writeLaunchMetadataFixture(artifactRoot.path, metadata.c_str()),
            "launch_metadata_oversized_env_entry_fixture_written");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.plan.config.architecture = MachineCpuArchitecture::x86_64;

         String failure = {};
         bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
         suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_oversized_execute_env_entry");
         suite.expect(
            stringContains(failure, "execute_env entries must be at most"),
            "launch_metadata_runtime_loader_reports_oversized_execute_env_entry");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "artifact_resource_limits_rootfs_bytes_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            writeFileFixture(artifactRootPath / "rootfs" / "large.bin", repeatedString(2ULL * 1024ULL * 1024ULL, 'r')),
            "artifact_resource_limits_rootfs_bytes_fixture_large_file_written");
         suite.expect(
            writeLaunchMetadataFixture(
               artifactRoot.path,
               R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
            "artifact_resource_limits_rootfs_bytes_fixture_metadata_written");

         String failure = {};
         bool valid = ContainerManager::debugValidateContainerArtifactResourceLimits(
            artifactRoot.path,
            1ULL * 1024ULL * 1024ULL,
            prodigyContainerRuntimeLimits.maxArtifactEntries,
            prodigyContainerRuntimeLimits.maxArtifactBytes,
            &failure);
         suite.expect(valid == false, "artifact_resource_limits_reject_rootfs_bytes_above_filesystem_limit");
         suite.expect(
            stringContains(failure, "rootfs regular-file bytes exceed filesystemMB"),
            "artifact_resource_limits_report_rootfs_bytes_above_filesystem_limit");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "artifact_resource_limits_total_bytes_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            writeFileFixture(artifactRootPath / "rootfs" / "large.bin", repeatedString(2ULL * 1024ULL * 1024ULL, 't')),
            "artifact_resource_limits_total_bytes_fixture_large_file_written");
         suite.expect(
            writeLaunchMetadataFixture(
               artifactRoot.path,
               R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
            "artifact_resource_limits_total_bytes_fixture_metadata_written");

         String failure = {};
         bool valid = ContainerManager::debugValidateContainerArtifactResourceLimits(
            artifactRoot.path,
            4ULL * 1024ULL * 1024ULL,
            prodigyContainerRuntimeLimits.maxArtifactEntries,
            1ULL * 1024ULL * 1024ULL,
            &failure);
         suite.expect(valid == false, "artifact_resource_limits_reject_total_artifact_bytes_above_global_limit");
         suite.expect(
            stringContains(failure, "artifact regular-file bytes exceed maximum"),
            "artifact_resource_limits_report_total_artifact_bytes_above_global_limit");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "artifact_resource_limits_entry_count_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            writeFileFixture(artifactRootPath / "rootfs" / "a", "a"),
            "artifact_resource_limits_entry_count_fixture_file_a_written");
         suite.expect(
            writeFileFixture(artifactRootPath / "rootfs" / "b", "b"),
            "artifact_resource_limits_entry_count_fixture_file_b_written");
         suite.expect(
            writeLaunchMetadataFixture(
               artifactRoot.path,
               R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
            "artifact_resource_limits_entry_count_fixture_metadata_written");

         String failure = {};
         bool valid = ContainerManager::debugValidateContainerArtifactResourceLimits(
            artifactRoot.path,
            8ULL * 1024ULL * 1024ULL,
            4,
            prodigyContainerRuntimeLimits.maxArtifactBytes,
            &failure);
         suite.expect(valid == false, "artifact_resource_limits_reject_too_many_entries");
         suite.expect(
            stringContains(failure, "artifact contains too many entries"),
            "artifact_resource_limits_report_too_many_entries");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "rootfs_host_mount_targets_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "rootfs_host_mount_targets_fixture_rootfs_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.userID = uint32_t(fixtureWritableUserID());

         String failure = {};
         bool prepared = ContainerManager::debugPrepareContainerRootFSMountTargets(&container, &failure);
         suite.expect(prepared, "rootfs_host_mount_targets_prepare_succeeds");
         suite.expect(failure.size() == 0, "rootfs_host_mount_targets_prepare_clears_failure");
         suite.expect(
            std::filesystem::exists(artifactRootPath / "rootfs" / "etc" / "resolv.conf"),
            "rootfs_host_mount_targets_prepare_creates_resolv_conf_target");
         suite.expect(
            std::filesystem::exists(artifactRootPath / "rootfs" / "proc"),
            "rootfs_host_mount_targets_prepare_creates_proc_directory");
         suite.expect(
            std::filesystem::exists(artifactRootPath / "rootfs" / "dev" / "null"),
            "rootfs_host_mount_targets_prepare_creates_standard_device_nodes");
         struct stat etcStat = {};
         struct stat resolvStat = {};
         int etcStatResult = ::stat((artifactRootPath / "rootfs" / "etc").c_str(), &etcStat);
         int resolvStatResult = ::stat((artifactRootPath / "rootfs" / "etc" / "resolv.conf").c_str(), &resolvStat);
         suite.expect(
            etcStatResult == 0 && etcStat.st_uid == fixtureWritableUserID() && etcStat.st_gid == fixtureWritableGroupID(),
            "rootfs_host_mount_targets_prepare_sets_etc_ownership");
         suite.expect(
            resolvStatResult == 0 && resolvStat.st_uid == fixtureWritableUserID() && resolvStat.st_gid == fixtureWritableGroupID(),
            "rootfs_host_mount_targets_prepare_sets_resolv_conf_ownership");
         suite.expect(
            std::filesystem::exists(artifactRootPath / "rootfs" / "run" / "systemd" / "resolve" / "io.systemd.Resolve") == false,
            "rootfs_host_mount_targets_prepare_does_not_create_systemd_resolve_target");
         suite.expect(
            std::filesystem::exists(artifactRootPath / "rootfs" / "var" / "cache" / "ca-certs") == false,
            "rootfs_host_mount_targets_prepare_does_not_create_host_ca_cache_target");
      }
   }

   {
      suite.expect(
         ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/dri/renderD128"_ctv),
         "gpu_device_allowlist_accepts_dri_render_node");
      suite.expect(
         ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/dri/card0"_ctv),
         "gpu_device_allowlist_accepts_dri_card_node");
      suite.expect(
         ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/nvidia0"_ctv),
         "gpu_device_allowlist_accepts_nvidia_minor_node");
      suite.expect(
         ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/nvidiactl"_ctv),
         "gpu_device_allowlist_accepts_nvidiactl");
      suite.expect(
         ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/null"_ctv) == false,
         "gpu_device_allowlist_rejects_non_gpu_char_device");
      suite.expect(
         ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/sda"_ctv) == false,
         "gpu_device_allowlist_rejects_block_device_path");
      suite.expect(
         ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/tmp/fake-gpu"_ctv) == false,
         "gpu_device_allowlist_rejects_non_dev_path");
      suite.expect(
         ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/nvidiactl/extra"_ctv) == false,
         "gpu_device_allowlist_rejects_nested_path");
   }

   {
      int pipeFDs[2] = {-1, -1};
      suite.expect(pipe(pipeFDs) == 0, "container_exec_fd_move_fixture_pipe_created");

      if (pipeFDs[0] >= 0 && pipeFDs[1] >= 0)
      {
         int movedFD = pipeFDs[1];
         String failure = {};
         bool moved = ContainerManager::debugMoveContainerExecDescriptorAboveMinimum(movedFD, &failure);
         suite.expect(moved, "container_exec_fd_move_rehomes_low_fd");
         suite.expect(failure.size() == 0, "container_exec_fd_move_success_clears_failure");
         suite.expect(movedFD >= containerExecInheritedFDMinimum, "container_exec_fd_move_places_fd_above_minimum");
         suite.expect(fcntl(movedFD, F_GETFD) >= 0, "container_exec_fd_move_preserves_rehomed_fd");
         suite.expect(fcntl(pipeFDs[1], F_GETFD) < 0 && errno == EBADF, "container_exec_fd_move_closes_original_fd");
         close(pipeFDs[0]);
         close(movedFD);
      }
   }

   {
      int preservedFDs[2] = {-1, -1};
      int extraFDs[2] = {-1, -1};
      suite.expect(pipe(preservedFDs) == 0, "container_exec_fd_sanitizer_fixture_preserved_pipe_created");
      suite.expect(pipe(extraFDs) == 0, "container_exec_fd_sanitizer_fixture_extra_pipe_created");

      if (preservedFDs[0] >= 0 && preservedFDs[1] >= 0 && extraFDs[0] >= 0 && extraFDs[1] >= 0)
      {
         pid_t child = fork();
         suite.expect(child >= 0, "container_exec_fd_sanitizer_fixture_fork_created");

         if (child == 0)
         {
            int preservedFD = preservedFDs[1];
            String failure = {};
            bool sanitized = ContainerManager::debugCloseAllContainerExecDescriptorsExcept(preservedFD, -1, &failure);
            if (sanitized == false)
            {
               _exit(10);
            }

            if (fcntl(preservedFD, F_GETFD) < 0)
            {
               _exit(11);
            }

            if (fcntl(extraFDs[0], F_GETFD) >= 0 || errno != EBADF)
            {
               _exit(12);
            }

            if (fcntl(extraFDs[1], F_GETFD) >= 0 || errno != EBADF)
            {
               _exit(13);
            }

            _exit(0);
         }

         if (child > 0)
         {
            int status = 0;
            waitpid(child, &status, 0);
            suite.expect(WIFEXITED(status) && WEXITSTATUS(status) == 0, "container_exec_fd_sanitizer_closes_unpreserved_fds");
         }

         close(preservedFDs[0]);
         close(preservedFDs[1]);
         close(extraFDs[0]);
         close(extraFDs[1]);
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "launch_target_validation_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            writeFileFixture(artifactRootPath / "rootfs" / "app" / "hello", "#!/bin/sh\nexit 0\n"),
            "launch_target_validation_fixture_binary_written");
         suite.expect(
            makeFileExecutableFixture(artifactRootPath / "rootfs" / "app" / "hello"),
            "launch_target_validation_fixture_binary_executable");
         suite.expect(
            createDirectoryFixture(artifactRootPath / "rootfs" / "app"),
            "launch_target_validation_fixture_cwd_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.executePath.assign("/app/hello"_ctv);
         container.executeCwd.assign("/app"_ctv);

         String failure = {};
         bool valid = ContainerManager::debugValidateContainerLaunchTargets(&container, &failure);
         suite.expect(valid, "launch_target_validation_accepts_paths_beneath_rootfs");
         suite.expect(failure.size() == 0, "launch_target_validation_success_clears_failure");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "launch_target_execute_symlink_escape_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "launch_target_execute_symlink_escape_fixture_rootfs_created");
         suite.expect(createDirectoryFixture(artifactRootPath / "outside"), "launch_target_execute_symlink_escape_fixture_outside_created");
         suite.expect(
            writeFileFixture(artifactRootPath / "outside" / "hello", "#!/bin/sh\nexit 0\n"),
            "launch_target_execute_symlink_escape_fixture_outside_binary_written");
         suite.expect(
            makeFileExecutableFixture(artifactRootPath / "outside" / "hello"),
            "launch_target_execute_symlink_escape_fixture_outside_binary_executable");
         suite.expect(
            createSymlinkFixture("../outside", artifactRootPath / "rootfs" / "app"),
            "launch_target_execute_symlink_escape_fixture_symlink_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.executePath.assign("/app/hello"_ctv);
         container.executeCwd.assign("/"_ctv);

         String failure = {};
         bool valid = ContainerManager::debugValidateContainerLaunchTargets(&container, &failure);
         suite.expect(valid == false, "launch_target_validation_rejects_execute_path_symlink_escape");
         suite.expect(
            stringContains(failure, "execute_path does not resolve beneath container rootfs"),
            "launch_target_validation_reports_execute_path_symlink_escape");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "launch_target_cwd_symlink_escape_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            writeFileFixture(artifactRootPath / "rootfs" / "bin" / "hello", "#!/bin/sh\nexit 0\n"),
            "launch_target_cwd_symlink_escape_fixture_binary_written");
         suite.expect(
            makeFileExecutableFixture(artifactRootPath / "rootfs" / "bin" / "hello"),
            "launch_target_cwd_symlink_escape_fixture_binary_executable");
         suite.expect(createDirectoryFixture(artifactRootPath / "outside-work"), "launch_target_cwd_symlink_escape_fixture_outside_created");
         suite.expect(
            createSymlinkFixture("../outside-work", artifactRootPath / "rootfs" / "work"),
            "launch_target_cwd_symlink_escape_fixture_symlink_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.executePath.assign("/bin/hello"_ctv);
         container.executeCwd.assign("/work"_ctv);

         String failure = {};
         bool valid = ContainerManager::debugValidateContainerLaunchTargets(&container, &failure);
         suite.expect(valid == false, "launch_target_validation_rejects_execute_cwd_symlink_escape");
         suite.expect(
            stringContains(failure, "execute_cwd does not resolve beneath container rootfs"),
            "launch_target_validation_reports_execute_cwd_symlink_escape");
      }
   }

   {
      TemporaryDirectory receiveScratch;
      suite.expect(receiveScratch.create(), "receive_scratch_single_entry_fixture_mkdtemp_created");

      if (receiveScratch.path.size() > 0)
      {
         std::filesystem::path receiveScratchPath = filesystemPathFromString(receiveScratch.path);
         suite.expect(
            createDirectoryFixture(receiveScratchPath / "artifact"),
            "receive_scratch_single_entry_fixture_artifact_created");

         String artifactName = {};
         String artifactPath = {};
         String failure = {};
         bool selected = ContainerManager::debugSelectReceivedContainerArtifactFromScratch(
            receiveScratch.path,
            artifactName,
            artifactPath,
            &failure);

         String expectedArtifactPath = {};
         expectedArtifactPath.assign(receiveScratch.path);
         expectedArtifactPath.append("/artifact"_ctv);

         suite.expect(selected, "receive_scratch_selector_accepts_exact_single_entry");
         suite.expect(failure.size() == 0, "receive_scratch_selector_success_clears_failure");
         suite.expect(artifactName == "artifact"_ctv, "receive_scratch_selector_returns_entry_name");
         suite.expect(artifactPath.equals(expectedArtifactPath), "receive_scratch_selector_returns_entry_path");
      }
   }

   {
      TemporaryDirectory receiveScratch;
      suite.expect(receiveScratch.create(), "receive_scratch_empty_fixture_mkdtemp_created");

      if (receiveScratch.path.size() > 0)
      {
         String artifactName = {};
         String artifactPath = {};
         String failure = {};
         bool selected = ContainerManager::debugSelectReceivedContainerArtifactFromScratch(
            receiveScratch.path,
            artifactName,
            artifactPath,
            &failure);

         suite.expect(selected == false, "receive_scratch_selector_rejects_empty_directory");
         suite.expect(
            stringContains(failure, "produced no artifact"),
            "receive_scratch_selector_reports_empty_directory");
      }
   }

   {
      TemporaryDirectory receiveScratch;
      suite.expect(receiveScratch.create(), "receive_scratch_hidden_entry_fixture_mkdtemp_created");

      if (receiveScratch.path.size() > 0)
      {
         std::filesystem::path receiveScratchPath = filesystemPathFromString(receiveScratch.path);
         suite.expect(
            createDirectoryFixture(receiveScratchPath / ".artifact"),
            "receive_scratch_hidden_entry_fixture_artifact_created");

         String artifactName = {};
         String artifactPath = {};
         String failure = {};
         bool selected = ContainerManager::debugSelectReceivedContainerArtifactFromScratch(
            receiveScratch.path,
            artifactName,
            artifactPath,
            &failure);

         suite.expect(selected == false, "receive_scratch_selector_rejects_hidden_entry");
         suite.expect(
            stringContains(failure, "hidden top-level artifact entries"),
            "receive_scratch_selector_reports_hidden_entry");
      }
   }

   {
      TemporaryDirectory receiveScratch;
      suite.expect(receiveScratch.create(), "receive_scratch_multiple_entries_fixture_mkdtemp_created");

      if (receiveScratch.path.size() > 0)
      {
         std::filesystem::path receiveScratchPath = filesystemPathFromString(receiveScratch.path);
         suite.expect(
            createDirectoryFixture(receiveScratchPath / "artifact-a"),
            "receive_scratch_multiple_entries_fixture_a_created");
         suite.expect(
            createDirectoryFixture(receiveScratchPath / "artifact-b"),
            "receive_scratch_multiple_entries_fixture_b_created");

         String artifactName = {};
         String artifactPath = {};
         String failure = {};
         bool selected = ContainerManager::debugSelectReceivedContainerArtifactFromScratch(
            receiveScratch.path,
            artifactName,
            artifactPath,
            &failure);

         suite.expect(selected == false, "receive_scratch_selector_rejects_multiple_entries");
         suite.expect(
            stringContains(failure, "exactly one top-level artifact entry"),
            "receive_scratch_selector_reports_multiple_entries");
      }
   }

   {
      TemporaryDirectory containersRoot;
      suite.expect(containersRoot.create(), "failed_create_artifact_cleanup_fixture_mkdtemp_created");

      if (containersRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(containersRoot.path) / "1234";
         suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "failed_create_artifact_cleanup_fixture_rootfs_created");
         suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "failed_create_artifact_cleanup_fixture_private_dir_created");
         suite.expect(
            writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", "{}\n"),
            "failed_create_artifact_cleanup_fixture_metadata_written");

         Container container {};
         container.artifactRootPath.assign(stringFromFilesystemPath(artifactRootPath));
         container.rootfsPath.assign(stringFromFilesystemPath(artifactRootPath / "rootfs"));

         String failure = {};
         bool cleaned = ContainerManager::debugCleanupFailedCreateArtifactRoot(&container, &failure);

         std::error_code existsError;
         bool artifactExists = std::filesystem::exists(artifactRootPath, existsError);

         suite.expect(cleaned, "failed_create_artifact_cleanup_removes_artifact_root");
         suite.expect(failure.size() == 0, "failed_create_artifact_cleanup_success_clears_failure");
         suite.expect(existsError.value() == 0 && artifactExists == false, "failed_create_artifact_cleanup_erases_artifact_tree");
         suite.expect(container.artifactRootPath.size() == 0, "failed_create_artifact_cleanup_clears_artifact_root_path");
         suite.expect(container.rootfsPath.size() == 0, "failed_create_artifact_cleanup_clears_rootfs_path");
      }
   }

   {
      TemporaryDirectory containersRoot;
      suite.expect(containersRoot.create(), "rejected_artifact_janitor_orphan_fixture_mkdtemp_created");

      if (containersRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(containersRoot.path) / "1001";
         suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "rejected_artifact_janitor_orphan_fixture_rootfs_created");
         suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "rejected_artifact_janitor_orphan_fixture_private_dir_created");
         suite.expect(
            writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", "{}\n"),
            "rejected_artifact_janitor_orphan_fixture_metadata_written");
         suite.expect(
            writeFileFixture(artifactRootPath / ".prodigy-private" / "create.pending", "99999999\n"),
            "rejected_artifact_janitor_orphan_fixture_marker_written");

         String failure = {};
         bool cleaned = ContainerManager::debugCleanupRejectedOrphanedContainerArtifacts(containersRoot.path, &failure);

         std::error_code existsError;
         bool artifactExists = std::filesystem::exists(artifactRootPath, existsError);

         suite.expect(cleaned, "rejected_artifact_janitor_reaps_orphaned_pending_artifact");
         suite.expect(failure.size() == 0, "rejected_artifact_janitor_orphan_success_clears_failure");
         suite.expect(existsError.value() == 0 && artifactExists == false, "rejected_artifact_janitor_erases_orphaned_artifact_tree");
      }
   }

   {
      TemporaryDirectory containersRoot;
      suite.expect(containersRoot.create(), "rejected_artifact_janitor_live_fixture_mkdtemp_created");

      if (containersRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(containersRoot.path) / "1002";
         suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "rejected_artifact_janitor_live_fixture_rootfs_created");
         suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "rejected_artifact_janitor_live_fixture_private_dir_created");
         suite.expect(
            writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", "{}\n"),
            "rejected_artifact_janitor_live_fixture_metadata_written");
         char livePidText[64] = {0};
         std::snprintf(livePidText, sizeof(livePidText), "%d\n", int(getpid()));
         suite.expect(
            writeFileFixture(artifactRootPath / ".prodigy-private" / "create.pending", livePidText),
            "rejected_artifact_janitor_live_fixture_marker_written");

         String failure = {};
         bool cleaned = ContainerManager::debugCleanupRejectedOrphanedContainerArtifacts(containersRoot.path, &failure);

         std::error_code existsError;
         bool artifactExists = std::filesystem::exists(artifactRootPath, existsError);

         suite.expect(cleaned, "rejected_artifact_janitor_preserves_live_pending_artifact");
         suite.expect(failure.size() == 0, "rejected_artifact_janitor_live_success_clears_failure");
         suite.expect(existsError.value() == 0 && artifactExists, "rejected_artifact_janitor_keeps_live_pending_artifact_tree");
      }
   }

   {
      TemporaryDirectory containersRoot;
      suite.expect(containersRoot.create(), "rejected_artifact_janitor_unmarked_fixture_mkdtemp_created");

      if (containersRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(containersRoot.path) / "1003";
         suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "rejected_artifact_janitor_unmarked_fixture_rootfs_created");
         suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "rejected_artifact_janitor_unmarked_fixture_private_dir_created");
         suite.expect(
            writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", "{}\n"),
            "rejected_artifact_janitor_unmarked_fixture_metadata_written");

         String failure = {};
         bool cleaned = ContainerManager::debugCleanupRejectedOrphanedContainerArtifacts(containersRoot.path, &failure);

         std::error_code existsError;
         bool artifactExists = std::filesystem::exists(artifactRootPath, existsError);

         suite.expect(cleaned, "rejected_artifact_janitor_preserves_unmarked_artifact");
         suite.expect(failure.size() == 0, "rejected_artifact_janitor_unmarked_success_clears_failure");
         suite.expect(existsError.value() == 0 && artifactExists, "rejected_artifact_janitor_keeps_unmarked_artifact_tree");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      TemporaryDirectory retentionRoot;
      suite.expect(artifactRoot.create(), "failed_container_retention_fixture_artifact_root_created");
      suite.expect(retentionRoot.create(), "failed_container_retention_fixture_retention_root_created");

      if (artifactRoot.path.size() > 0 && retentionRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         std::filesystem::path rootfsPath = artifactRootPath / "rootfs";
         suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "failed_container_retention_fixture_private_dir_created");
         suite.expect(createDirectoryFixture(rootfsPath), "failed_container_retention_fixture_rootfs_dir_created");
         suite.expect(createDirectoryFixture(rootfsPath / "logs"), "failed_container_retention_fixture_logs_dir_created");
         suite.expect(writeFileFixture(rootfsPath / "bootstage.txt", "boot=prepare\n"), "failed_container_retention_fixture_bootstage_written");
         suite.expect(writeFileFixture(rootfsPath / "crashreport.txt", "crash=segv\n"), "failed_container_retention_fixture_crashreport_written");
         suite.expect(writeFileFixture(rootfsPath / "readytrace.log", "ready=0\n"), "failed_container_retention_fixture_readytrace_written");
         suite.expect(writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", "{\"launch\":1}\n"), "failed_container_retention_fixture_launch_metadata_written");
         suite.expect(writeFileFixture(rootfsPath / "logs" / "stdout.log", "stdout-line\n"), "failed_container_retention_fixture_stdout_written");
         suite.expect(writeFileFixture(rootfsPath / "logs" / "stderr.log", "stderr-line\n"), "failed_container_retention_fixture_stderr_written");

         Container container = {};
         container.plan.uuid = uint128_t(0x7123);
         container.plan.config.applicationID = 77;
         container.plan.state = ContainerState::healthy;
         container.plan.restartOnFailure = true;
         container.name.assign("15947919734958006183"_ctv);
         container.pid = 4242;
         container.artifactRootPath.assign(artifactRoot.path);
         container.rootfsPath.assign(stringFromFilesystemPath(rootfsPath));

         siginfo_t info = {};
         info.si_code = CLD_DUMPED;
         info.si_status = SIGSEGV;
         info.si_pid = container.pid;

         String retainedBundlePath = {};
         String failure = {};
         bool preserved = ContainerManager::debugPreserveFailedContainerArtifactsAtPath(
            retentionRoot.path,
            &container,
            info,
            1'710'000'000'000LL,
            SIGSEGV,
            &retainedBundlePath,
            &failure);
         if (!preserved || failure.size() > 0)
         {
            fprintf(stderr, "detail failed_container_retention preserve=%d failure=%s retainedPath=%s\n",
               int(preserved),
               failure.c_str(),
               retainedBundlePath.c_str());
            fflush(stderr);
         }
         suite.expect(preserved, "failed_container_retention_preserves_bundle");
         suite.expect(failure.size() == 0, "failed_container_retention_success_clears_failure");

         std::filesystem::path retainedPath = filesystemPathFromString(retainedBundlePath);
         suite.expect(std::filesystem::exists(retainedPath / "metadata.txt"), "failed_container_retention_writes_metadata");
         suite.expect(std::filesystem::exists(retainedPath / "bootstage.txt"), "failed_container_retention_copies_bootstage");
         suite.expect(std::filesystem::exists(retainedPath / "crashreport.txt"), "failed_container_retention_copies_crashreport");
         suite.expect(std::filesystem::exists(retainedPath / "readytrace.log"), "failed_container_retention_copies_readytrace");
         suite.expect(std::filesystem::exists(retainedPath / "launch.metadata"), "failed_container_retention_copies_launch_metadata");
         suite.expect(std::filesystem::exists(retainedPath / "logs" / "stdout.log"), "failed_container_retention_copies_stdout");
         suite.expect(std::filesystem::exists(retainedPath / "logs" / "stderr.log"), "failed_container_retention_copies_stderr");
      }
   }

   {
      TemporaryDirectory retentionRoot;
      suite.expect(retentionRoot.create(), "failed_container_retention_gc_fixture_root_created");

      if (retentionRoot.path.size() > 0)
      {
         std::filesystem::path rootPath = filesystemPathFromString(retentionRoot.path);
         std::filesystem::path expiredBundle = rootPath / "77" / "111" / "1000";
         std::filesystem::path freshBundle = rootPath / "77" / "222" / "2000";
         suite.expect(createDirectoryFixture(expiredBundle), "failed_container_retention_gc_fixture_expired_bundle_created");
         suite.expect(createDirectoryFixture(freshBundle), "failed_container_retention_gc_fixture_fresh_bundle_created");
         suite.expect(writeFileFixture(expiredBundle / "metadata.txt", "expired\n"), "failed_container_retention_gc_fixture_expired_metadata_written");
         suite.expect(writeFileFixture(freshBundle / "metadata.txt", "fresh\n"), "failed_container_retention_gc_fixture_fresh_metadata_written");

         std::error_code oldTimeError = {};
         std::filesystem::last_write_time(
            expiredBundle,
            std::filesystem::file_time_type::clock::now() - std::chrono::hours(30),
            oldTimeError);
         suite.expect(oldTimeError.value() == 0, "failed_container_retention_gc_fixture_sets_expired_bundle_time");

         std::error_code freshTimeError = {};
         std::filesystem::last_write_time(
            freshBundle,
            std::filesystem::file_time_type::clock::now() - std::chrono::hours(1),
            freshTimeError);
         suite.expect(freshTimeError.value() == 0, "failed_container_retention_gc_fixture_sets_fresh_bundle_time");

         String failure = {};
         bool cleaned = ContainerManager::debugCleanupExpiredFailedContainerArtifactsAtPath(
            retentionRoot.path,
            Time::now<TimeResolution::ms>(),
            failedContainerArtifactRetentionMs,
            &failure);
         suite.expect(cleaned, "failed_container_retention_gc_succeeds");
         suite.expect(failure.size() == 0, "failed_container_retention_gc_success_clears_failure");
         suite.expect(std::filesystem::exists(expiredBundle) == false, "failed_container_retention_gc_removes_expired_bundle");
         suite.expect(std::filesystem::exists(freshBundle), "failed_container_retention_gc_keeps_fresh_bundle");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      TemporaryDirectory retentionRoot;
      suite.expect(artifactRoot.create(), "failed_container_retention_if_needed_fixture_artifact_root_created");
      suite.expect(retentionRoot.create(), "failed_container_retention_if_needed_fixture_retention_root_created");

      if (artifactRoot.path.size() > 0 && retentionRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         std::filesystem::path rootfsPath = artifactRootPath / "rootfs";
         suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "failed_container_retention_if_needed_fixture_private_dir_created");
         suite.expect(createDirectoryFixture(rootfsPath), "failed_container_retention_if_needed_fixture_rootfs_dir_created");
         suite.expect(createDirectoryFixture(rootfsPath / "logs"), "failed_container_retention_if_needed_fixture_logs_dir_created");
         suite.expect(writeFileFixture(rootfsPath / "crashreport.txt", "crash=abort\n"), "failed_container_retention_if_needed_fixture_crashreport_written");
         suite.expect(writeFileFixture(rootfsPath / "logs" / "stderr.log", "stderr-line\n"), "failed_container_retention_if_needed_fixture_stderr_written");

         Container container = {};
         container.plan.uuid = uint128_t(0x8123);
         container.plan.config.applicationID = 88;
         container.plan.state = ContainerState::healthy;
         container.plan.restartOnFailure = false;
         container.name.assign("17170712990884937031"_ctv);
         container.pid = 5151;
         container.artifactRootPath.assign(artifactRoot.path);
         container.rootfsPath.assign(stringFromFilesystemPath(rootfsPath));
         container.infop = {};
         container.infop.si_pid = container.pid;
         container.infop.si_code = CLD_DUMPED;
         container.infop.si_status = SIGABRT;

         String firstRetainedBundlePath = {};
         String secondRetainedBundlePath = {};
         String failure = {};
         bool firstPreserved = ContainerManager::debugPreserveFailedContainerArtifactsIfNeededAtPath(
            retentionRoot.path,
            &container,
            1'710'000'123'000LL,
            &firstRetainedBundlePath,
            &failure);
         suite.expect(firstPreserved, "failed_container_retention_if_needed_first_preserves_bundle");
         suite.expect(failure.size() == 0, "failed_container_retention_if_needed_first_success_clears_failure");
         suite.expect(container.failedArtifactsPreserved, "failed_container_retention_if_needed_first_sets_preserved_flag");

         failure.clear();
         bool secondPreserved = ContainerManager::debugPreserveFailedContainerArtifactsIfNeededAtPath(
            retentionRoot.path,
            &container,
            1'710'000'124'000LL,
            &secondRetainedBundlePath,
            &failure);
         suite.expect(secondPreserved, "failed_container_retention_if_needed_second_succeeds");
         suite.expect(failure.size() == 0, "failed_container_retention_if_needed_second_success_clears_failure");
         suite.expect(secondRetainedBundlePath.size() == 0, "failed_container_retention_if_needed_second_noops_without_new_bundle");

         std::filesystem::path retainedRootPath = filesystemPathFromString(retentionRoot.path);
         uint32_t bundleCount = 0;
         std::error_code iteratorError = {};
         for (std::filesystem::recursive_directory_iterator it(retainedRootPath, iteratorError), end; it != end; it.increment(iteratorError))
         {
            if (iteratorError)
            {
               break;
            }

            std::error_code statusError = {};
            std::filesystem::file_status status = it->symlink_status(statusError);
            if (statusError)
            {
               iteratorError = statusError;
               break;
            }

            if (std::filesystem::is_directory(status) && it->path().filename() == "1710000123000")
            {
               bundleCount += 1;
            }
         }
         suite.expect(iteratorError.value() == 0, "failed_container_retention_if_needed_bundle_count_iteration_succeeds");
         suite.expect(bundleCount == 1, "failed_container_retention_if_needed_only_one_bundle_written");
         suite.expect(std::filesystem::exists(filesystemPathFromString(firstRetainedBundlePath) / "metadata.txt"), "failed_container_retention_if_needed_first_bundle_writes_metadata");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "secure_rootfs_symlink_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            createDirectoryFixture(artifactRootPath / "outside-rootfs"),
            "secure_rootfs_symlink_fixture_outside_directory_created");
         suite.expect(
            createSymlinkFixture(artifactRootPath / "outside-rootfs", artifactRootPath / "rootfs"),
            "secure_rootfs_symlink_fixture_rootfs_symlink_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);

         String failure = {};
         bool opened = ContainerManager::debugOpenVerifiedContainerRootfs(&container, &failure);
         suite.expect(opened == false, "secure_rootfs_open_rejects_rootfs_symlink");
         suite.expect(
            stringContains(failure, "without following symlinks"),
            "secure_rootfs_open_reports_rootfs_symlink_rejection");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "rootfs_ownership_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            createDirectoryFixture(artifactRootPath / "rootfs"),
            "rootfs_ownership_fixture_rootfs_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);

         uid_t targetUserID = fixtureWritableUserID();
         gid_t targetGroupID = fixtureWritableGroupID();

         String failure = {};
         bool assigned = ContainerManager::debugAssignContainerRootfsOwnership(
            &container,
            uint32_t(targetUserID),
            uint32_t(targetGroupID),
            &failure);
         suite.expect(assigned, "rootfs_ownership_helper_accepts_o_path_descriptor");
         suite.expect(failure.size() == 0, "rootfs_ownership_helper_success_clears_failure");

         struct stat rootfsStat = {};
         int statResult = ::stat((artifactRootPath / "rootfs").c_str(), &rootfsStat);
         suite.expect(statResult == 0, "rootfs_ownership_fixture_stat_succeeds");
         suite.expect(
            statResult == 0 && rootfsStat.st_uid == targetUserID,
            "rootfs_ownership_helper_sets_rootfs_uid");
         suite.expect(
            statResult == 0 && rootfsStat.st_gid == targetGroupID,
            "rootfs_ownership_helper_sets_rootfs_gid");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "secure_mount_target_etc_symlink_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            createDirectoryFixture(artifactRootPath / "rootfs"),
            "secure_mount_target_etc_symlink_fixture_rootfs_created");
         suite.expect(
            createDirectoryFixture(artifactRootPath / "outside-etc"),
            "secure_mount_target_etc_symlink_fixture_outside_created");
         suite.expect(
            createSymlinkFixture(artifactRootPath / "outside-etc", artifactRootPath / "rootfs" / "etc"),
            "secure_mount_target_etc_symlink_fixture_symlink_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.userID = uint32_t(fixtureWritableUserID());

         String failure = {};
         bool prepared = ContainerManager::debugPrepareContainerRootFSMountTargets(&container, &failure);
         suite.expect(prepared == false, "secure_mount_target_prep_rejects_etc_symlink");
         suite.expect(
            stringContains(failure, "without following symlinks"),
            "secure_mount_target_prep_reports_etc_symlink_rejection");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "secure_mount_target_run_symlink_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            createDirectoryFixture(artifactRootPath / "rootfs"),
            "secure_mount_target_run_symlink_fixture_rootfs_created");
         suite.expect(
            createDirectoryFixture(artifactRootPath / "outside-run"),
            "secure_mount_target_run_symlink_fixture_outside_created");
         suite.expect(
            createSymlinkFixture(artifactRootPath / "outside-run", artifactRootPath / "rootfs" / "run"),
            "secure_mount_target_run_symlink_fixture_symlink_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.userID = uint32_t(fixtureWritableUserID());

         String failure = {};
         bool prepared = ContainerManager::debugPrepareContainerRootFSMountTargets(&container, &failure);
         suite.expect(prepared, "secure_mount_target_prep_ignores_run_symlink_when_run_mount_removed");
         suite.expect(
            failure.size() == 0,
            "secure_mount_target_prep_run_symlink_removed_surface_clears_failure");
         suite.expect(
            std::filesystem::is_symlink(artifactRootPath / "rootfs" / "run"),
            "secure_mount_target_prep_run_symlink_removed_surface_leaves_run_symlink_untouched");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "secure_mount_target_storage_symlink_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            createDirectoryFixture(artifactRootPath / "rootfs"),
            "secure_mount_target_storage_symlink_fixture_rootfs_created");
         suite.expect(
            createDirectoryFixture(artifactRootPath / "outside-storage"),
            "secure_mount_target_storage_symlink_fixture_outside_created");
         suite.expect(
            createSymlinkFixture(artifactRootPath / "outside-storage", artifactRootPath / "rootfs" / "storage"),
            "secure_mount_target_storage_symlink_fixture_symlink_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.plan.config.storageMB = 64;
         container.userID = uint32_t(fixtureWritableUserID());

         String failure = {};
         bool prepared = ContainerManager::debugPrepareContainerRootFSMountTargets(&container, &failure);
         suite.expect(prepared == false, "secure_mount_target_prep_rejects_storage_symlink");
         suite.expect(
            stringContains(failure, "without following symlinks"),
            "secure_mount_target_prep_reports_storage_symlink_rejection");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "secure_mount_target_var_symlink_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            createDirectoryFixture(artifactRootPath / "rootfs"),
            "secure_mount_target_var_symlink_fixture_rootfs_created");
         suite.expect(
            createDirectoryFixture(artifactRootPath / "outside-var"),
            "secure_mount_target_var_symlink_fixture_outside_created");
         suite.expect(
            createSymlinkFixture(artifactRootPath / "outside-var", artifactRootPath / "rootfs" / "var"),
            "secure_mount_target_var_symlink_fixture_symlink_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);
         container.userID = uint32_t(fixtureWritableUserID());

         String failure = {};
         bool prepared = ContainerManager::debugPrepareContainerRootFSMountTargets(&container, &failure);
         suite.expect(prepared, "secure_mount_target_prep_ignores_var_symlink_when_var_mount_removed");
         suite.expect(
            failure.size() == 0,
            "secure_mount_target_prep_var_symlink_removed_surface_clears_failure");
         suite.expect(
            std::filesystem::is_symlink(artifactRootPath / "rootfs" / "var"),
            "secure_mount_target_prep_var_symlink_removed_surface_leaves_var_symlink_untouched");
      }
   }

   {
      TemporaryDirectory artifactRoot;
      suite.expect(artifactRoot.create(), "secure_bind_target_dev_symlink_fixture_mkdtemp_created");

      if (artifactRoot.path.size() > 0)
      {
         std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
         suite.expect(
            createDirectoryFixture(artifactRootPath / "rootfs"),
            "secure_bind_target_dev_symlink_fixture_rootfs_created");
         suite.expect(
            createDirectoryFixture(artifactRootPath / "outside-dev"),
            "secure_bind_target_dev_symlink_fixture_outside_created");
         suite.expect(
            createSymlinkFixture(artifactRootPath / "outside-dev", artifactRootPath / "rootfs" / "dev"),
            "secure_bind_target_dev_symlink_fixture_symlink_created");

         Container container {};
         container.artifactRootPath.assign(artifactRoot.path);

         String failure = {};
         bool prepared = ContainerManager::debugPrepareBindMountFileTargetInRootFS(&container, "/dev/null"_ctv, &failure);
         suite.expect(prepared == false, "secure_bind_target_prep_rejects_dev_symlink");
         suite.expect(
            stringContains(failure, "without following symlinks"),
            "secure_bind_target_prep_reports_dev_symlink_rejection");
      }
   }

   {
      String hex = {};
      hex.assignItoh(uint16_t(0x1234));
      suite.expect(hex == "0x1234"_ctv, "assignItoh_uint16_formats_canonical_hex");
      suite.expect(String::numberFromHexString<uint16_t>(hex) == uint16_t(0x1234), "numberFromHexString_uint16_roundtrips_canonical_hex");
   }

   {
      const uint128_t uuid = (uint128_t(0x25a812f1daecf688ULL) << 64) | uint128_t(0xfc738a2aa4684e95ULL);
      String hex = {};
      hex.assignItoh(uuid);

      suite.expect(hex == "0x25a812f1daecf688fc738a2aa4684e95"_ctv, "assignItoh_uint128_formats_canonical_hex");
      suite.expect(String::numberFromHexString<uint128_t>(hex) == uuid, "numberFromHexString_uint128_roundtrips_canonical_hex");
      suite.expect(
         String::numberFromHexString<uint128_t>("0X000025A812F1DAECF688FC738A2AA4684E95"_ctv) == uuid,
         "numberFromHexString_uint128_accepts_prefix_case_and_leading_zeroes");
      suite.expect(
         String::numberFromHexString<uint128_t>("0x25a812f1daecf688fc738a2aa4684e95gg"_ctv) == uint128_t(0),
         "numberFromHexString_uint128_rejects_invalid_hex");
   }

   {
      suite.expect(
         statefulConstructionNeedsSeedingSubscription(DataStrategy::genesis, false) == false,
         "stateful_seeding_subscription_genesis_without_seeding_always");
      suite.expect(
         statefulConstructionNeedsSeedingSubscription(DataStrategy::genesis, true) == false,
         "stateful_seeding_subscription_genesis_ignores_seeding_always");
      suite.expect(
         statefulConstructionNeedsSeedingSubscription(DataStrategy::changelog, false) == false,
         "stateful_seeding_subscription_changelog_skips_without_seeding_always");
      suite.expect(
         statefulConstructionNeedsSeedingSubscription(DataStrategy::changelog, true),
         "stateful_seeding_subscription_changelog_uses_seeding_always");
      suite.expect(
         statefulConstructionNeedsSeedingSubscription(DataStrategy::seeding, false),
         "stateful_seeding_subscription_seeding_strategy_requires_seeders");
      suite.expect(
         statefulConstructionNeedsSeedingSubscription(DataStrategy::sharding, true) == false,
         "stateful_seeding_subscription_sharding_uses_dedicated_sharding_mesh");
   }

   {
      DeploymentPlan plan{};
      plan.config.config_version = 77;
      plan.config.applicationID = 42;
      plan.config.versionID = 9;
      plan.config.type = ApplicationType::stateful;
      plan.config.containerBlobSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv;
      plan.config.containerBlobBytes = 4096;
      plan.minimumSubscriberCapacity = 11;
      plan.isStateful = true;
      plan.config.minGPUs = 2;
      plan.config.gpuMemoryGB = 24;
      plan.config.nicSpeedGbps = 10;
      plan.config.minInternetDownloadMbps = 500;
      plan.config.minInternetUploadMbps = 250;
      plan.config.maxInternetLatencyMs = 20;
      plan.stateful.clientPrefix = 101;
      plan.stateful.siblingPrefix = 102;
      plan.stateful.cousinPrefix = 103;
      plan.stateful.seedingPrefix = 104;
      plan.stateful.shardingPrefix = 105;
      plan.stateful.allowUpdateInPlace = true;
      plan.stateful.seedingAlways = false;
      plan.stateful.neverShard = false;
      plan.stateful.allMasters = true;
      plan.useHostNetworkNamespace = true;
      Whitehole whitehole = {};
      whitehole.transport = ExternalAddressTransport::quic;
      whitehole.family = ExternalAddressFamily::ipv6;
      whitehole.source = ExternalAddressSource::hostPublicAddress;
      whitehole.hasAddress = true;
      whitehole.address = IPAddress("2001:db8::55", true);
      whitehole.sourcePort = 5555;
      whitehole.bindingNonce = 77;
      plan.whiteholes.push_back(whitehole);

      String serialized;
      BitseryEngine::serialize(serialized, plan);

      DeploymentPlan roundtrip{};
      bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

      suite.expect(decoded, "deployment_plan_roundtrip_deserializes");
      suite.expect(roundtrip.config.config_version == 77, "deployment_plan_roundtrip_preserves_config_version");
      suite.expect(roundtrip.config.minGPUs == 2, "deployment_plan_roundtrip_preserves_min_gpus");
      suite.expect(roundtrip.config.gpuMemoryGB == 24, "deployment_plan_roundtrip_preserves_gpu_memory_gb");
      suite.expect(roundtrip.config.nicSpeedGbps == 10, "deployment_plan_roundtrip_preserves_nic_speed_gbps");
      suite.expect(roundtrip.config.minInternetDownloadMbps == 500, "deployment_plan_roundtrip_preserves_min_internet_download");
      suite.expect(roundtrip.config.minInternetUploadMbps == 250, "deployment_plan_roundtrip_preserves_min_internet_upload");
      suite.expect(roundtrip.config.maxInternetLatencyMs == 20, "deployment_plan_roundtrip_preserves_max_internet_latency");
      suite.expect(roundtrip.config.containerBlobSHA256.equals(plan.config.containerBlobSHA256), "deployment_plan_roundtrip_preserves_container_blob_sha256");
      suite.expect(roundtrip.config.containerBlobBytes == plan.config.containerBlobBytes, "deployment_plan_roundtrip_preserves_container_blob_bytes");
      suite.expect(roundtrip.stateful.allMasters == true, "deployment_plan_roundtrip_preserves_all_masters");
      suite.expect(roundtrip.useHostNetworkNamespace == true, "deployment_plan_roundtrip_preserves_host_network_namespace");
      suite.expect(roundtrip.whiteholes.size() == 1, "deployment_plan_roundtrip_preserves_whiteholes");
      suite.expect(roundtrip.whiteholes[0].sourcePort == 5555, "deployment_plan_roundtrip_preserves_whitehole_source_port");
      suite.expect(roundtrip.whiteholes[0].bindingNonce == 77, "deployment_plan_roundtrip_preserves_whitehole_binding_nonce");
   }

   {
      DeploymentPlan plan{};
      Wormhole wormhole = {};
      wormhole.externalAddress = IPAddress("2001:db8::44", true);
      wormhole.externalPort = 443;
      wormhole.containerPort = 8443;
      wormhole.layer4 = IPPROTO_UDP;
      wormhole.isQuic = true;
      wormhole.hasQuicCidKeyState = true;
      wormhole.source = ExternalAddressSource::registeredRoutableAddress;
      wormhole.routableAddressUUID = uint128_t(0xAABBCCDD0011);
      wormhole.quicCidKeyState.rotationHours = 12;
      wormhole.quicCidKeyState.activeKeyIndex = 1;
      wormhole.quicCidKeyState.rotatedAtMs = 123456789;
      wormhole.quicCidKeyState.keyMaterialByIndex[0] = uint128_t(0x1111222233334444ULL);
      wormhole.quicCidKeyState.keyMaterialByIndex[1] = uint128_t(0xAAAABBBBCCCCDDDDULL);
      plan.wormholes.push_back(wormhole);

      String serialized;
      BitseryEngine::serialize(serialized, plan);

      DeploymentPlan roundtrip{};
      bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

      suite.expect(decoded, "deployment_plan_roundtrip_quic_wormhole_deserializes");
      suite.expect(roundtrip.wormholes.size() == 1, "deployment_plan_roundtrip_preserves_wormhole_count");
      suite.expect(roundtrip.wormholes[0].isQuic == true, "deployment_plan_roundtrip_preserves_wormhole_quic_flag");
      suite.expect(roundtrip.wormholes[0].hasQuicCidKeyState == true, "deployment_plan_roundtrip_preserves_wormhole_quic_key_state_flag");
      suite.expect(roundtrip.wormholes[0].quicCidKeyState.rotationHours == 12, "deployment_plan_roundtrip_preserves_wormhole_quic_rotation_hours");
      suite.expect(roundtrip.wormholes[0].quicCidKeyState.activeKeyIndex == 1, "deployment_plan_roundtrip_preserves_wormhole_quic_active_key_index");
      suite.expect(roundtrip.wormholes[0].quicCidKeyState.rotatedAtMs == 123456789, "deployment_plan_roundtrip_preserves_wormhole_quic_rotated_at");
      suite.expect(roundtrip.wormholes[0].quicCidKeyState.keyMaterialByIndex[0] == uint128_t(0x1111222233334444ULL), "deployment_plan_roundtrip_preserves_wormhole_quic_key_slot_0");
      suite.expect(roundtrip.wormholes[0].quicCidKeyState.keyMaterialByIndex[1] == uint128_t(0xAAAABBBBCCCCDDDDULL), "deployment_plan_roundtrip_preserves_wormhole_quic_key_slot_1");
      suite.expect(wormholeUsesQuicCidEncryption(roundtrip.wormholes[0]), "deployment_plan_roundtrip_recognizes_quic_wormhole");
      suite.expect(wormholeQuicCidInactiveKeyIndex(roundtrip.wormholes[0].quicCidKeyState) == 0, "deployment_plan_roundtrip_computes_quic_inactive_key_index");
   }

   {
      ContainerPlan plan{};
      plan.uuid = uint128_t(0x77);
      plan.config.applicationID = 88;
      plan.fragment = 9;
      plan.useHostNetworkNamespace = true;
      plan.restartOnFailure = true;
      plan.isStateful = true;
      plan.shardGroup = 3;
      plan.nShardGroups = 5;
      plan.assignedGPUMemoryMBs.push_back(16 * 1024u);
      plan.assignedGPUMemoryMBs.push_back(24 * 1024u);
      AssignedGPUDevice firstGPU = {};
      firstGPU.vendor = "nvidia"_ctv;
      firstGPU.model = "L4"_ctv;
      firstGPU.busAddress = "0000:65:00.0"_ctv;
      firstGPU.memoryMB = 24 * 1024u;
      plan.assignedGPUDevices.push_back(firstGPU);
      AssignedGPUDevice secondGPU = {};
      secondGPU.vendor = "amd"_ctv;
      secondGPU.model = "MI210"_ctv;
      secondGPU.busAddress = "0000:66:00.0"_ctv;
      secondGPU.memoryMB = 16 * 1024u;
      plan.assignedGPUDevices.push_back(secondGPU);
      Whitehole whitehole = {};
      whitehole.transport = ExternalAddressTransport::tcp;
      whitehole.family = ExternalAddressFamily::ipv4;
      whitehole.source = ExternalAddressSource::hostPublicAddress;
      whitehole.hasAddress = true;
      whitehole.address = IPAddress("203.0.113.99", false);
      whitehole.sourcePort = 6000;
      whitehole.bindingNonce = 1234;
      plan.whiteholes.push_back(whitehole);

      String serialized;
      BitseryEngine::serialize(serialized, plan);

      ContainerPlan roundtrip{};
      bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

      suite.expect(decoded, "container_plan_roundtrip_deserializes");
      suite.expect(roundtrip.useHostNetworkNamespace == true, "container_plan_roundtrip_preserves_host_network_namespace");
      suite.expect(roundtrip.fragment == 9, "container_plan_roundtrip_preserves_fragment");
      suite.expect(roundtrip.shardGroup == 3, "container_plan_roundtrip_preserves_shard_group");
      suite.expect(roundtrip.nShardGroups == 5, "container_plan_roundtrip_preserves_shard_group_count");
      suite.expect(roundtrip.assignedGPUMemoryMBs.size() == 2, "container_plan_roundtrip_preserves_assigned_gpu_count");
      suite.expect(roundtrip.assignedGPUMemoryMBs[0] == 16 * 1024u && roundtrip.assignedGPUMemoryMBs[1] == 24 * 1024u, "container_plan_roundtrip_preserves_assigned_gpu_memory");
      suite.expect(roundtrip.assignedGPUDevices.size() == 2, "container_plan_roundtrip_preserves_assigned_gpu_devices_count");
      suite.expect(roundtrip.assignedGPUDevices[0].busAddress == "0000:65:00.0"_ctv && roundtrip.assignedGPUDevices[1].busAddress == "0000:66:00.0"_ctv, "container_plan_roundtrip_preserves_assigned_gpu_device_bus_addresses");
      suite.expect(roundtrip.assignedGPUDevices[0].vendor == "nvidia"_ctv && roundtrip.assignedGPUDevices[1].vendor == "amd"_ctv, "container_plan_roundtrip_preserves_assigned_gpu_device_vendors");
      suite.expect(roundtrip.whiteholes.size() == 1, "container_plan_roundtrip_preserves_whiteholes");
      suite.expect(roundtrip.whiteholes[0].sourcePort == 6000, "container_plan_roundtrip_preserves_whitehole_source_port");
      suite.expect(roundtrip.whiteholes[0].bindingNonce == 1234, "container_plan_roundtrip_preserves_whitehole_binding_nonce");
   }

   {
      DeploymentPlan plan{};
      plan.config.applicationID = 77;
      plan.config.versionID = 1;
      plan.config.type = ApplicationType::stateless;
      plan.config.filesystemMB = 64;
      plan.config.storageMB = 64;
      plan.config.memoryMB = 128;
      plan.config.nLogicalCores = 1;
      plan.config.msTilHealthy = 10'000;
      plan.config.sTilHealthcheck = 15;
      plan.config.sTilKillable = 30;
      plan.minimumSubscriberCapacity = 1024;
      plan.isStateful = false;
      plan.stateless.nBase = 1;
      plan.stateless.maxPerRackRatio = 1.0f;
      plan.stateless.maxPerMachineRatio = 1.0f;
      plan.stateless.moveableDuringCompaction = true;
      plan.useHostNetworkNamespace = false;
      plan.moveConstructively = true;
      plan.requiresDatacenterUniqueTag = false;

      Advertisement advertisement{};
      advertisement.service = 0x0100'0000'0000'0001ULL;
      advertisement.startAt = ContainerState::scheduled;
      advertisement.stopAt = ContainerState::destroying;
      advertisement.port = 19121;
      plan.advertisements.push_back(advertisement);

      Subscription subscription{};
      subscription.service = 0x0100'0000'0000'0001ULL;
      subscription.startAt = ContainerState::scheduled;
      subscription.stopAt = ContainerState::destroying;
      subscription.nature = SubscriptionNature::any;
      plan.subscriptions.push_back(subscription);

      String serialized;
      BitseryEngine::serialize(serialized, plan);

      DeploymentPlan roundtrip{};
      const bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

      suite.expect(decoded, "deployment_plan_mesh_roundtrip_deserializes");
      suite.expect(roundtrip.advertisements.size() == 1, "deployment_plan_mesh_roundtrip_preserves_advertisement");
      suite.expect(roundtrip.subscriptions.size() == 1, "deployment_plan_mesh_roundtrip_preserves_subscription");

      String messageBuffer;
      const uint32_t headerOffset = Message::appendHeader(messageBuffer, MothershipTopic::measureApplication);
      Message::serializeAndAppendObject(messageBuffer, plan);
      Message::finish(messageBuffer, headerOffset);
      suite.expect(messageBuffer.size() >= sizeof(Message), "deployment_plan_mesh_message_serializes");

      String stagedMessageBuffer;
      const uint32_t stagedHeaderOffset = Message::appendHeader(stagedMessageBuffer, MothershipTopic::measureApplication);
      String stagedSerializedPlan;
      BitseryEngine::serialize(stagedSerializedPlan, plan);
      Message::appendValue(stagedMessageBuffer, stagedSerializedPlan);
      Message::finish(stagedMessageBuffer, stagedHeaderOffset);

      Message *stagedMessage = reinterpret_cast<Message *>(stagedMessageBuffer.data());
      uint8_t *stagedArgs = stagedMessage->args;
      String stagedPayload;
      Message::extractToStringView(stagedArgs, stagedPayload);
      DeploymentPlan stagedRoundtrip{};
      const bool stagedDecoded = BitseryEngine::deserializeSafe(stagedPayload, stagedRoundtrip);
      suite.expect(stagedDecoded, "deployment_plan_mesh_staged_message_deserializes");
      suite.expect(stagedRoundtrip.advertisements.size() == 1, "deployment_plan_mesh_staged_message_preserves_advertisement");
      suite.expect(stagedRoundtrip.subscriptions.size() == 1, "deployment_plan_mesh_staged_message_preserves_subscription");
   }

   {
      DeploymentPlan plan{};

      HorizontalScaler horizontalCpu{};
      horizontalCpu.name.assign(ProdigyMetrics::runtimeContainerCpuUtilPctName);
      plan.horizontalScalers.push_back(horizontalCpu);

      HorizontalScaler horizontalIngress{};
      horizontalIngress.name.assign(ProdigyMetrics::runtimeIngressQueueWaitCompositeName);
      plan.horizontalScalers.push_back(horizontalIngress);

      VerticalScaler verticalMemory{};
      verticalMemory.resource = ScalingDimension::memory;
      plan.verticalScalers.push_back(verticalMemory);

      NeuronContainerMetricPolicy policy = deriveNeuronMetricPolicyForDeployment(plan);
      const uint64_t expectedMask =
         ProdigyMetrics::maskForScalingDimension(ScalingDimension::cpu) |
         ProdigyMetrics::maskForScalingDimension(ScalingDimension::memory);

      suite.expect(policy.scalingDimensionsMask == expectedMask, "deriveNeuronMetricPolicy_uses_collectable_scaler_dimensions");
      suite.expect(policy.metricsCadenceMs == ProdigyMetrics::defaultNeuronCollectionCadenceMs, "deriveNeuronMetricPolicy_sets_default_cadence_when_collectable_present");
   }

   {
      DeploymentPlan plan{};
      HorizontalScaler horizontalIngress{};
      horizontalIngress.name.assign(ProdigyMetrics::runtimeIngressQueueWaitCompositeName);
      plan.horizontalScalers.push_back(horizontalIngress);

      NeuronContainerMetricPolicy policy = deriveNeuronMetricPolicyForDeployment(plan);
      suite.expect(policy.scalingDimensionsMask == 0, "deriveNeuronMetricPolicy_excludes_ingress_composite_from_neuron_sampling");
      suite.expect(policy.metricsCadenceMs == 0, "deriveNeuronMetricPolicy_keeps_zero_cadence_without_collectable_dimensions");
   }

   {
      NeuronContainerBootstrap bootstrap{};
      bootstrap.plan.uuid = uint128_t(0x1234);
      bootstrap.plan.config.applicationID = 55;
      bootstrap.plan.config.versionID = 66;
      bootstrap.plan.config.containerBlobSHA256 = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"_ctv;
      bootstrap.plan.config.containerBlobBytes = 8192;
      bootstrap.plan.useHostNetworkNamespace = true;
      Whitehole whitehole = {};
      whitehole.transport = ExternalAddressTransport::tcp;
      whitehole.family = ExternalAddressFamily::ipv4;
      whitehole.source = ExternalAddressSource::hostPublicAddress;
      whitehole.hasAddress = true;
      whitehole.address = IPAddress("198.51.100.77", false);
      whitehole.sourcePort = 4444;
      whitehole.bindingNonce = 222;
      bootstrap.plan.whiteholes.push_back(whitehole);
      bootstrap.metricPolicy.scalingDimensionsMask = ProdigyMetrics::maskForScalingDimension(ScalingDimension::storage);
      bootstrap.metricPolicy.metricsCadenceMs = 9000;

      String serialized;
      BitseryEngine::serialize(serialized, bootstrap);

      NeuronContainerBootstrap roundtrip{};
      const bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

      suite.expect(decoded, "neuron_container_bootstrap_roundtrip_deserializes");
      suite.expect(roundtrip.plan.uuid == uint128_t(0x1234), "neuron_container_bootstrap_roundtrip_preserves_plan_uuid");
      suite.expect(roundtrip.plan.config.applicationID == 55 && roundtrip.plan.config.versionID == 66, "neuron_container_bootstrap_roundtrip_preserves_plan_config_ids");
      suite.expect(roundtrip.plan.config.containerBlobSHA256.equals(bootstrap.plan.config.containerBlobSHA256), "neuron_container_bootstrap_roundtrip_preserves_plan_blob_sha256");
      suite.expect(roundtrip.plan.config.containerBlobBytes == bootstrap.plan.config.containerBlobBytes, "neuron_container_bootstrap_roundtrip_preserves_plan_blob_bytes");
      suite.expect(roundtrip.plan.useHostNetworkNamespace == true, "neuron_container_bootstrap_roundtrip_preserves_host_network_namespace");
      suite.expect(roundtrip.plan.whiteholes.size() == 1, "neuron_container_bootstrap_roundtrip_preserves_whiteholes");
      suite.expect(roundtrip.plan.whiteholes[0].sourcePort == 4444, "neuron_container_bootstrap_roundtrip_preserves_whitehole_source_port");
      suite.expect(roundtrip.metricPolicy.scalingDimensionsMask == bootstrap.metricPolicy.scalingDimensionsMask, "neuron_container_bootstrap_roundtrip_preserves_metric_mask");
      suite.expect(roundtrip.metricPolicy.metricsCadenceMs == 9000, "neuron_container_bootstrap_roundtrip_preserves_metric_cadence");

      String stagedMessageBuffer;
      const uint32_t stagedHeaderOffset = Message::appendHeader(stagedMessageBuffer, NeuronTopic::stateUpload);
      String stagedSerializedBootstrap;
      BitseryEngine::serialize(stagedSerializedBootstrap, bootstrap);
      Message::appendValue(stagedMessageBuffer, stagedSerializedBootstrap);
      Message::finish(stagedMessageBuffer, stagedHeaderOffset);

      Message *stagedMessage = reinterpret_cast<Message *>(stagedMessageBuffer.data());
      uint8_t *stagedArgs = stagedMessage->args;
      String stagedPayload;
      Message::extractToStringView(stagedArgs, stagedPayload);
      NeuronContainerBootstrap stagedRoundtrip{};
      const bool stagedDecoded = BitseryEngine::deserializeSafe(stagedPayload, stagedRoundtrip);
      suite.expect(stagedDecoded, "neuron_container_bootstrap_staged_message_deserializes");
      suite.expect(stagedRoundtrip.plan.uuid == bootstrap.plan.uuid, "neuron_container_bootstrap_staged_message_preserves_plan_uuid");
      suite.expect(stagedRoundtrip.metricPolicy.metricsCadenceMs == bootstrap.metricPolicy.metricsCadenceMs, "neuron_container_bootstrap_staged_message_preserves_metric_cadence");
   }

   {
      DeploymentPlan deploymentPlan{};
      deploymentPlan.config.applicationID = 501;
      deploymentPlan.config.versionID = 3;
      deploymentPlan.useHostNetworkNamespace = true;
      deploymentPlan.requiresDatacenterUniqueTag = true;

      ContainerView container{};
      container.uuid = uint128_t(0x8888);
      container.fragment = 17;
      container.lifetime = ApplicationLifetime::base;
      container.state = ContainerState::scheduled;
      container.createdAtMs = 123456;
      container.shardGroup = 7;
      container.assignedGPUMemoryMBs.push_back(24 * 1024u);
      AssignedGPUDevice assignedGPU = {};
      assignedGPU.vendor = "nvidia"_ctv;
      assignedGPU.model = "A10"_ctv;
      assignedGPU.busAddress = "0000:af:00.0"_ctv;
      assignedGPU.memoryMB = 24 * 1024u;
      container.assignedGPUDevices.push_back(assignedGPU);

      ContainerPlan plan = container.generatePlan(deploymentPlan);
      suite.expect(plan.useHostNetworkNamespace == true, "containerview_generatePlan_preserves_host_network_namespace");
      suite.expect(plan.requiresDatacenterUniqueTag == true, "containerview_generatePlan_preserves_unique_tag");
      suite.expect(plan.fragment == 17, "containerview_generatePlan_preserves_fragment");
      suite.expect(plan.assignedGPUMemoryMBs.size() == 1 && plan.assignedGPUMemoryMBs[0] == 24 * 1024u, "containerview_generatePlan_preserves_assigned_gpu_memory");
      suite.expect(plan.assignedGPUDevices.size() == 1 && plan.assignedGPUDevices[0].busAddress == "0000:af:00.0"_ctv, "containerview_generatePlan_preserves_assigned_gpu_devices");
   }

   {
      DeploymentPlan deploymentPlan{};
      deploymentPlan.config.applicationID = 502;
      deploymentPlan.config.versionID = 4;
      deploymentPlan.useHostNetworkNamespace = true;
      deploymentPlan.isStateful = true;
      deploymentPlan.stateful.clientPrefix = (uint64_t(502) << 48) | (uint64_t(1) << 40) | 0x3ffULL;
      deploymentPlan.stateful.siblingPrefix = (uint64_t(502) << 48) | (uint64_t(2) << 40) | 0x3ffULL;
      deploymentPlan.stateful.cousinPrefix = (uint64_t(502) << 48) | (uint64_t(3) << 40) | 0x3ffULL;
      deploymentPlan.stateful.seedingPrefix = (uint64_t(502) << 48) | (uint64_t(4) << 40) | 0x3ffULL;
      deploymentPlan.stateful.shardingPrefix = (uint64_t(502) << 48) | (uint64_t(5) << 40) | 0x3ffULL;

      ContainerView container{};
      container.uuid = uint128_t(0x9999);
      container.fragment = 18;
      container.lifetime = ApplicationLifetime::base;
      container.state = ContainerState::scheduled;
      container.createdAtMs = 123457;
      container.shardGroup = 7;
      container.isStateful = true;

      StatefulMeshRoles roles = StatefulMeshRoles::forShardGroup(deploymentPlan.stateful, container.shardGroup);
      container.advertisements.emplace(roles.sibling, Advertisement(roles.sibling, ContainerState::scheduled, ContainerState::destroying, 19113));
      container.subscriptions.emplace(roles.sibling, Subscription(roles.sibling, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));
      container.subscriptions.emplace(roles.seeding, Subscription(roles.seeding, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));

      ContainerPlan plan = container.generatePlan(deploymentPlan, 11);
      suite.expect(plan.statefulMeshRoles.client == 0, "containerview_generatePlan_prunes_unassigned_stateful_client_role");
      suite.expect(plan.statefulMeshRoles.sibling == roles.sibling, "containerview_generatePlan_preserves_assigned_stateful_sibling_role");
      suite.expect(plan.statefulMeshRoles.cousin == 0, "containerview_generatePlan_prunes_unassigned_stateful_cousin_role");
      suite.expect(plan.statefulMeshRoles.seeding == roles.seeding, "containerview_generatePlan_preserves_assigned_stateful_seeding_role");
      suite.expect(plan.statefulMeshRoles.sharding == 0, "containerview_generatePlan_prunes_unassigned_stateful_sharding_role");
      suite.expect(plan.nShardGroups == 11, "containerview_generatePlan_preserves_stateful_shard_group_count");
   }

   {
      ContainerPlan plan{};
      plan.isStateful = true;
      plan.shardGroup = 7;
      plan.nShardGroups = 13;

      Vector<uint64_t> flags = {};
      prodigyBuildContainerStartupFlags(plan, flags);

      suite.expect(flags.size() == 2, "container_startup_flags_stateful_include_two_entries");
      suite.expect(flags[0] == 7, "container_startup_flags_stateful_preserve_shard_group");
      suite.expect(flags[1] == 13, "container_startup_flags_stateful_preserve_shard_group_count");
   }

   {
      ContainerPlan plan{};
      Vector<uint64_t> flags = {};
      prodigyBuildContainerStartupFlags(plan, flags);

      suite.expect(flags.size() == 1, "container_startup_flags_stateless_keep_legacy_shape");
      suite.expect(flags[0] == 0, "container_startup_flags_stateless_default_zero_group");
   }

   {
      ApplicationConfig config{};
      String json = "{\"minGPUs\":2,\"gpuMemoryGB\":24,\"nicSpeedGbps\":10,\"minInternetDownloadMbps\":500,\"minInternetUploadMbps\":250,\"maxInternetLatencyMs\":20}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool parsedField = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         String failure;
         parsedField = mothershipParseApplicationMachineSelectionObject(doc, config, "config"_ctv, &failure);
         suite.expect(failure.size() == 0, "mothership_parse_machine_resource_criteria_no_failure");
      }

      suite.expect(parsedField, "mothership_parse_machine_resource_criteria_parses");
      suite.expect(config.minGPUs == 2, "mothership_parse_machine_resource_fields_sets_min_gpus");
      suite.expect(config.gpuMemoryGB == 24, "mothership_parse_machine_resource_fields_sets_gpu_memory_gb");
      suite.expect(config.nicSpeedGbps == 10, "mothership_parse_machine_resource_fields_sets_nic_speed_gbps");
      suite.expect(config.minInternetDownloadMbps == 500, "mothership_parse_machine_resource_fields_sets_min_internet_download");
      suite.expect(config.minInternetUploadMbps == 250, "mothership_parse_machine_resource_fields_sets_min_internet_upload");
      suite.expect(config.maxInternetLatencyMs == 20, "mothership_parse_machine_resource_fields_sets_max_internet_latency");
   }

   {
      ApplicationConfig config{};
      String json = "{\"gpuMemoryGB\":24}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool rejected = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         String failure;
         rejected = (mothershipParseApplicationMachineSelectionObject(doc, config, "config"_ctv, &failure) == false);
         suite.expect(failure == "config.gpuMemoryGB requires minGPUs > 0"_ctv, "mothership_parse_machine_resource_fields_gpu_memory_requires_gpus_failure_text");
      }

      suite.expect(rejected, "mothership_parse_machine_resource_fields_gpu_memory_requires_gpus");
   }

   {
      ApplicationConfig config{};
      String json = "{\"minGPUMemoryMB\":24576}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool rejected = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         String failure;
         rejected = (mothershipParseApplicationMachineSelectionObject(doc, config, "config"_ctv, &failure) == false);
         suite.expect(failure == "config.minGPUMemoryMB is not recognized"_ctv, "mothership_parse_machine_resource_fields_old_gpu_memory_field_rejected_text");
      }

      suite.expect(rejected, "mothership_parse_machine_resource_fields_old_gpu_memory_field_rejected");
   }

   {
      ApplicationConfig config{};
      String json = "{\"nHugepages2MB\":1}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool rejected = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         uint32_t seenMask = 0;
         for (auto field : doc.get_object())
         {
            String key = {};
            key.setInvariant(field.key);

            String sizeFailure = {};
            if (mothershipParseApplicationConfigSizeField(key, field.value, config, seenMask, "config"_ctv, &sizeFailure))
            {
               continue;
            }

            suite.expect(sizeFailure.size() == 0, "mothership_parse_nhugepages_removed_size_failure_empty");

            String criteriaFailure = {};
            if (mothershipParseApplicationMachineSelectionField(key, field.value, config, &criteriaFailure))
            {
               continue;
            }

            suite.expect(criteriaFailure.size() == 0, "mothership_parse_nhugepages_removed_machine_failure_empty");

            if (key == "nHugepages2MB"_ctv)
            {
               rejected = true;
            }
         }
      }

      suite.expect(rejected, "mothership_parse_nhugepages_removed_field_rejected");
   }

   {
      ApplicationConfig config{};
      String json = "{\"nThreads\":4}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool rejected = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         uint32_t seenMask = 0;
         for (auto field : doc.get_object())
         {
            String key = {};
            key.setInvariant(field.key);

            String sizeFailure = {};
            if (mothershipParseApplicationConfigSizeField(key, field.value, config, seenMask, "config"_ctv, &sizeFailure))
            {
               continue;
            }

            suite.expect(sizeFailure.size() == 0, "mothership_parse_nthreads_removed_size_failure_empty");

            String criteriaFailure = {};
            if (mothershipParseApplicationMachineSelectionField(key, field.value, config, &criteriaFailure))
            {
               continue;
            }

            suite.expect(criteriaFailure.size() == 0, "mothership_parse_nthreads_removed_machine_failure_empty");

            if (key == "nThreads"_ctv)
            {
               rejected = true;
            }
         }
      }

      suite.expect(rejected, "mothership_parse_nthreads_removed_field_rejected");
   }

   {
      ApplicationConfig config{};
      String json = "{\"memoryGB\":2,\"filesystemMB\":512,\"storageGB\":10}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      uint32_t seenMask = 0;
      bool parsedAll = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         String failure = {};
         parsedAll = true;
         for (auto field : doc.get_object())
         {
            String key = {};
            key.setInvariant(field.key);
            if (mothershipParseApplicationConfigSizeField(key, field.value, config, seenMask, "config"_ctv, &failure) == false)
            {
               parsedAll = false;
               break;
            }
         }

         suite.expect(failure.size() == 0, "mothership_parse_application_size_fields_mb_or_gb_no_failure");
      }

      suite.expect(parsedAll, "mothership_parse_application_size_fields_mb_or_gb");
      suite.expect(config.memoryMB == 2u * 1024u, "mothership_parse_application_size_fields_memory_gb_to_mb");
      suite.expect(config.filesystemMB == 512u, "mothership_parse_application_size_fields_filesystem_mb_preserved");
      suite.expect(config.storageMB == 10u * 1024u, "mothership_parse_application_size_fields_storage_gb_to_mb");
   }

   {
      ApplicationConfig config{};
      String json = "{\"memoryMB\":512,\"memoryGB\":1}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool rejected = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         uint32_t seenMask = 0;
         String failure = {};
         for (auto field : doc.get_object())
         {
            String key = {};
            key.setInvariant(field.key);
            if (mothershipParseApplicationConfigSizeField(key, field.value, config, seenMask, "config"_ctv, &failure) == false)
            {
               rejected = true;
               suite.expect(failure.size() > 0, "mothership_parse_application_size_fields_rejects_mixed_units_reason");
               break;
            }
         }
      }

      suite.expect(rejected, "mothership_parse_application_size_fields_rejects_mixed_units");
   }

   {
      DeploymentPlan plan{};
      String json = "{\"useHostNetworkNamespace\":true}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      const bool parsedJSON = (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS);
      suite.expect(parsedJSON, "mothership_parse_use_host_network_namespace_json_valid");

      bool parsedField = false;
      if (parsedJSON)
      {
         for (auto field : doc.get_object())
         {
            String key;
            key.setInvariant(field.key.data(), field.key.size());
            if (key == "useHostNetworkNamespace"_ctv)
            {
               String failure;
               parsedField = mothershipParseDeploymentPlanUseHostNetworkNamespace(field.value, plan, &failure);
               suite.expect(parsedField, "mothership_parse_use_host_network_namespace_accepts_bool");
               suite.expect(failure.size() == 0, "mothership_parse_use_host_network_namespace_clears_failure");
            }
         }
      }

      suite.expect(parsedField && plan.useHostNetworkNamespace == true, "mothership_parse_use_host_network_namespace_sets_plan");
   }

   {
      ApplicationConfig config{};
      String json = "{\"isolateCPUs\":true,\"nLogicalCores\":3}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool parsedIsolation = false;
      bool parsedCores = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         for (auto field : doc.get_object())
         {
            String key;
            key.setInvariant(field.key.data(), field.key.size());
            String failure;
            if (key == "isolateCPUs"_ctv)
            {
               parsedIsolation = mothershipParseApplicationCPUIsolationMode(field.value, config, &failure);
               suite.expect(parsedIsolation, "mothership_parse_isolated_cpu_mode_accepts_bool");
               suite.expect(failure.size() == 0, "mothership_parse_isolated_cpu_mode_no_failure");
            }
            else if (key == "nLogicalCores"_ctv)
            {
               parsedCores = mothershipParseApplicationCPURequest(field.value, config, &failure);
               suite.expect(parsedCores, "mothership_parse_isolated_cpu_request_accepts_integer");
               suite.expect(failure.size() == 0, "mothership_parse_isolated_cpu_request_no_failure");
            }
         }
      }

      suite.expect(parsedIsolation && parsedCores, "mothership_parse_isolated_cpu_fields_parse");
      suite.expect(config.cpuMode == ApplicationCPUMode::isolated, "mothership_parse_isolated_cpu_sets_mode");
      suite.expect(config.nLogicalCores == 3, "mothership_parse_isolated_cpu_sets_core_count");
      suite.expect(config.sharedCPUMillis == 0, "mothership_parse_isolated_cpu_clears_shared_millis");
   }

   {
      ApplicationConfig config{};
      String json = "{\"isolateCPUs\":false,\"nLogicalCores\":1.25}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool parsedIsolation = false;
      bool parsedCores = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         for (auto field : doc.get_object())
         {
            String key;
            key.setInvariant(field.key.data(), field.key.size());
            String failure;
            if (key == "isolateCPUs"_ctv)
            {
               parsedIsolation = mothershipParseApplicationCPUIsolationMode(field.value, config, &failure);
               suite.expect(parsedIsolation, "mothership_parse_shared_cpu_mode_accepts_bool");
               suite.expect(failure.size() == 0, "mothership_parse_shared_cpu_mode_no_failure");
            }
            else if (key == "nLogicalCores"_ctv)
            {
               parsedCores = mothershipParseApplicationCPURequest(field.value, config, &failure);
               suite.expect(parsedCores, "mothership_parse_shared_cpu_request_accepts_fractional_number");
               suite.expect(failure.size() == 0, "mothership_parse_shared_cpu_request_no_failure");
            }
         }
      }

      suite.expect(parsedIsolation && parsedCores, "mothership_parse_shared_cpu_fields_parse");
      suite.expect(config.cpuMode == ApplicationCPUMode::shared, "mothership_parse_shared_cpu_sets_mode");
      suite.expect(config.sharedCPUMillis == 1250, "mothership_parse_shared_cpu_sets_millis");
      suite.expect(config.nLogicalCores == 2, "mothership_parse_shared_cpu_sets_core_hint");
   }

   {
      ApplicationConfig config{};
      config.cpuMode = ApplicationCPUMode::isolated;
      String json = "{\"nLogicalCores\":128}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool parsedCores = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         for (auto field : doc.get_object())
         {
            String key;
            key.setInvariant(field.key.data(), field.key.size());
            if (key == "nLogicalCores"_ctv)
            {
               String failure;
               parsedCores = mothershipParseApplicationCPURequest(field.value, config, &failure);
               suite.expect(failure.size() == 0, "mothership_parse_large_isolated_cpu_no_failure");
            }
         }
      }

      suite.expect(parsedCores, "mothership_parse_large_isolated_cpu_accepts_integer");
      suite.expect(config.cpuMode == ApplicationCPUMode::isolated, "mothership_parse_large_isolated_cpu_keeps_mode");
      suite.expect(config.nLogicalCores == 128, "mothership_parse_large_isolated_cpu_sets_count");
      suite.expect(config.sharedCPUMillis == 0, "mothership_parse_large_isolated_cpu_clears_shared_millis");
   }

   {
      ApplicationConfig config{};
      config.cpuMode = ApplicationCPUMode::shared;
      String json = "{\"nLogicalCores\":64.5}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool parsedCores = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         for (auto field : doc.get_object())
         {
            String key;
            key.setInvariant(field.key.data(), field.key.size());
            if (key == "nLogicalCores"_ctv)
            {
               String failure;
               parsedCores = mothershipParseApplicationCPURequest(field.value, config, &failure);
               suite.expect(failure.size() == 0, "mothership_parse_large_shared_cpu_no_failure");
            }
         }
      }

      suite.expect(parsedCores, "mothership_parse_large_shared_cpu_accepts_fractional");
      suite.expect(config.cpuMode == ApplicationCPUMode::shared, "mothership_parse_large_shared_cpu_keeps_mode");
      suite.expect(config.sharedCPUMillis == 64500, "mothership_parse_large_shared_cpu_sets_millis");
      suite.expect(config.nLogicalCores == 65, "mothership_parse_large_shared_cpu_sets_core_hint");
   }

   {
      ApplicationConfig config{};
      config.cpuMode = ApplicationCPUMode::isolated;
      String json = "{\"nLogicalCores\":1.25}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool rejected = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         for (auto field : doc.get_object())
         {
            String key;
            key.setInvariant(field.key.data(), field.key.size());
            if (key == "nLogicalCores"_ctv)
            {
               String failure;
               rejected = (mothershipParseApplicationCPURequest(field.value, config, &failure) == false);
               suite.expect(failure == "config.nLogicalCores requires an integer when isolateCPUs=true"_ctv, "mothership_parse_isolated_cpu_rejects_fractional_failure_text");
            }
         }
      }

      suite.expect(rejected, "mothership_parse_isolated_cpu_rejects_fractional");
   }

   {
      String json = "{\"sharedCpuOvercommit\":1.5}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      uint16_t permille = 0;
      bool parsedField = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         for (auto field : doc.get_object())
         {
            String key;
            key.setInvariant(field.key.data(), field.key.size());
            if (key == "sharedCpuOvercommit"_ctv)
            {
               String failure;
               parsedField = mothershipParseSharedCPUOvercommitValue(field.value, permille, &failure);
               suite.expect(failure.size() == 0, "mothership_parse_shared_cpu_overcommit_no_failure");
            }
         }
      }

      suite.expect(parsedField, "mothership_parse_shared_cpu_overcommit_parses");
      suite.expect(permille == 1500, "mothership_parse_shared_cpu_overcommit_sets_permille");
   }

   {
      String json = "{\"sharedCpuOvercommit\":2.1}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      uint16_t permille = 0;
      bool rejected = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         for (auto field : doc.get_object())
         {
            String key;
            key.setInvariant(field.key.data(), field.key.size());
            if (key == "sharedCpuOvercommit"_ctv)
            {
               String failure;
               rejected = (mothershipParseSharedCPUOvercommitValue(field.value, permille, &failure) == false);
               suite.expect(failure == "sharedCpuOvercommit must be in 1.0..2.0"_ctv, "mothership_parse_shared_cpu_overcommit_rejects_out_of_range_failure_text");
            }
         }
      }

      suite.expect(rejected, "mothership_parse_shared_cpu_overcommit_rejects_out_of_range");
   }

   {
      Wormhole wormhole{};
      String json = "{\"quicCidKeyRotationHours\":36}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool parsedField = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         for (auto field : doc.get_object())
         {
            String key;
            key.setInvariant(field.key.data(), field.key.size());
            if (key == "quicCidKeyRotationHours"_ctv)
            {
               String failure;
               parsedField = mothershipParseWormholeQuicCidKeyRotationHours(field.value, wormhole, &failure);
               suite.expect(failure.size() == 0, "mothership_parse_wormhole_quic_rotation_hours_no_failure");
            }
         }
      }

      suite.expect(parsedField, "mothership_parse_wormhole_quic_rotation_hours_parses");
      suite.expect(wormhole.quicCidKeyState.rotationHours == 36, "mothership_parse_wormhole_quic_rotation_hours_sets_value");
   }

   {
      Wormhole wormhole{};
      String json = "{\"quicCidKeyRotationHours\":0}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      bool rejected = false;
      if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
      {
         for (auto field : doc.get_object())
         {
            String key;
            key.setInvariant(field.key.data(), field.key.size());
            if (key == "quicCidKeyRotationHours"_ctv)
            {
               String failure;
               rejected = (mothershipParseWormholeQuicCidKeyRotationHours(field.value, wormhole, &failure) == false);
               suite.expect(failure == "wormhole.quicCidKeyRotationHours must be > 0"_ctv, "mothership_parse_wormhole_quic_rotation_hours_zero_failure_text");
            }
         }
      }

      suite.expect(rejected, "mothership_parse_wormhole_quic_rotation_hours_rejects_zero");
   }

   {
      DeploymentPlan plan{};
      String json = "{\"useHostNetworkNamespace\":\"yes\"}"_ctv;
      json.need(simdjson::SIMDJSON_PADDING);

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      const bool parsedJSON = (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS);
      suite.expect(parsedJSON, "mothership_parse_use_host_network_namespace_invalid_json_valid");

      bool rejected = false;
      if (parsedJSON)
      {
         for (auto field : doc.get_object())
         {
            String key;
            key.setInvariant(field.key.data(), field.key.size());
            if (key == "useHostNetworkNamespace"_ctv)
            {
               String failure;
               rejected = (mothershipParseDeploymentPlanUseHostNetworkNamespace(field.value, plan, &failure) == false);
               suite.expect(rejected, "mothership_parse_use_host_network_namespace_rejects_non_bool");
               suite.expect(failure == "useHostNetworkNamespace requires a bool"_ctv, "mothership_parse_use_host_network_namespace_failure_text");
            }
         }
      }

      suite.expect(rejected, "mothership_parse_use_host_network_namespace_invalid_type_detected");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.nTargetBase = 3;
      deployment.nTargetSurge = 2;
      deployment.nTargetCanary = 1;

      deployment.nDeployedBase = 2;
      deployment.nDeployedSurge = 1;
      deployment.nDeployedCanary = 1;

      deployment.nHealthyBase = 2;
      deployment.nHealthySurge = 1;
      deployment.nHealthyCanary = 0;

      suite.expect(deployment.nTarget() == 6, "deployment_nTarget_sum");
      suite.expect(deployment.nDeployed() == 4, "deployment_nDeployed_sum");
      suite.expect(deployment.nHealthy() == 3, "deployment_nHealthy_sum");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);

      uint32_t fit = ApplicationDeployment::nFitOntoResources(&deployment, 9, 0, 4'096, 4'096, {}, 10);
      suite.expect(fit == 4, "nFitOntoResources_core_bound");

      fit = ApplicationDeployment::nFitOntoResources(&deployment, 99, 0, 0, 99, {}, 10);
      suite.expect(fit == 0, "nFitOntoResources_zero_memory");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);

      Rack rack{};
      rack.uuid = 77;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 8;
      machine.memoryMB_available = 4'096;
      machine.storageMB_available = 4'096;

      uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 20);
      suite.expect(fit == 4, "nFitOnMachine_resource_bound");

      MachineResourcesDelta negativeDelta{};
      negativeDelta.nLogicalCores = -16;
      fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 20, negativeDelta);
      suite.expect(fit == 0, "nFitOnMachine_negative_delta_clamped");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.plan.config.minGPUs = 2;
      deployment.plan.config.gpuMemoryGB = 16;

      Rack rack{};
      rack.uuid = 7701;

      Machine machine;
      machine.slug = "gpu-capable"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 32;
      machine.memoryMB_available = 64'000;
      machine.storageMB_available = 64'000;
      machine.hardware.gpus.push_back(MachineGpuHardwareProfile{.memoryMB = 16 * 1024u});
      machine.hardware.gpus.push_back(MachineGpuHardwareProfile{.memoryMB = 16 * 1024u});
      machine.resetAvailableGPUMemoryMBsFromHardware();

      uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
      suite.expect(fit == 1, "nFitOnMachine_gpu_criteria_accepts_machine_capability_and_available_gpus");

      machine.availableGPUMemoryMBs.erase(machine.availableGPUMemoryMBs.begin());
      fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
      suite.expect(fit == 0, "nFitOnMachine_gpu_criteria_rejects_when_available_gpus_consumed");

      machine.hardware.gpus[1].memoryMB = 12 * 1024u;
      machine.resetAvailableGPUMemoryMBsFromHardware();
      fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
      suite.expect(fit == 0, "nFitOnMachine_gpu_criteria_rejects_machine_without_required_per_gpu_memory");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.plan.config.nicSpeedGbps = 10;
      deployment.plan.config.minInternetDownloadMbps = 800;
      deployment.plan.config.minInternetUploadMbps = 400;
      deployment.plan.config.maxInternetLatencyMs = 25;

      Rack rack{};
      rack.uuid = 7702;

      Machine machine;
      machine.slug = "network-qualified"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 8;
      machine.memoryMB_available = 4'096;
      machine.storageMB_available = 4'096;
      machine.hasInternetAccess = true;
      machine.hardware.network.nics.push_back(MachineNicHardwareProfile{.linkSpeedMbps = 25'000});
      machine.hardware.network.internet.attempted = true;
      machine.hardware.network.internet.downloadMbps = 900;
      machine.hardware.network.internet.uploadMbps = 500;
      machine.hardware.network.internet.latencyMs = 15;

      uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
      suite.expect(fit == 4, "nFitOnMachine_machine_resource_criteria_accepts_matching_nic_and_internet_profile");

      machine.hardware.network.nics[0].linkSpeedMbps = 1'000;
      fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
      suite.expect(fit == 0, "nFitOnMachine_machine_resource_criteria_rejects_insufficient_nic_speed");

      machine.hardware.network.nics[0].linkSpeedMbps = 25'000;
      machine.hardware.network.internet.downloadMbps = 600;
      fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
      suite.expect(fit == 0, "nFitOnMachine_machine_resource_criteria_rejects_insufficient_internet_download");

      machine.hardware.network.internet.downloadMbps = 900;
      machine.hardware.network.internet.latencyMs = 40;
      fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
      suite.expect(fit == 0, "nFitOnMachine_machine_resource_criteria_rejects_excessive_internet_latency");
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack rack{};
      rack.uuid = 7801;

      Machine worker;
      worker.uuid = uint128_t(0x1001);
      worker.fragment = 0x000011u;
      worker.slug = "worker-private"_ctv;
      worker.rack = &rack;
      worker.state = MachineState::healthy;
      worker.nLogicalCores_available = 8;
      worker.memoryMB_available = 4'096;
      worker.storageMB_available = 4'096;

      worker.hasInternetAccess = true;
      worker.hardware.network.internet.sourceAddress = IPAddress("192.168.50.10", false);
      brain.machines.insert(&worker);

      MachineConfig workerConfig = {};
      workerConfig.slug = worker.slug;
      brain.brainConfig.configBySlug.insert_or_assign(worker.slug, workerConfig);

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);

      Whitehole whitehole = {};
      whitehole.transport = ExternalAddressTransport::tcp;
      whitehole.family = ExternalAddressFamily::ipv4;
      whitehole.source = ExternalAddressSource::hostPublicAddress;
      deployment.plan.whiteholes.push_back(whitehole);

      uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &worker, 1);
      suite.expect(fit == 1, "nFitOnMachine_whitehole_host_public_accepts_machine_local_internet_source");

      worker.hasInternetAccess = false;
      fit = ApplicationDeployment::nFitOnMachine(&deployment, &worker, 1);
      suite.expect(fit == 0, "nFitOnMachine_whitehole_host_public_rejects_machine_without_internet_access");

      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack rack{};
      rack.uuid = 7802;

      Machine worker;
      worker.uuid = uint128_t(0x1002);
      worker.fragment = 0x000012u;
      worker.slug = "worker-distributed"_ctv;
      worker.rack = &rack;
      worker.state = MachineState::healthy;
      worker.nLogicalCores_available = 8;
      worker.memoryMB_available = 4'096;
      worker.storageMB_available = 4'096;
      worker.hasInternetAccess = true;
      brain.machines.insert(&worker);

      MachineConfig workerConfig = {};
      workerConfig.slug = worker.slug;
      brain.brainConfig.configBySlug.insert_or_assign(worker.slug, workerConfig);

      DistributableExternalSubnet subnet = {};
      subnet.name = "whitehole-ipv4"_ctv;
      subnet.subnet.network = IPAddress("198.18.0.0", false);
      subnet.subnet.cidr = 16;
      subnet.subnet.canonicalize();
      subnet.usage = ExternalSubnetUsage::whiteholes;
      brain.brainConfig.distributableExternalSubnets.push_back(subnet);

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);

      Whitehole whitehole = {};
      whitehole.transport = ExternalAddressTransport::tcp;
      whitehole.family = ExternalAddressFamily::ipv4;
      whitehole.source = ExternalAddressSource::distributableSubnet;
      deployment.plan.whiteholes.push_back(whitehole);

      uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &worker, 1);
      suite.expect(fit == 1, "nFitOnMachine_whitehole_distributable_subnet_accepts_whitehole_subnet_usage");

      brain.brainConfig.distributableExternalSubnets[0].usage = ExternalSubnetUsage::wormholes;
      fit = ApplicationDeployment::nFitOnMachine(&deployment, &worker, 1);
      suite.expect(fit == 0, "nFitOnMachine_whitehole_distributable_subnet_rejects_wormhole_only_subnet_usage");

      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack hostRack{};
      hostRack.uuid = 7803;
      Rack otherRack{};
      otherRack.uuid = 7804;

      Machine host{};
      host.uuid = uint128_t(0x1003);
      host.fragment = 0x000013u;
      host.slug = "wormhole-host"_ctv;
      host.rack = &hostRack;
      host.state = MachineState::healthy;
      host.nLogicalCores_available = 8;
      host.memoryMB_available = 4'096;
      host.storageMB_available = 4'096;
      brain.machines.insert(&host);

      Machine other{};
      other.uuid = uint128_t(0x1004);
      other.fragment = 0x000014u;
      other.slug = "wormhole-other"_ctv;
      other.rack = &otherRack;
      other.state = MachineState::healthy;
      other.nLogicalCores_available = 8;
      other.memoryMB_available = 4'096;
      other.storageMB_available = 4'096;
      brain.machines.insert(&other);

      RegisteredRoutableAddress registered = {};
      registered.uuid = uint128_t(0xABCD1004);
      registered.name = "wormhole-route"_ctv;
      registered.family = ExternalAddressFamily::ipv6;
      registered.kind = RoutableAddressKind::anyHostPublicAddress;
      registered.machineUUID = host.uuid;
      registered.address = IPAddress("2001:db8:100::44", true);
      brain.brainConfig.routableAddresses.push_back(registered);

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);

      Wormhole wormhole = {};
      wormhole.externalPort = 443;
      wormhole.containerPort = 8443;
      wormhole.layer4 = IPPROTO_UDP;
      wormhole.isQuic = true;
      wormhole.source = ExternalAddressSource::registeredRoutableAddress;
      wormhole.routableAddressUUID = registered.uuid;
      deployment.plan.wormholes.push_back(wormhole);

      uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &host, 1);
      suite.expect(fit == 1, "nFitOnMachine_wormhole_registered_routable_address_accepts_owning_machine");

      fit = ApplicationDeployment::nFitOnMachine(&deployment, &other, 1);
      suite.expect(fit == 0, "nFitOnMachine_wormhole_registered_routable_address_rejects_non_owning_machine");

      thisBrain = savedBrain;
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);

      Rack rack{};
      rack.uuid = 78;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 10'000;
      machine.memoryMB_available = 10'000'000;
      machine.storageMB_available = 10'000'000;

      Vector<ContainerView *> seededContainers;
      for (uint32_t index = 0; index < 255; ++index)
      {
         ContainerView *container = new ContainerView();
         container->deploymentID = deployment.plan.config.deploymentID();
         machine.upsertContainerIndexEntry(container->deploymentID, container);
         seededContainers.push_back(container);
      }

      uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 10);
      suite.expect(fit == 1, "nFitOnMachine_container_slot_budget_one_remaining");

      ContainerView *finalContainer = new ContainerView();
      finalContainer->deploymentID = deployment.plan.config.deploymentID();
      machine.upsertContainerIndexEntry(finalContainer->deploymentID, finalContainer);
      seededContainers.push_back(finalContainer);

      fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 10);
      suite.expect(fit == 0, "nFitOnMachine_container_slot_budget_exhausted");

      for (ContainerView *container : seededContainers)
      {
         machine.removeContainerIndexEntry(container->deploymentID, container);
         delete container;
      }
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);

      Rack rack{};
      rack.uuid = 79;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 10'000;
      machine.memoryMB_available = 10'000'000;
      machine.storageMB_available = 10'000'000;

      Machine::Claim claim{};
      claim.nFit = 255;
      machine.claims.push_back(claim);

      uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 10);
      suite.expect(fit == 1, "nFitOnMachine_pending_claims_consume_container_slots");

      machine.claims[0].nFit = Machine::maxSchedulableContainers;
      fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 10);
      suite.expect(fit == 0, "nFitOnMachine_pending_claims_exhaust_container_slots");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.nTargetBase = 10;
      deployment.plan.stateless.maxPerRackRatio = 0.5f;     // ceil(10 * 0.5) = 5
      deployment.plan.stateless.maxPerMachineRatio = 0.2f;  // ceil(10 * 0.2) = 2

      Rack rack{};
      rack.uuid = 88;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;

      deployment.countPerRack[&rack] = 3;
      deployment.countPerMachine[&machine] = 1;

      uint32_t budget = ApplicationDeployment::clampBudgetByRackAndMachine(&deployment, &machine, 99);
      suite.expect(budget == 2, "clampBudgetByRackAndMachine_min_budget");

      deployment.countPerRack[&rack] = 5;
      budget = ApplicationDeployment::clampBudgetByRackAndMachine(&deployment, &machine, 99);
      suite.expect(budget == 0, "clampBudgetByRackAndMachine_exhausted_rack");

      deployment.plan.stateless.maxPerRackRatio = 0.0f;
      deployment.plan.stateless.maxPerMachineRatio = 0.0f;
      budget = ApplicationDeployment::clampBudgetByRackAndMachine(&deployment, &machine, 99);
      suite.expect(budget == 0, "clampBudgetByRackAndMachine_zero_ratio");

      deployment.nTargetBase = 3;
      deployment.plan.stateless.maxPerRackRatio = 0.01f;
      deployment.plan.stateless.maxPerMachineRatio = 0.01f;
      deployment.countPerRack[&rack] = 0;
      deployment.countPerMachine[&machine] = 0;
      budget = ApplicationDeployment::clampBudgetByRackAndMachine(&deployment, &machine, 99);
      suite.expect(budget == 1, "clampBudgetByRackAndMachine_minimum_one_when_nonzero_ratio");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.nTargetBase = 4;

      Rack rack{};
      rack.uuid = 99;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 8;
      machine.memoryMB_available = 4'096;
      machine.storageMB_available = 4'096;

      MachineTicket ticket{};
      uint32_t fit = deployment.nFitOnMachineClaim(&ticket, &machine, 3);

      suite.expect(fit == 3, "nFitOnMachineClaim_stateless_fit");
      suite.expect(machine.claims.size() == 1, "nFitOnMachineClaim_stateless_claim_recorded");
      suite.expect(machine.claims[0].ticket == &ticket, "nFitOnMachineClaim_stateless_ticket_linked");
      suite.expect(deployment.countPerMachine.getIf(&machine) == 3, "nFitOnMachineClaim_stateless_counts_machine");
      suite.expect(deployment.countPerRack.getIf(&rack) == 3, "nFitOnMachineClaim_stateless_counts_rack");
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack hostRack{};
      hostRack.uuid = 1002;
      Rack otherRack{};
      otherRack.uuid = 1003;

      Machine host{};
      host.uuid = uint128_t(0x2201);
      host.fragment = 0x000021u;
      host.slug = "claim-host"_ctv;
      host.rack = &hostRack;
      host.state = MachineState::healthy;
      host.nLogicalCores_available = 8;
      host.memoryMB_available = 4'096;
      host.storageMB_available = 4'096;

      Machine other{};
      other.uuid = uint128_t(0x2202);
      other.fragment = 0x000022u;
      other.slug = "claim-other"_ctv;
      other.rack = &otherRack;
      other.state = MachineState::healthy;
      other.nLogicalCores_available = 8;
      other.memoryMB_available = 4'096;
      other.storageMB_available = 4'096;

      RegisteredRoutableAddress registered = {};
      registered.uuid = uint128_t(0x2203);
      registered.name = "claim-route"_ctv;
      registered.family = ExternalAddressFamily::ipv6;
      registered.kind = RoutableAddressKind::anyHostPublicAddress;
      registered.machineUUID = host.uuid;
      registered.address = IPAddress("2001:db8:100::45", true);
      brain.brainConfig.routableAddresses.push_back(registered);

      ApplicationDeployment hostDeployment;
      seedCommonPlan(hostDeployment, false);
      hostDeployment.nTargetBase = 2;

      Wormhole wormhole = {};
      wormhole.externalPort = 443;
      wormhole.containerPort = 8443;
      wormhole.layer4 = IPPROTO_UDP;
      wormhole.isQuic = true;
      wormhole.source = ExternalAddressSource::registeredRoutableAddress;
      wormhole.routableAddressUUID = registered.uuid;
      hostDeployment.plan.wormholes.push_back(wormhole);

      MachineTicket hostTicket{};
      uint32_t fit = hostDeployment.nFitOnMachineClaim(&hostTicket, &host, 2);
      suite.expect(fit == 2, "nFitOnMachineClaim_wormhole_registered_routable_address_claims_owning_machine");

      ApplicationDeployment otherDeployment;
      seedCommonPlan(otherDeployment, false);
      otherDeployment.nTargetBase = 2;
      otherDeployment.plan.wormholes.push_back(wormhole);

      MachineTicket otherTicket{};
      fit = otherDeployment.nFitOnMachineClaim(&otherTicket, &other, 2);
      suite.expect(fit == 0, "nFitOnMachineClaim_wormhole_registered_routable_address_rejects_non_owning_machine");

      thisBrain = savedBrain;
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.nTargetBase = 300;

      Rack rack{};
      rack.uuid = 100;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 10'000;
      machine.memoryMB_available = 10'000'000;
      machine.storageMB_available = 10'000'000;

      Vector<ContainerView *> seededContainers;
      for (uint32_t index = 0; index < 255; ++index)
      {
         ContainerView *container = new ContainerView();
         container->deploymentID = deployment.plan.config.deploymentID();
         machine.upsertContainerIndexEntry(container->deploymentID, container);
         seededContainers.push_back(container);
      }

      MachineTicket firstTicket{};
      uint32_t fit = deployment.nFitOnMachineClaim(&firstTicket, &machine, 10);
      suite.expect(fit == 1, "nFitOnMachineClaim_container_slot_budget_last_slot");
      suite.expect(machine.claims.size() == 1 && machine.claims[0].nFit == 1, "nFitOnMachineClaim_records_last_slot_claim");

      MachineTicket secondTicket{};
      fit = deployment.nFitOnMachineClaim(&secondTicket, &machine, 10);
      suite.expect(fit == 0, "nFitOnMachineClaim_container_slot_budget_exhausted");

      for (ContainerView *container : seededContainers)
      {
         machine.removeContainerIndexEntry(container->deploymentID, container);
         delete container;
      }
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.plan.config.minGPUs = 1;
      deployment.plan.config.gpuMemoryGB = 24;
      deployment.nTargetBase = 4;

      Rack rack{};
      rack.uuid = 1001;

      Machine machine;
      machine.slug = "gpu-claim"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 64;
      machine.memoryMB_available = 128'000;
      machine.storageMB_available = 128'000;
      MachineGpuHardwareProfile firstGPU = {};
      firstGPU.vendor = "nvidia"_ctv;
      firstGPU.model = "A10"_ctv;
      firstGPU.busAddress = "0000:17:00.0"_ctv;
      firstGPU.memoryMB = 24 * 1024u;
      machine.hardware.gpus.push_back(firstGPU);
      MachineGpuHardwareProfile secondGPU = {};
      secondGPU.vendor = "nvidia"_ctv;
      secondGPU.model = "A16"_ctv;
      secondGPU.busAddress = "0000:65:00.0"_ctv;
      secondGPU.memoryMB = 48 * 1024u;
      machine.hardware.gpus.push_back(secondGPU);
      machine.resetAvailableGPUMemoryMBsFromHardware();

      MachineTicket firstTicket{};
      uint32_t fit = deployment.nFitOnMachineClaim(&firstTicket, &machine, 3);
      suite.expect(fit == 2, "nFitOnMachineClaim_gpu_capacity_uses_whole_gpus");
      suite.expect(machine.claims.size() == 1, "nFitOnMachineClaim_gpu_capacity_claim_recorded");
      suite.expect(machine.claims[0].reservedGPUMemoryMBs.size() == 2, "nFitOnMachineClaim_gpu_capacity_reserves_each_gpu_whole");
      suite.expect(machine.claims[0].reservedGPUDevices.size() == 2, "nFitOnMachineClaim_gpu_capacity_reserves_gpu_device_identity");
      suite.expect(machine.claims[0].reservedGPUDevices[0].busAddress == "0000:17:00.0"_ctv && machine.claims[0].reservedGPUDevices[1].busAddress == "0000:65:00.0"_ctv, "nFitOnMachineClaim_gpu_capacity_preserves_gpu_bus_addresses");
      suite.expect(machine.availableGPUMemoryMBs.empty(), "nFitOnMachineClaim_gpu_capacity_consumes_all_free_gpus");
      suite.expect(machine.availableGPUHardwareIndexes.empty(), "nFitOnMachineClaim_gpu_capacity_consumes_all_free_gpu_indexes");

      MachineTicket secondTicket{};
      fit = deployment.nFitOnMachineClaim(&secondTicket, &machine, 1);
      suite.expect(fit == 0, "nFitOnMachineClaim_gpu_capacity_rejects_shared_gpu_overcommit");
   }

   {
      bytell_hash_map<String, MachineConfig> configBySlug;

      MachineConfig wide{};
      wide.slug = "wide"_ctv;
      wide.nLogicalCores = 4;
      wide.nMemoryMB = 2'048;
      wide.nStorageMB = 128;
      configBySlug.insert_or_assign(wide.slug, wide);

      MachineConfig dense{};
      dense.slug = "dense"_ctv;
      dense.nLogicalCores = 8;
      dense.nMemoryMB = 2'048;
      dense.nStorageMB = 256;
      configBySlug.insert_or_assign(dense.slug, dense);

      MachineConfig denseTie{};
      denseTie.slug = "dense-a"_ctv;
      denseTie.nLogicalCores = 8;
      denseTie.nMemoryMB = 2'048;
      denseTie.nStorageMB = 256;
      configBySlug.insert_or_assign(denseTie.slug, denseTie);

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);

      String selectedSlug;
      const MachineConfig *selectedConfig = nullptr;
      bool found = Brain::selectScaleOutMachineConfig(configBySlug, deployment.plan.config, 3, selectedSlug, selectedConfig);

      suite.expect(found, "selectScaleOutMachineConfig_finds_resource_fit");
      suite.expect(selectedConfig != nullptr, "selectScaleOutMachineConfig_returns_machine_config");
      suite.expect(selectedSlug == "dense"_ctv, "selectScaleOutMachineConfig_prefers_lowest_waste_then_slug");
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;
      brain.brainConfig.sharedCPUOvercommitPermille = 1500;

      bytell_hash_map<String, MachineConfig> configBySlug;

      MachineConfig compact{};
      compact.slug = "compact"_ctv;
      compact.nLogicalCores = 4;
      compact.nMemoryMB = 4096;
      compact.nStorageMB = 256;
      configBySlug.insert_or_assign(compact.slug, compact);

      MachineConfig wide{};
      wide.slug = "wide"_ctv;
      wide.nLogicalCores = 6;
      wide.nMemoryMB = 4096;
      wide.nStorageMB = 256;
      configBySlug.insert_or_assign(wide.slug, wide);

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.plan.config.cpuMode = ApplicationCPUMode::shared;
      deployment.plan.config.sharedCPUMillis = 1200;
      deployment.plan.config.nLogicalCores = 2;

      String selectedSlug;
      const MachineConfig *selectedConfig = nullptr;
      bool found = Brain::selectScaleOutMachineConfig(configBySlug, deployment.plan.config, 5, selectedSlug, selectedConfig);

      suite.expect(found, "selectScaleOutMachineConfig_shared_cpu_finds_resource_fit");
      suite.expect(selectedConfig != nullptr, "selectScaleOutMachineConfig_shared_cpu_returns_machine_config");
      suite.expect(selectedSlug == "compact"_ctv, "selectScaleOutMachineConfig_shared_cpu_uses_overcommit_capacity");

      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;
      brain.brainConfig.sharedCPUOvercommitPermille = 1500;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.plan.config.cpuMode = ApplicationCPUMode::shared;
      deployment.plan.config.sharedCPUMillis = 1000;
      deployment.plan.config.nLogicalCores = 1;

      Machine machine = {};
      machine.ownedLogicalCores = 4;
      prodigyRecomputeMachineCPUAvailability(&machine, 1500);
      suite.expect(machine.sharedCPUMillis_available == 6000, "shared_cpu_overcommit_initial_shared_capacity");
      suite.expect(machine.nLogicalCores_available == 4, "shared_cpu_overcommit_initial_isolated_capacity");

      machine.sharedCPUMillisCommitted = 6000;
      prodigyRecomputeMachineCPUAvailability(&machine, 1500);
      suite.expect(machine.sharedCPUMillis_available == 0, "shared_cpu_overcommit_full_capacity_consumed");
      suite.expect(machine.nLogicalCores_available == 0, "shared_cpu_overcommit_full_capacity_removes_isolated_headroom");

      prodigyRecomputeMachineCPUAvailability(&machine, 1000);
      suite.expect(prodigyMachineUsesCPUOvercommit(&machine), "shared_cpu_overcommit_lowered_marks_machine_overcommitted");
      suite.expect(machine.sharedCPUMillis_available < 0, "shared_cpu_overcommit_lowered_leaves_negative_headroom");
      suite.expect(machine.sharedCPUMillisCommitted == 6000, "shared_cpu_overcommit_lowered_does_not_change_committed_shared_cpu");
      suite.expect(machine.isolatedLogicalCoresCommitted == 0, "shared_cpu_overcommit_lowered_does_not_move_isolated_cpu_ownership");

      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;
      brain.brainConfig.sharedCPUOvercommitPermille = 1500;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.plan.config.cpuMode = ApplicationCPUMode::shared;
      deployment.plan.config.sharedCPUMillis = 1000;
      deployment.plan.config.nLogicalCores = 1;

      Rack rackA{};
      rackA.uuid = 2001;
      Rack rackB{};
      rackB.uuid = 2002;

      Machine overcommitted = {};
      overcommitted.uuid = uint128_t(0x2001);
      overcommitted.slug = "overcommitted"_ctv;
      overcommitted.rack = &rackA;
      overcommitted.ownedLogicalCores = 4;
      overcommitted.sharedCPUMillisCommitted = 4500;
      overcommitted.memoryMB_available = 8192;
      overcommitted.storageMB_available = 8192;
      prodigyRecomputeMachineCPUAvailability(&overcommitted, 1500);

      Machine healthy = {};
      healthy.uuid = uint128_t(0x2002);
      healthy.slug = "healthy"_ctv;
      healthy.rack = &rackB;
      healthy.ownedLogicalCores = 4;
      healthy.memoryMB_available = 8192;
      healthy.storageMB_available = 8192;
      prodigyRecomputeMachineCPUAvailability(&healthy, 1500);

      suite.expect(
         prodigySharedCPUSchedulingMachineComesBefore(&healthy, nullptr, &overcommitted, nullptr),
         "shared_cpu_machine_order_prefers_non_overcommitted_machine");

      MachineResourcesDelta healthyDelta = {};
      healthyDelta.sharedCPUMillis = -7000;
      suite.expect(
         prodigySharedCPUSchedulingMachineComesBefore(&overcommitted, nullptr, &healthy, &healthyDelta),
         "shared_cpu_machine_order_uses_effective_post_delta_state");
      thisBrain = savedBrain;
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);

      Rack rack{};
      rack.uuid = 123;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 8;
      machine.memoryMB_available = 4'096;
      machine.storageMB_available = 4'096;

      MachineTicket ticket{};
      ticket.shardGroups.push_back(11);
      ticket.shardGroups.push_back(22);

      uint32_t fit = deployment.nFitOnMachineClaim(&ticket, &machine, 2);
      suite.expect(fit == 2, "nFitOnMachineClaim_stateful_fit");
      suite.expect(ticket.shardGroups.size() == 0, "nFitOnMachineClaim_stateful_consumes_ticket_groups");
      suite.expect(deployment.racksByShardGroup[11].contains(&rack), "nFitOnMachineClaim_stateful_tracks_rack_11");
      suite.expect(deployment.racksByShardGroup[22].contains(&rack), "nFitOnMachineClaim_stateful_tracks_rack_22");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);

      Rack rack{};
      rack.uuid = 124;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 8;
      machine.memoryMB_available = 4'096;
      machine.storageMB_available = 4'096;

      MachineTicket ticket{};
      ticket.shardGroups.push_back(11);
      ticket.shardGroups.push_back(22);
      deployment.racksByShardGroup[11].insert(&rack);

      uint32_t fit = deployment.nFitOnMachineClaim(&ticket, &machine, 2);
      suite.expect(fit == 1, "nFitOnMachineClaim_stateful_skips_existing_rack_group");
      suite.expect(ticket.shardGroups.size() == 1, "nFitOnMachineClaim_stateful_leaves_unmoved_groups");
      suite.expect(ticket.shardGroups[0] == 11, "nFitOnMachineClaim_stateful_preserves_conflicting_group");
      suite.expect(deployment.racksByShardGroup[22].contains(&rack), "nFitOnMachineClaim_stateful_tracks_new_group_only");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.nTargetBase = 4;
      deployment.plan.stateless.maxPerRackRatio = 1.0f;
      deployment.plan.stateless.maxPerMachineRatio = 0.25f;

      Rack rack{};
      rack.uuid = 125;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 8;
      machine.memoryMB_available = 4'096;
      machine.storageMB_available = 4'096;

      deployment.countPerMachine[&machine] = 1;
      deployment.countPerRack[&rack] = 0;

      MachineTicket ticket{};
      uint32_t fit = deployment.nFitOnMachineClaim(&ticket, &machine, 3);
      suite.expect(fit == 0, "nFitOnMachineClaim_stateless_machine_ratio_budget_zero");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.nTargetBase = 2;

      Rack rack{};
      Machine machine;
      machine.slug = "other-type"_ctv;
      machine.rack = &rack;
      machine.nLogicalCores_available = 8;
      machine.memoryMB_available = 4'096;
      machine.storageMB_available = 4'096;

      MachineTicket ticket{};
      uint32_t fit = deployment.nFitOnMachineClaim(&ticket, &machine, 2);
      suite.expect(fit == 2, "nFitOnMachineClaim_ignores_machine_slug_when_resources_fit");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);

      uint32_t fit = ApplicationDeployment::nFitOntoResources(&deployment, 200, 0, 200'000, 63, {}, 200);
      suite.expect(fit == 0, "nFitOntoResources_storage_bound");
   }

   {
      ApplicationDeployment deployment;
      deployment.plan.moveConstructively = true;

      DeploymentWork cwork;
      cwork.emplace<StatelessWork>();
      std::get<StatelessWork>(cwork).lifecycle = LifecycleOp::construct;
      DeploymentWork dwork;
      dwork.emplace<StatelessWork>();
      std::get<StatelessWork>(dwork).lifecycle = LifecycleOp::destruct;

      deployment.scheduleConstructionDestruction(&cwork, &dwork);

      suite.expect(deployment.toSchedule.size() == 2, "scheduleConstructionDestruction_constructive_count");
      suite.expect(deployment.toSchedule[0] == &cwork && deployment.toSchedule[1] == &dwork, "scheduleConstructionDestruction_constructive_order");
      suite.expect(std::get<StatelessWork>(cwork).next == &dwork, "scheduleConstructionDestruction_constructive_next");
      suite.expect(std::get<StatelessWork>(dwork).prev == &cwork, "scheduleConstructionDestruction_constructive_prev");
   }

   {
      ApplicationDeployment deployment;
      deployment.plan.moveConstructively = false;

      DeploymentWork cwork;
      cwork.emplace<StatelessWork>();
      std::get<StatelessWork>(cwork).lifecycle = LifecycleOp::construct;
      DeploymentWork dwork;
      dwork.emplace<StatelessWork>();
      std::get<StatelessWork>(dwork).lifecycle = LifecycleOp::destruct;

      deployment.scheduleConstructionDestruction(&cwork, &dwork);

      suite.expect(deployment.toSchedule.size() == 2, "scheduleConstructionDestruction_destructive_count");
      suite.expect(deployment.toSchedule[0] == &dwork && deployment.toSchedule[1] == &cwork, "scheduleConstructionDestruction_destructive_order");
      suite.expect(std::get<StatelessWork>(dwork).next == &cwork, "scheduleConstructionDestruction_destructive_next");
      suite.expect(std::get<StatelessWork>(cwork).prev == &dwork, "scheduleConstructionDestruction_destructive_prev");
   }

   {
      ApplicationDeployment deployment;
      deployment.plan.moveConstructively = true;

      DeploymentWork cwork;
      cwork.emplace<StatefulWork>();
      std::get<StatefulWork>(cwork).lifecycle = LifecycleOp::construct;
      DeploymentWork dwork;
      dwork.emplace<StatefulWork>();
      std::get<StatefulWork>(dwork).lifecycle = LifecycleOp::destruct;

      deployment.scheduleConstructionDestruction(&cwork, &dwork);

      suite.expect(deployment.toSchedule.size() == 2, "scheduleConstructionDestruction_stateful_constructive_count");
      suite.expect(deployment.toSchedule[0] == &cwork && deployment.toSchedule[1] == &dwork, "scheduleConstructionDestruction_stateful_constructive_order");
      suite.expect(std::get<StatefulWork>(cwork).next == &dwork, "scheduleConstructionDestruction_stateful_constructive_next");
      suite.expect(std::get<StatefulWork>(dwork).prev == &cwork, "scheduleConstructionDestruction_stateful_constructive_prev");
   }

   {
      ApplicationDeployment deployment;
      deployment.plan.moveConstructively = false;

      DeploymentWork cwork;
      cwork.emplace<StatefulWork>();
      std::get<StatefulWork>(cwork).lifecycle = LifecycleOp::construct;
      DeploymentWork dwork;
      dwork.emplace<StatefulWork>();
      std::get<StatefulWork>(dwork).lifecycle = LifecycleOp::destruct;

      deployment.scheduleConstructionDestruction(&cwork, &dwork);

      suite.expect(deployment.toSchedule.size() == 2, "scheduleConstructionDestruction_stateful_destructive_count");
      suite.expect(deployment.toSchedule[0] == &dwork && deployment.toSchedule[1] == &cwork, "scheduleConstructionDestruction_stateful_destructive_order");
      suite.expect(std::get<StatefulWork>(dwork).next == &cwork, "scheduleConstructionDestruction_stateful_destructive_next");
      suite.expect(std::get<StatefulWork>(cwork).prev == &dwork, "scheduleConstructionDestruction_stateful_destructive_prev");
   }

   {
      ApplicationDeployment deployment;

      DeploymentWork cwork;
      cwork.emplace<StatelessWork>();
      std::get<StatelessWork>(cwork).lifecycle = LifecycleOp::construct;

      deployment.scheduleConstructionDestruction(&cwork, nullptr);
      suite.expect(deployment.toSchedule.size() == 1 && deployment.toSchedule[0] == &cwork, "scheduleConstructionDestruction_construct_only");
   }

   {
      ApplicationDeployment deployment;
      deployment.state = DeploymentState::running;
      suite.expect(deployment.statelessCompactionDonorIsQuiescent(), "statelessCompactionDonorIsQuiescent_running_idle_true");

      deployment.state = DeploymentState::deploying;
      suite.expect(deployment.statelessCompactionDonorIsQuiescent() == false, "statelessCompactionDonorIsQuiescent_deploying_false");

      deployment.state = DeploymentState::running;
      ContainerView waiting;
      deployment.waitingOnContainers.insert_or_assign(&waiting, ContainerState::healthy);
      suite.expect(deployment.statelessCompactionDonorIsQuiescent() == false, "statelessCompactionDonorIsQuiescent_waiting_false");
      deployment.waitingOnContainers.clear();

      DeploymentWork pendingWork;
      pendingWork.emplace<StatelessWork>();
      deployment.toSchedule.push_back(&pendingWork);
      suite.expect(deployment.statelessCompactionDonorIsQuiescent() == false, "statelessCompactionDonorIsQuiescent_scheduled_work_false");
      deployment.toSchedule.clear();

      deployment.waitingOnCompactions = true;
      suite.expect(deployment.statelessCompactionDonorIsQuiescent() == false, "statelessCompactionDonorIsQuiescent_compaction_wait_false");
      deployment.waitingOnCompactions = false;

      CoroutineStack coro;
      deployment.schedulingStack.execution = &coro;
      suite.expect(deployment.statelessCompactionDonorIsQuiescent() == false, "statelessCompactionDonorIsQuiescent_active_scheduler_false");
      deployment.schedulingStack.execution = nullptr;
   }

   {
      ContainerView baseHealthy;
      baseHealthy.lifetime = ApplicationLifetime::base;
      baseHealthy.state = ContainerState::healthy;
      suite.expect(ApplicationDeployment::statelessCompactionContainerIsEligible(&baseHealthy), "statelessCompactionContainerIsEligible_base_healthy_true");

      ContainerView surgeHealthy;
      surgeHealthy.lifetime = ApplicationLifetime::surge;
      surgeHealthy.state = ContainerState::healthy;
      suite.expect(ApplicationDeployment::statelessCompactionContainerIsEligible(&surgeHealthy), "statelessCompactionContainerIsEligible_surge_healthy_true");

      ContainerView scheduledBase;
      scheduledBase.lifetime = ApplicationLifetime::base;
      scheduledBase.state = ContainerState::scheduled;
      suite.expect(ApplicationDeployment::statelessCompactionContainerIsEligible(&scheduledBase) == false, "statelessCompactionContainerIsEligible_scheduled_false");

      ContainerView destroyingBase;
      destroyingBase.lifetime = ApplicationLifetime::base;
      destroyingBase.state = ContainerState::destroying;
      suite.expect(ApplicationDeployment::statelessCompactionContainerIsEligible(&destroyingBase) == false, "statelessCompactionContainerIsEligible_destroying_false");

      ContainerView healthyCanary;
      healthyCanary.lifetime = ApplicationLifetime::canary;
      healthyCanary.state = ContainerState::healthy;
      suite.expect(ApplicationDeployment::statelessCompactionContainerIsEligible(&healthyCanary) == false, "statelessCompactionContainerIsEligible_canary_false");
   }

   {
      ApplicationDeployment deployment;
      deployment.state = DeploymentState::running;
      deployment.nTargetBase = 2;
      deployment.nTargetSurge = 0;
      deployment.nTargetCanary = 0;
      deployment.nDeployedBase = 99;
      deployment.nHealthyBase = 99;

      ContainerView healthy;
      healthy.lifetime = ApplicationLifetime::base;
      healthy.state = ContainerState::healthy;

      ContainerView scheduled;
      scheduled.lifetime = ApplicationLifetime::base;
      scheduled.state = ContainerState::scheduled;

      deployment.containers.insert(&healthy);
      deployment.containers.insert(&scheduled);

      deployment.recoverAfterReboot();

      suite.expect(deployment.nDeployedBase == 2, "recoverAfterReboot_rebuilds_deployed_counts");
      suite.expect(deployment.nHealthyBase == 1, "recoverAfterReboot_rebuilds_healthy_counts");
   }

   {
      ApplicationDeployment deployment;
      deployment.state = DeploymentState::failed;
      deployment.nDeployedBase = 7;
      deployment.nHealthyBase = 5;
      deployment.recoverAfterReboot();
      suite.expect(deployment.nDeployedBase == 7 && deployment.nHealthyBase == 5, "recoverAfterReboot_skips_failed_state");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.plan.config.versionID = 42;
      deployment.state = DeploymentState::running;
      deployment.nTargetBase = 1;
      deployment.nDeployedBase = 1;
      deployment.nHealthyBase = 1;
      deployment.nCrashes = 4;

      ContainerView container;
      container.uuid = uint128_t(0xAA);
      container.runtime_nLogicalCores = 3;
      container.runtime_memoryMB = 777;
      container.runtime_storageMB = 222;
      deployment.containers.insert(&container);

      DeploymentStatusReport report = deployment.generateReport();
      suite.expect(report.versionID == 42, "generateReport_version");
      suite.expect(report.nTarget == 1 && report.nDeployed == 1 && report.nHealthy == 1, "generateReport_counts");
      suite.expect(report.nCrashes == 4, "generateReport_crash_count");
      suite.expect(report.containerRuntimes.size() == 1, "generateReport_runtime_count");
      suite.expect(report.containerRuntimes[0].nLogicalCores == 3, "generateReport_runtime_cores");
      suite.expect(report.containerRuntimes[0].memoryMB == 777, "generateReport_runtime_memory");
      suite.expect(report.containerRuntimes[0].storageMB == 222, "generateReport_runtime_storage");
   }

   {
      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);

      for (uint32_t index = 0; index < 80; index++)
      {
         FailureReport report{};
         report.containerUUID = uint128_t(index + 1);
         report.approxTimeMs = index;
         report.nthCrash = index;
         report.signal = 9;
         report.restarted = false;
         report.wasCanary = false;
         report.report.assignItoa(index);
         deployment.failureReports.push_back(report);
      }

      DeploymentStatusReport status = deployment.generateReport();
      suite.expect(status.failureReports.size() == 64, "generateReport_failure_reports_capped_to_max");
      suite.expect(status.failureReports[0].containerUUID == uint128_t(17), "generateReport_failure_reports_keep_most_recent_tail");
      suite.expect(status.failureReports[63].containerUUID == uint128_t(80), "generateReport_failure_reports_tail_end");
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);

      Rack rack{};
      rack.uuid = 901;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;

      ContainerView oldContainer;
      oldContainer.machine = &machine;
      oldContainer.shardGroup = 7;
      oldContainer.deploymentID = deployment.plan.config.deploymentID();
      oldContainer.state = ContainerState::planned;

      DeploymentWork *work = deployment.planStatefulUpdateInPlace(&oldContainer);
      StatefulWork *stateful = std::get_if<StatefulWork>(work);
      ContainerView *replacement = (stateful ? stateful->container : nullptr);

      suite.expect(stateful != nullptr, "planStatefulUpdateInPlace_returns_stateful_work");
      suite.expect(stateful && stateful->lifecycle == LifecycleOp::updateInPlace, "planStatefulUpdateInPlace_lifecycle");
      suite.expect(stateful && stateful->oldContainer == &oldContainer, "planStatefulUpdateInPlace_old_container_link");
      suite.expect(replacement != nullptr, "planStatefulUpdateInPlace_creates_replacement");
      suite.expect(replacement && replacement->machine == &machine, "planStatefulUpdateInPlace_replacement_machine");
      suite.expect(replacement && replacement->shardGroup == oldContainer.shardGroup, "planStatefulUpdateInPlace_preserves_shard_group");
      suite.expect(oldContainer.state == ContainerState::aboutToDestroy, "planStatefulUpdateInPlace_marks_old_about_to_destroy");
      suite.expect(oldContainer.plannedWork == work, "planStatefulUpdateInPlace_marks_old_plannedWork");
      suite.expect(replacement && replacement->plannedWork == work, "planStatefulUpdateInPlace_marks_new_plannedWork");

      deployment.cancelDeploymentWork(work);
      suite.expect(oldContainer.plannedWork == nullptr, "cancelDeploymentWork_updateInPlace_clears_old_plannedWork");
      suite.expect(replacement && replacement->plannedWork == nullptr, "cancelDeploymentWork_updateInPlace_clears_new_plannedWork");

      if (replacement)
      {
         deployment.containers.erase(replacement);
         while (deployment.containersByShardGroup.eraseEntry(replacement->shardGroup, replacement)) {}
         brain.containers.erase(replacement->uuid);
         machine.removeContainerIndexEntry(replacement->deploymentID, replacement);
         delete replacement;
      }

      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment previous;
      seedCommonPlan(previous, false);
      previous.nTargetBase = 5;
      previous.nTargetSurge = 2;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.previous = &previous;
      deployment.plan.stateless.nBase = 6;
      deployment.plan.stateless.maxPerRackRatio = 1.0f;
      deployment.plan.stateless.maxPerMachineRatio = 1.0f;

      (void)deployment.measure();
      suite.expect(deployment.nTargetBase == 6, "measure_rehydrates_stateless_base_target_from_plan");
      suite.expect(deployment.nTargetSurge == 1, "measure_rehydrates_stateless_surge_target_after_base_raise");

      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment previous;
      seedCommonPlan(previous, false);
      previous.nTargetBase = 7;
      previous.nTargetSurge = 3;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.previous = &previous;
      deployment.plan.stateless.nBase = 4;
      deployment.plan.stateless.maxPerRackRatio = 1.0f;
      deployment.plan.stateless.maxPerMachineRatio = 1.0f;

      (void)deployment.measure();
      suite.expect(deployment.nTargetBase == 7, "measure_preserves_larger_previous_stateless_base_target");
      suite.expect(deployment.nTargetSurge == 3, "measure_preserves_stateless_surge_when_base_not_raised");

      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment previous;
      seedCommonPlan(previous, true);
      previous.nShardGroups = 4;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);
      deployment.previous = &previous;

      (void)deployment.measure();
      suite.expect(deployment.nShardGroups == 4, "measure_rehydrates_stateful_shard_group_count_from_previous");
      suite.expect(deployment.nTargetBase == 12, "measure_rehydrates_stateful_target_base_from_shards");

      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);

      (void)deployment.measure();
      suite.expect(deployment.nShardGroups == 1, "measure_stateful_defaults_to_single_shard_group");
      suite.expect(deployment.nTargetBase == 3, "measure_stateful_defaults_to_three_replicas");

      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack rackA{};
      rackA.uuid = 1950'0001;
      Rack rackB{};
      rackB.uuid = 1950'0002;
      Rack rackC{};
      rackC.uuid = 1950'0003;
      brain.racks.insert_or_assign(rackA.uuid, &rackA);
      brain.racks.insert_or_assign(rackB.uuid, &rackB);
      brain.racks.insert_or_assign(rackC.uuid, &rackC);

      ScopedSocketPair socketA = {};
      ScopedSocketPair socketB = {};
      ScopedSocketPair socketC = {};
      bool socketsReady =
         socketA.create(suite, "measure_stateful_three_replica_creates_socketpair_a")
         && socketB.create(suite, "measure_stateful_three_replica_creates_socketpair_b")
         && socketC.create(suite, "measure_stateful_three_replica_creates_socketpair_c");

      Machine machineA = {};
      machineA.uuid = uint128_t(0x19500001);
      machineA.slug = "measure-a"_ctv;
      machineA.rack = &rackA;
      machineA.state = MachineState::healthy;
      machineA.lifetime = MachineLifetime::owned;
      machineA.nLogicalCores_available = 8;
      machineA.memoryMB_available = 8'192;
      machineA.storageMB_available = 4'096;
      bool machineAReady = socketsReady && armNeuronControlStream(machineA, socketA);
      rackA.machines.insert(&machineA);
      brain.machines.insert(&machineA);

      Machine machineB = {};
      machineB.uuid = uint128_t(0x19500002);
      machineB.slug = "measure-b"_ctv;
      machineB.rack = &rackB;
      machineB.state = MachineState::healthy;
      machineB.lifetime = MachineLifetime::owned;
      machineB.nLogicalCores_available = 8;
      machineB.memoryMB_available = 8'192;
      machineB.storageMB_available = 4'096;
      bool machineBReady = socketsReady && armNeuronControlStream(machineB, socketB);
      rackB.machines.insert(&machineB);
      brain.machines.insert(&machineB);

      Machine machineC = {};
      machineC.uuid = uint128_t(0x19500003);
      machineC.slug = "measure-c"_ctv;
      machineC.rack = &rackC;
      machineC.state = MachineState::healthy;
      machineC.lifetime = MachineLifetime::owned;
      machineC.nLogicalCores_available = 8;
      machineC.memoryMB_available = 8'192;
      machineC.storageMB_available = 4'096;
      bool machineCReady = socketsReady && armNeuronControlStream(machineC, socketC);
      rackC.machines.insert(&machineC);
      brain.machines.insert(&machineC);

      suite.expect(machineAReady && machineBReady && machineCReady, "measure_stateful_three_replica_seeds_machine_neuron_control_streams");

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);

      uint32_t measured = deployment.measure();
      suite.expect(measured == 3, "measure_stateful_reports_three_replica_fit");
      suite.expect(brain.containers.size() == 0, "measure_stateful_cleans_brain_container_index");
      suite.expect(machineA.containersByDeploymentID.size() == 0, "measure_stateful_cleans_machine_a_index");
      suite.expect(machineB.containersByDeploymentID.size() == 0, "measure_stateful_cleans_machine_b_index");
      suite.expect(machineC.containersByDeploymentID.size() == 0, "measure_stateful_cleans_machine_c_index");
      suite.expect(deployment.containers.size() == 0, "measure_stateful_cleans_deployment_container_set");
      suite.expect(deployment.containersByShardGroup.size() == 0, "measure_stateful_cleans_deployment_shard_bins");
      suite.expect(deployment.toSchedule.size() == 0, "measure_stateful_cleans_scheduled_work");

      rackA.machines.erase(&machineA);
      rackB.machines.erase(&machineB);
      rackC.machines.erase(&machineC);
      brain.machines.erase(&machineA);
      brain.machines.erase(&machineB);
      brain.machines.erase(&machineC);
      brain.racks.erase(rackA.uuid);
      brain.racks.erase(rackB.uuid);
      brain.racks.erase(rackC.uuid);
      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack rackA{};
      rackA.uuid = 1902'2901;
      Rack rackB{};
      rackB.uuid = 1902'2902;
      Rack rackC{};
      rackC.uuid = 1902'2903;
      brain.racks.insert_or_assign(rackA.uuid, &rackA);
      brain.racks.insert_or_assign(rackB.uuid, &rackB);
      brain.racks.insert_or_assign(rackC.uuid, &rackC);

      ScopedSocketPair socketBrain = {};
      ScopedSocketPair socketWorkerA = {};
      ScopedSocketPair socketWorkerB = {};
      bool socketsReady =
         socketBrain.create(suite, "measure_stateful_inactive_machine_creates_socketpair_brain")
         && socketWorkerA.create(suite, "measure_stateful_inactive_machine_creates_socketpair_worker_a")
         && socketWorkerB.create(suite, "measure_stateful_inactive_machine_creates_socketpair_worker_b");

      Machine brainMachine = {};
      brainMachine.slug = "controller-brain-inactive"_ctv;
      brainMachine.rack = &rackA;
      brainMachine.state = MachineState::healthy;
      brainMachine.lifetime = MachineLifetime::owned;
      brainMachine.isBrain = true;
      brainMachine.nLogicalCores_available = 8;
      brainMachine.memoryMB_available = 8'192;
      brainMachine.storageMB_available = 4'096;
      bool brainMachineArmed = socketsReady && armNeuronControlStream(brainMachine, socketBrain);
      brainMachine.neuron.connected = false;
      rackA.machines.insert(&brainMachine);
      brain.machines.insert(&brainMachine);

      Machine workerA = {};
      workerA.slug = "worker-active-a"_ctv;
      workerA.rack = &rackB;
      workerA.state = MachineState::healthy;
      workerA.lifetime = MachineLifetime::owned;
      workerA.nLogicalCores_available = 8;
      workerA.memoryMB_available = 8'192;
      workerA.storageMB_available = 4'096;
      bool workerAReady = socketsReady && armNeuronControlStream(workerA, socketWorkerA);
      rackB.machines.insert(&workerA);
      brain.machines.insert(&workerA);

      Machine workerB = {};
      workerB.slug = "worker-active-b"_ctv;
      workerB.rack = &rackC;
      workerB.state = MachineState::healthy;
      workerB.lifetime = MachineLifetime::owned;
      workerB.nLogicalCores_available = 8;
      workerB.memoryMB_available = 8'192;
      workerB.storageMB_available = 4'096;
      bool workerBReady = socketsReady && armNeuronControlStream(workerB, socketWorkerB);
      rackC.machines.insert(&workerB);
      brain.machines.insert(&workerB);

      suite.expect(brainMachineArmed && workerAReady && workerBReady, "measure_stateful_inactive_machine_seeds_neuron_control_streams");

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);

      uint32_t measured = deployment.measure();
      suite.expect(measured == 2, "measure_stateful_excludes_healthy_machine_without_neuron_control");

      rackA.machines.erase(&brainMachine);
      rackB.machines.erase(&workerA);
      rackC.machines.erase(&workerB);
      brain.machines.erase(&brainMachine);
      brain.machines.erase(&workerA);
      brain.machines.erase(&workerB);
      brain.racks.erase(rackA.uuid);
      brain.racks.erase(rackB.uuid);
      brain.racks.erase(rackC.uuid);
      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack rack{};
      rack.uuid = 1951'0001;
      brain.racks.insert_or_assign(rack.uuid, &rack);

      ScopedSocketPair socket = {};
      bool socketReady = socket.create(suite, "measure_stateful_previous_creates_socketpair");

      Machine machine = {};
      machine.uuid = uint128_t(0x19510001);
      machine.slug = "measure-previous"_ctv;
      machine.rack = &rack;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;
      machine.nLogicalCores_available = 8;
      machine.memoryMB_available = 8'192;
      machine.storageMB_available = 4'096;
      bool machineReady = socketReady && armNeuronControlStream(machine, socket);
      rack.machines.insert(&machine);
      brain.machines.insert(&machine);

      suite.expect(machineReady, "measure_stateful_previous_seeds_machine_neuron_control_stream");

      ApplicationDeployment previous;
      seedCommonPlan(previous, true);
      previous.plan.config.versionID = 1;
      previous.nShardGroups = 1;

      ContainerView oldContainer = {};
      oldContainer.uuid = uint128_t(0x19510010);
      oldContainer.deploymentID = previous.plan.config.deploymentID();
      oldContainer.applicationID = previous.plan.config.applicationID;
      oldContainer.machine = &machine;
      oldContainer.lifetime = ApplicationLifetime::base;
      oldContainer.state = ContainerState::healthy;
      oldContainer.isStateful = true;
      oldContainer.shardGroup = 0;
      previous.containers.insert(&oldContainer);
      previous.containersByShardGroup.insert(oldContainer.shardGroup, &oldContainer);
      brain.containers.insert_or_assign(oldContainer.uuid, &oldContainer);
      machine.upsertContainerIndexEntry(oldContainer.deploymentID, &oldContainer);

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);
      deployment.plan.config.versionID = 2;
      deployment.previous = &previous;

      uint32_t measured = deployment.measure();
      suite.expect(measured == 1, "measure_stateful_previous_fixture_updates_in_place_fit");
      suite.expect(oldContainer.state == ContainerState::healthy, "measure_stateful_restores_previous_container_state");
      suite.expect(oldContainer.plannedWork == nullptr, "measure_stateful_restores_previous_container_planned_work");
      suite.expect(brain.containers.size() == 1 && brain.containers.contains(oldContainer.uuid), "measure_stateful_keeps_previous_brain_container_only");
      suite.expect(machine.containersByDeploymentID.size() == 1, "measure_stateful_keeps_only_previous_machine_index");
      suite.expect(machine.containersByDeploymentID.hasEntryFor(previous.plan.config.deploymentID(), &oldContainer), "measure_stateful_preserves_previous_machine_entry");
      suite.expect(machine.containersByDeploymentID.find(deployment.plan.config.deploymentID()) == machine.containersByDeploymentID.end(), "measure_stateful_removes_new_deployment_machine_entry");
      suite.expect(deployment.containers.size() == 0, "measure_stateful_previous_cleanup_new_container_set");
      suite.expect(deployment.toSchedule.size() == 0, "measure_stateful_previous_cleanup_new_work");

      previous.containers.erase(&oldContainer);
      while (previous.containersByShardGroup.eraseEntry(oldContainer.shardGroup, &oldContainer)) {}
      brain.containers.erase(oldContainer.uuid);
      machine.removeContainerIndexEntry(oldContainer.deploymentID, &oldContainer);
      rack.machines.erase(&machine);
      brain.machines.erase(&machine);
      brain.racks.erase(rack.uuid);
      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.plan.stateless.nBase = 1;
      deployment.nDeployedBase = 9;
      deployment.nDeployedSurge = 7;
      deployment.nHealthyBase = 5;
      deployment.nHealthySurge = 3;
      deployment.nTargetSurge = 4;

      Machine machine = {};
      machine.slug = "takeover-worker"_ctv;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;

      ContainerView base = {};
      base.uuid = uint128_t(0x19011902);
      base.deploymentID = deployment.plan.config.deploymentID();
      base.applicationID = deployment.plan.config.applicationID;
      base.machine = &machine;
      base.lifetime = ApplicationLifetime::base;
      base.state = ContainerState::healthy;

      ContainerView surge = {};
      surge.uuid = uint128_t(0x19011903);
      surge.deploymentID = deployment.plan.config.deploymentID();
      surge.applicationID = deployment.plan.config.applicationID;
      surge.machine = &machine;
      surge.lifetime = ApplicationLifetime::surge;
      surge.state = ContainerState::healthy;

      deployment.containers.insert(&base);
      deployment.containers.insert(&surge);

      deployment.evaluateAfterNewMaster();
      suite.expect(deployment.nTargetBase == 1, "evaluateAfterNewMaster_stateless_restores_base_target");
      suite.expect(deployment.nTargetSurge == 1, "evaluateAfterNewMaster_stateless_derives_surge_target_from_live_containers");
      suite.expect(deployment.nDeployedBase == 1, "evaluateAfterNewMaster_stateless_rebuilds_base_deployed_from_live_containers");
      suite.expect(deployment.nDeployedSurge == 1, "evaluateAfterNewMaster_stateless_rebuilds_surge_deployed_from_live_containers");
      suite.expect(deployment.nHealthyBase == 1, "evaluateAfterNewMaster_stateless_rebuilds_base_healthy_from_live_containers");
      suite.expect(deployment.nHealthySurge == 1, "evaluateAfterNewMaster_stateless_rebuilds_surge_healthy_from_live_containers");

      deployment.evaluateAfterNewMaster();
      suite.expect(deployment.nTargetSurge == 1, "evaluateAfterNewMaster_stateless_is_idempotent_for_surge_target");
      suite.expect(deployment.nDeployedBase == 1, "evaluateAfterNewMaster_stateless_is_idempotent_for_base_deployed");
      suite.expect(deployment.nDeployedSurge == 1, "evaluateAfterNewMaster_stateless_is_idempotent_for_surge_deployed");
      suite.expect(deployment.nHealthyBase == 1, "evaluateAfterNewMaster_stateless_is_idempotent_for_base_healthy");
      suite.expect(deployment.nHealthySurge == 1, "evaluateAfterNewMaster_stateless_is_idempotent_for_surge_healthy");

      deployment.containers.erase(&base);
      deployment.containers.erase(&surge);
      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);
      deployment.nShardGroups = 99;
      deployment.nTargetBase = 77;
      deployment.nTargetCanary = 6;
      deployment.nTargetSurge = 5;
      deployment.nDeployedBase = 9;
      deployment.nDeployedCanary = 8;
      deployment.nDeployedSurge = 7;
      deployment.nHealthyBase = 4;
      deployment.nHealthyCanary = 3;
      deployment.nHealthySurge = 2;

      Machine machine = {};
      machine.slug = "stateful-takeover-worker"_ctv;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;

      ContainerView baseHealthy = {};
      baseHealthy.uuid = uint128_t(0x19011904);
      baseHealthy.deploymentID = deployment.plan.config.deploymentID();
      baseHealthy.applicationID = deployment.plan.config.applicationID;
      baseHealthy.machine = &machine;
      baseHealthy.lifetime = ApplicationLifetime::base;
      baseHealthy.state = ContainerState::healthy;
      baseHealthy.shardGroup = 0;

      ContainerView baseScheduled = {};
      baseScheduled.uuid = uint128_t(0x19011905);
      baseScheduled.deploymentID = deployment.plan.config.deploymentID();
      baseScheduled.applicationID = deployment.plan.config.applicationID;
      baseScheduled.machine = &machine;
      baseScheduled.lifetime = ApplicationLifetime::base;
      baseScheduled.state = ContainerState::scheduled;
      baseScheduled.shardGroup = 0;

      ContainerView baseHealthyTwo = {};
      baseHealthyTwo.uuid = uint128_t(0x19011908);
      baseHealthyTwo.deploymentID = deployment.plan.config.deploymentID();
      baseHealthyTwo.applicationID = deployment.plan.config.applicationID;
      baseHealthyTwo.machine = &machine;
      baseHealthyTwo.lifetime = ApplicationLifetime::base;
      baseHealthyTwo.state = ContainerState::healthy;
      baseHealthyTwo.shardGroup = 0;

      ContainerView surgeHealthy = {};
      surgeHealthy.uuid = uint128_t(0x19011906);
      surgeHealthy.deploymentID = deployment.plan.config.deploymentID();
      surgeHealthy.applicationID = deployment.plan.config.applicationID;
      surgeHealthy.machine = &machine;
      surgeHealthy.lifetime = ApplicationLifetime::surge;
      surgeHealthy.state = ContainerState::healthy;
      surgeHealthy.shardGroup = 0;

      ContainerView canaryHealthy = {};
      canaryHealthy.uuid = uint128_t(0x19011907);
      canaryHealthy.deploymentID = deployment.plan.config.deploymentID();
      canaryHealthy.applicationID = deployment.plan.config.applicationID;
      canaryHealthy.machine = &machine;
      canaryHealthy.lifetime = ApplicationLifetime::canary;
      canaryHealthy.state = ContainerState::healthy;
      canaryHealthy.shardGroup = 1;

      deployment.containers.insert(&baseHealthy);
      deployment.containers.insert(&baseScheduled);
      deployment.containers.insert(&baseHealthyTwo);
      deployment.containers.insert(&surgeHealthy);
      deployment.containers.insert(&canaryHealthy);
      deployment.containersByShardGroup.insert(0, &baseHealthy);

      deployment.evaluateAfterNewMaster();
      suite.expect(deployment.nShardGroups == 1, "evaluateAfterNewMaster_stateful_restores_shard_groups");
      suite.expect(deployment.nTargetBase == 3, "evaluateAfterNewMaster_stateful_restores_base_target_from_shard_groups");
      suite.expect(deployment.nTargetSurge == 1, "evaluateAfterNewMaster_stateful_rebuilds_surge_target_from_live_containers");
      suite.expect(deployment.nTargetCanary == 1, "evaluateAfterNewMaster_stateful_rebuilds_canary_target_from_live_containers");
      suite.expect(deployment.nDeployedBase == 3, "evaluateAfterNewMaster_stateful_rebuilds_base_deployed_from_live_containers");
      suite.expect(deployment.nDeployedSurge == 1, "evaluateAfterNewMaster_stateful_rebuilds_surge_deployed_from_live_containers");
      suite.expect(deployment.nDeployedCanary == 1, "evaluateAfterNewMaster_stateful_rebuilds_canary_deployed_from_live_containers");
      suite.expect(deployment.nHealthyBase == 2, "evaluateAfterNewMaster_stateful_rebuilds_base_healthy_from_live_containers");
      suite.expect(deployment.nHealthySurge == 1, "evaluateAfterNewMaster_stateful_rebuilds_surge_healthy_from_live_containers");
      suite.expect(deployment.nHealthyCanary == 1, "evaluateAfterNewMaster_stateful_rebuilds_canary_healthy_from_live_containers");

      deployment.evaluateAfterNewMaster();
      suite.expect(deployment.nTargetBase == 3, "evaluateAfterNewMaster_stateful_is_idempotent_for_base_target");
      suite.expect(deployment.nTargetSurge == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_surge_target");
      suite.expect(deployment.nTargetCanary == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_canary_target");
      suite.expect(deployment.nDeployedBase == 3, "evaluateAfterNewMaster_stateful_is_idempotent_for_base_deployed");
      suite.expect(deployment.nDeployedSurge == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_surge_deployed");
      suite.expect(deployment.nDeployedCanary == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_canary_deployed");
      suite.expect(deployment.nHealthyBase == 2, "evaluateAfterNewMaster_stateful_is_idempotent_for_base_healthy");
      suite.expect(deployment.nHealthySurge == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_surge_healthy");
      suite.expect(deployment.nHealthyCanary == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_canary_healthy");

      deployment.containers.erase(&baseHealthy);
      deployment.containers.erase(&baseScheduled);
      deployment.containers.erase(&baseHealthyTwo);
      deployment.containers.erase(&surgeHealthy);
      deployment.containers.erase(&canaryHealthy);
      while (deployment.containersByShardGroup.eraseEntry(0, &baseHealthy)) {}
      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack rackA{};
      rackA.uuid = 1951'1001;
      Rack rackB{};
      rackB.uuid = 1951'1002;
      brain.racks.insert_or_assign(rackA.uuid, &rackA);
      brain.racks.insert_or_assign(rackB.uuid, &rackB);

      ScopedSocketPair socketB = {};
      bool socketReady = socketB.create(suite, "spin_stateless_move_creates_socketpair_target");

      Machine machineA = {};
      machineA.uuid = uint128_t(0x19511001);
      machineA.slug = "spin-stateless-source"_ctv;
      machineA.rack = &rackA;
      machineA.state = MachineState::healthy;
      machineA.lifetime = MachineLifetime::owned;
      machineA.nLogicalCores_available = 8;
      machineA.memoryMB_available = 8'192;
      machineA.storageMB_available = 4'096;
      rackA.machines.insert(&machineA);
      brain.machines.insert(&machineA);

      Machine machineB = {};
      machineB.uuid = uint128_t(0x19511002);
      machineB.slug = "spin-stateless-target"_ctv;
      machineB.rack = &rackB;
      machineB.state = MachineState::healthy;
      machineB.lifetime = MachineLifetime::owned;
      machineB.nLogicalCores_available = 8;
      machineB.memoryMB_available = 8'192;
      machineB.storageMB_available = 4'096;
      bool machineBReady = socketReady && armNeuronControlStream(machineB, socketB);
      rackB.machines.insert(&machineB);
      brain.machines.insert(&machineB);

      suite.expect(machineBReady, "spin_stateless_move_seeds_target_machine_neuron_control_stream");

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.nTargetBase = 1;
      deployment.nTargetCanary = 0;
      deployment.nTargetSurge = 0;

      DeploymentWork *work = deployment.planStatelessConstruction(&machineA, ApplicationLifetime::base);
      StatelessWork *stateless = std::get_if<StatelessWork>(work);
      ContainerView *container = stateless ? stateless->container : nullptr;

      suite.expect(container != nullptr, "spin_stateless_move_creates_planned_container");
      suite.expect(container && machineA.containersByDeploymentID.hasEntryFor(container->deploymentID, container), "spin_stateless_move_indexes_source_machine_before_move");

      deployment.countPerMachine[&machineA] = 1;
      deployment.countPerRack[&rackA] = 1;

      deployment.drainMachine(&machineA, false);

      suite.expect(container && container->machine == &machineB, "spin_stateless_move_retargets_container_machine");
      suite.expect(container && machineA.containersByDeploymentID.hasEntryFor(container->deploymentID, container) == false, "spin_stateless_move_removes_source_machine_index");
      suite.expect(container && machineB.containersByDeploymentID.hasEntryFor(container->deploymentID, container), "spin_stateless_move_indexes_target_machine");

      if (container)
      {
         if (container->plannedWork)
         {
            deployment.cancelDeploymentWork(container->plannedWork);
         }

         deployment.containers.erase(container);
         machineA.removeContainerIndexEntry(container->deploymentID, container);
         machineB.removeContainerIndexEntry(container->deploymentID, container);
         brain.containers.erase(container->uuid);
         delete container;
      }

      rackA.machines.erase(&machineA);
      rackB.machines.erase(&machineB);
      brain.machines.erase(&machineA);
      brain.machines.erase(&machineB);
      brain.racks.erase(rackA.uuid);
      brain.racks.erase(rackB.uuid);
      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack rackA{};
      rackA.uuid = 1951'2001;
      Rack rackB{};
      rackB.uuid = 1951'2002;
      brain.racks.insert_or_assign(rackA.uuid, &rackA);
      brain.racks.insert_or_assign(rackB.uuid, &rackB);

      ScopedSocketPair socketB = {};
      bool socketReady = socketB.create(suite, "spin_stateful_move_creates_socketpair_target");

      Machine machineA = {};
      machineA.uuid = uint128_t(0x19512001);
      machineA.slug = "spin-stateful-source"_ctv;
      machineA.rack = &rackA;
      machineA.state = MachineState::healthy;
      machineA.lifetime = MachineLifetime::owned;
      machineA.nLogicalCores_available = 8;
      machineA.memoryMB_available = 8'192;
      machineA.storageMB_available = 4'096;
      rackA.machines.insert(&machineA);
      brain.machines.insert(&machineA);

      Machine machineB = {};
      machineB.uuid = uint128_t(0x19512002);
      machineB.slug = "spin-stateful-target"_ctv;
      machineB.rack = &rackB;
      machineB.state = MachineState::healthy;
      machineB.lifetime = MachineLifetime::owned;
      machineB.nLogicalCores_available = 8;
      machineB.memoryMB_available = 8'192;
      machineB.storageMB_available = 4'096;
      bool machineBReady = socketReady && armNeuronControlStream(machineB, socketB);
      rackB.machines.insert(&machineB);
      brain.machines.insert(&machineB);

      suite.expect(machineBReady, "spin_stateful_move_seeds_target_machine_neuron_control_stream");

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);
      deployment.nShardGroups = 1;
      deployment.nTargetBase = 1;
      deployment.nTargetCanary = 0;
      deployment.nTargetSurge = 0;

      DeploymentWork *work = deployment.planStatefulConstruction(&machineA, 7, DataStrategy::seeding);
      StatefulWork *stateful = std::get_if<StatefulWork>(work);
      ContainerView *container = stateful ? stateful->container : nullptr;

      suite.expect(container != nullptr, "spin_stateful_move_creates_planned_container");
      suite.expect(container && machineA.containersByDeploymentID.hasEntryFor(container->deploymentID, container), "spin_stateful_move_indexes_source_machine_before_move");

      deployment.countPerMachine[&machineA] = 1;
      deployment.countPerRack[&rackA] = 1;
      deployment.racksByShardGroup[7].insert(&rackA);

      deployment.drainMachine(&machineA, false);

      suite.expect(container && container->machine == &machineB, "spin_stateful_move_retargets_container_machine");
      suite.expect(container && machineA.containersByDeploymentID.hasEntryFor(container->deploymentID, container) == false, "spin_stateful_move_removes_source_machine_index");
      suite.expect(container && machineB.containersByDeploymentID.hasEntryFor(container->deploymentID, container), "spin_stateful_move_indexes_target_machine");
      suite.expect(deployment.racksByShardGroup[7].contains(&rackA) == false, "spin_stateful_move_releases_source_rack");
      suite.expect(deployment.racksByShardGroup[7].contains(&rackB), "spin_stateful_move_tracks_target_rack");

      if (container)
      {
         if (container->plannedWork)
         {
            deployment.cancelDeploymentWork(container->plannedWork);
         }

         deployment.containers.erase(container);
         while (deployment.containersByShardGroup.eraseEntry(container->shardGroup, container)) {}
         machineA.removeContainerIndexEntry(container->deploymentID, container);
         machineB.removeContainerIndexEntry(container->deploymentID, container);
         brain.containers.erase(container->uuid);
         delete container;
      }

      rackA.machines.erase(&machineA);
      rackB.machines.erase(&machineB);
      brain.machines.erase(&machineA);
      brain.machines.erase(&machineB);
      brain.racks.erase(rackA.uuid);
      brain.racks.erase(rackB.uuid);
      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack rack{};
      rack.uuid = 1901;
      brain.racks.insert_or_assign(rack.uuid, &rack);

      ScopedSocketPair socket = {};
      bool socketReady = socket.create(suite, "measure_stateless_capacity_creates_socketpair");

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;
      machine.nLogicalCores_available = 8;
      machine.memoryMB_available = 8'192;
      machine.storageMB_available = 4'096;
      bool machineReady = socketReady && armNeuronControlStream(machine, socket);
      rack.machines.insert(&machine);
      brain.machines.insert(&machine);

      suite.expect(machineReady, "measure_stateless_capacity_seeds_machine_neuron_control_stream");

      const int32_t initialCores = machine.nLogicalCores_available;
      const int32_t initialMemory = machine.memoryMB_available;
      const int32_t initialStorage = machine.storageMB_available;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.plan.stateless.nBase = 2;
      deployment.plan.stateless.maxPerRackRatio = 1.0f;
      deployment.plan.stateless.maxPerMachineRatio = 1.0f;

      uint32_t measured = deployment.measure();
      suite.expect(measured >= 1, "measure_stateless_reports_fit_capacity");
      suite.expect(deployment.nTargetBase == deployment.plan.stateless.nBase, "measure_restores_target_base_after_measurement");
      suite.expect(deployment.nTargetSurge == 0, "measure_restores_target_surge_after_measurement");
      suite.expect(deployment.nDeployedBase == 0 && deployment.nDeployedSurge == 0, "measure_restores_deployed_counters");
      suite.expect(brain.containers.size() == 0, "measure_stateless_cleans_brain_container_index");
      suite.expect(deployment.containers.size() == 0, "measure_stateless_cleans_deployment_container_set");
      suite.expect(deployment.toSchedule.size() == 0, "measure_stateless_cleans_scheduled_work");
      suite.expect(deployment.waitingOnContainers.size() == 0, "measure_stateless_cleans_waiting_containers");
      suite.expect(machine.nLogicalCores_available == initialCores, "measure_restores_machine_cores");
      suite.expect(machine.memoryMB_available == initialMemory, "measure_restores_machine_memory");
      suite.expect(machine.storageMB_available == initialStorage, "measure_restores_machine_storage");

      rack.machines.erase(&machine);
      brain.machines.erase(&machine);
      brain.racks.erase(rack.uuid);
      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack rack{};
      rack.uuid = 1901'1901;
      brain.racks.insert_or_assign(rack.uuid, &rack);

      ScopedSocketPair socket = {};
      bool socketReady = socket.create(suite, "measure_stateless_brain_machine_creates_socketpair");

      Machine brainMachine = {};
      brainMachine.slug = "controller-brain"_ctv;
      brainMachine.rack = &rack;
      brainMachine.state = MachineState::healthy;
      brainMachine.lifetime = MachineLifetime::owned;
      brainMachine.isBrain = true;
      brainMachine.nLogicalCores_available = 8;
      brainMachine.memoryMB_available = 8'192;
      brainMachine.storageMB_available = 4'096;
      bool brainMachineReady = socketReady && armNeuronControlStream(brainMachine, socket);
      rack.machines.insert(&brainMachine);
      brain.machines.insert(&brainMachine);

      suite.expect(brainMachineReady, "measure_stateless_brain_machine_seeds_neuron_control_stream");

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.plan.stateless.nBase = 1;
      deployment.plan.stateless.maxPerRackRatio = 1.0f;
      deployment.plan.stateless.maxPerMachineRatio = 1.0f;

      brainMachine.isBrain = false;
      uint32_t workerMeasured = deployment.measure();
      suite.expect(workerMeasured >= 1, "measure_stateless_worker_fixture_has_fit_capacity");

      brainMachine.isBrain = true;
      uint32_t measured = deployment.measure();
      suite.expect(measured >= 1, "measure_stateless_includes_brain_machines_in_placement");
      suite.expect(measured == workerMeasured, "measure_stateless_brain_machine_matches_worker_capacity");

      rack.machines.erase(&brainMachine);
      brain.machines.erase(&brainMachine);
      brain.racks.erase(rack.uuid);
      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack rackA{};
      rackA.uuid = 1902'1901;
      Rack rackB{};
      rackB.uuid = 1902'1902;
      Rack rackC{};
      rackC.uuid = 1902'1903;
      brain.racks.insert_or_assign(rackA.uuid, &rackA);
      brain.racks.insert_or_assign(rackB.uuid, &rackB);
      brain.racks.insert_or_assign(rackC.uuid, &rackC);

      ScopedSocketPair socketBrain = {};
      ScopedSocketPair socketWorkerA = {};
      ScopedSocketPair socketWorkerB = {};
      bool socketsReady =
         socketBrain.create(suite, "measure_stateful_brain_machine_creates_socketpair_brain")
         && socketWorkerA.create(suite, "measure_stateful_brain_machine_creates_socketpair_worker_a")
         && socketWorkerB.create(suite, "measure_stateful_brain_machine_creates_socketpair_worker_b");

      Machine brainMachine = {};
      brainMachine.slug = "controller-brain"_ctv;
      brainMachine.rack = &rackA;
      brainMachine.state = MachineState::healthy;
      brainMachine.lifetime = MachineLifetime::owned;
      brainMachine.isBrain = true;
      brainMachine.nLogicalCores_available = 8;
      brainMachine.memoryMB_available = 8'192;
      brainMachine.storageMB_available = 4'096;
      bool brainMachineReady = socketsReady && armNeuronControlStream(brainMachine, socketBrain);
      rackA.machines.insert(&brainMachine);
      brain.machines.insert(&brainMachine);

      Machine workerA = {};
      workerA.slug = "worker-a"_ctv;
      workerA.rack = &rackB;
      workerA.state = MachineState::healthy;
      workerA.lifetime = MachineLifetime::owned;
      workerA.nLogicalCores_available = 8;
      workerA.memoryMB_available = 8'192;
      workerA.storageMB_available = 4'096;
      bool workerAReady = socketsReady && armNeuronControlStream(workerA, socketWorkerA);
      rackB.machines.insert(&workerA);
      brain.machines.insert(&workerA);

      Machine workerB = {};
      workerB.slug = "worker-b"_ctv;
      workerB.rack = &rackC;
      workerB.state = MachineState::healthy;
      workerB.lifetime = MachineLifetime::owned;
      workerB.nLogicalCores_available = 8;
      workerB.memoryMB_available = 8'192;
      workerB.storageMB_available = 4'096;
      bool workerBReady = socketsReady && armNeuronControlStream(workerB, socketWorkerB);
      rackC.machines.insert(&workerB);
      brain.machines.insert(&workerB);

      suite.expect(brainMachineReady && workerAReady && workerBReady, "measure_stateful_brain_machine_seeds_neuron_control_streams");

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);

      brainMachine.isBrain = false;
      uint32_t workerMeasured = deployment.measure();
      suite.expect(workerMeasured == 3, "measure_stateful_worker_fixture_has_three_replica_fit");

      brainMachine.isBrain = true;
      uint32_t measured = deployment.measure();
      suite.expect(measured == 3, "measure_stateful_includes_brain_machines_in_placement");
      suite.expect(measured == workerMeasured, "measure_stateful_brain_machine_matches_worker_capacity");

      rackA.machines.erase(&brainMachine);
      rackB.machines.erase(&workerA);
      rackC.machines.erase(&workerB);
      brain.machines.erase(&brainMachine);
      brain.machines.erase(&workerA);
      brain.machines.erase(&workerB);
      brain.racks.erase(rackA.uuid);
      brain.racks.erase(rackB.uuid);
      brain.racks.erase(rackC.uuid);
      thisBrain = savedBrain;
   }

   {
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);
      deployment.plan.stateful.allMasters = true;

      Rack rack{};
      rack.uuid = 1902;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;
      machine.ownedLogicalCores = 12;
      machine.ownedMemoryMB = 4'512;
      machine.ownedStorageMB = 2'128;
      machine.isolatedLogicalCoresCommitted = deployment.plan.config.nLogicalCores;
      machine.nLogicalCores_available = 10;
      machine.sharedCPUMillis_available = 0;
      machine.memoryMB_available = 4'000;
      machine.storageMB_available = 2'000;

      brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

      ContainerView *container = new ContainerView();
      container->uuid = uint128_t(0xD351);
      container->deploymentID = deployment.plan.config.deploymentID();
      container->machine = &machine;
      container->lifetime = ApplicationLifetime::base;
      container->state = ContainerState::aboutToDestroy;
      container->isStateful = true;
      container->shardGroup = 55;

      deployment.containers.insert(container);
      deployment.containersByShardGroup.insert(container->shardGroup, container);
      brain.containers.insert_or_assign(container->uuid, container);
      machine.upsertContainerIndexEntry(container->deploymentID, container);

      deployment.nHealthyBase = 1;

      const uint128_t uuid = container->uuid;
      const int32_t coresBefore = machine.nLogicalCores_available;
      const int32_t memoryBefore = machine.memoryMB_available;
      const int32_t storageBefore = machine.storageMB_available;

      deployment.planStatefulDestruction(container);
      deployment.destructContainer(container);

      suite.expect(container->state == ContainerState::destroying, "destructContainer_moves_state_to_destroying");
      suite.expect(deployment.nHealthyBase == 0, "destructContainer_decrements_healthy_counts");
      suite.expect(machine.nLogicalCores_available == (coresBefore + int32_t(deployment.plan.config.nLogicalCores)), "destructContainer_restores_machine_cores");
      suite.expect(machine.memoryMB_available == (memoryBefore + int32_t(deployment.plan.config.totalMemoryMB())), "destructContainer_restores_machine_memory");
      suite.expect(machine.storageMB_available == (storageBefore + int32_t(deployment.plan.config.totalStorageMB())), "destructContainer_restores_machine_storage");
      suite.expect(deployment.containers.contains(container) == false, "destructContainer_erases_from_deployment_container_set");
      suite.expect(machine.containersByDeploymentID.size() == 0, "destructContainer_erases_machine_index_entry");

      deployment.containerDestroyed(container);
      suite.expect(brain.containers.contains(uuid) == false, "containerDestroyed_erases_brain_container_index");

      brain.deployments.erase(deployment.plan.config.deploymentID());
      thisBrain = savedBrain;
   }

   {
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);

      Rack rack{};
      rack.uuid = 1902'1;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;
      machine.nLogicalCores_available = 10;
      machine.sharedCPUMillis_available = 0;
      machine.memoryMB_available = 4'000;
      machine.storageMB_available = 2'000;

      brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

      ContainerView *container = new ContainerView();
      container->uuid = uint128_t(0xD3511);
      container->deploymentID = deployment.plan.config.deploymentID();
      container->machine = &machine;
      container->lifetime = ApplicationLifetime::base;
      container->state = ContainerState::aboutToDestroy;
      container->isStateful = false;

      deployment.containers.insert(container);
      brain.containers.insert_or_assign(container->uuid, container);
      machine.upsertContainerIndexEntry(container->deploymentID, container);

      deployment.nHealthyBase = 0;

      const uint128_t uuid = container->uuid;

      deployment.planStatelessDestruction(container, "destructContainer_zero_guard");
      deployment.destructContainer(container);

      suite.expect(deployment.nHealthyBase == 0, "destructContainer_clamps_zero_healthy_base");
      suite.expect(container->state == ContainerState::destroying, "destructContainer_zero_guard_moves_state_to_destroying");
      suite.expect(deployment.containers.contains(container) == false, "destructContainer_zero_guard_erases_from_deployment_container_set");
      suite.expect(machine.containersByDeploymentID.size() == 0, "destructContainer_zero_guard_erases_machine_index_entry");

      deployment.containerDestroyed(container);
      suite.expect(brain.containers.contains(uuid) == false, "destructContainer_zero_guard_erases_brain_container_index");

      brain.deployments.erase(deployment.plan.config.deploymentID());
      thisBrain = savedBrain;
   }

   {
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);
      deployment.plan.stateful.allMasters = true;

      Rack rack{};
      rack.uuid = 1903;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;
      machine.nLogicalCores_available = 10;
      machine.memoryMB_available = 4'000;
      machine.storageMB_available = 2'000;

      brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

      ContainerView *container = new ContainerView();
      container->uuid = uint128_t(0xD352);
      container->deploymentID = deployment.plan.config.deploymentID();
      container->machine = &machine;
      container->lifetime = ApplicationLifetime::base;
      container->state = ContainerState::aboutToDestroy;
      container->isStateful = true;
      container->shardGroup = 8;

      deployment.containers.insert(container);
      deployment.containersByShardGroup.insert(container->shardGroup, container);
      brain.containers.insert_or_assign(container->uuid, container);
      machine.upsertContainerIndexEntry(container->deploymentID, container);

      deployment.nHealthyBase = 1;

      const uint128_t uuid = container->uuid;

      deployment.drainMachine(&machine, true);

      suite.expect(deployment.containers.size() == 0, "drainMachine_failed_culls_about_to_destroy_container");
      suite.expect(brain.containers.contains(uuid) == false, "drainMachine_failed_removes_container_from_brain_index");
      suite.expect(machine.containersByDeploymentID.size() == 0, "drainMachine_failed_clears_machine_container_bin");
      suite.expect(deployment.nHealthyBase == 0, "drainMachine_failed_updates_healthy_counts");

      brain.deployments.erase(deployment.plan.config.deploymentID());
      thisBrain = savedBrain;
   }

   {
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);

      Rack rack{};
      rack.uuid = 1904;

      Machine machine;
      machine.slug = "dev-baremetal"_ctv;
      machine.rack = &rack;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;

      ContainerView oldContainer;
      oldContainer.machine = &machine;
      oldContainer.shardGroup = 12;

      deployment.scheduleStatefulUpdateInPlace(&oldContainer);

      suite.expect(deployment.toSchedule.size() == 1, "scheduleStatefulUpdateInPlace_enqueues_single_work_item");
      DeploymentWork *work = deployment.toSchedule[0];
      StatefulWork *stateful = std::get_if<StatefulWork>(work);
      suite.expect(stateful != nullptr, "scheduleStatefulUpdateInPlace_enqueues_stateful_work");
      suite.expect(stateful && stateful->lifecycle == LifecycleOp::updateInPlace, "scheduleStatefulUpdateInPlace_lifecycle");

      ContainerView *replacement = (stateful ? stateful->container : nullptr);
      deployment.cancelDeploymentWork(work);

      if (replacement)
      {
         deployment.containers.erase(replacement);
         brain.containers.erase(replacement->uuid);
         machine.removeContainerIndexEntry(replacement->deploymentID, replacement);
         delete replacement;
      }

      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Mesh mesh = {};
      brain.mesh = &mesh;

      Rack rackA = {};
      rackA.uuid = 1905'1901;
      Rack rackB = {};
      rackB.uuid = 1905'1902;
      Rack rackC = {};
      rackC.uuid = 1905'1903;
      brain.racks.insert_or_assign(rackA.uuid, &rackA);
      brain.racks.insert_or_assign(rackB.uuid, &rackB);
      brain.racks.insert_or_assign(rackC.uuid, &rackC);

      ScopedSocketPair socketA = {};
      ScopedSocketPair socketB = {};
      ScopedSocketPair socketC = {};
      bool socketsReady =
         socketA.create(suite, "deploy_stateful_initial_schedule_creates_socketpair_a")
         && socketB.create(suite, "deploy_stateful_initial_schedule_creates_socketpair_b")
         && socketC.create(suite, "deploy_stateful_initial_schedule_creates_socketpair_c");

      auto seedMachine = [&] (
         Machine& machine,
         Rack& rack,
         uint128_t uuid,
         uint32_t private4,
         const String& slug,
         ScopedSocketPair& sockets) -> bool {
         machine.uuid = uuid;
         machine.private4 = private4;
         machine.slug = slug;
         machine.rack = &rack;
         machine.state = MachineState::healthy;
         machine.lifetime = MachineLifetime::owned;
         machine.isBrain = true;
         machine.hardware.inventoryComplete = true;
         machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
         machine.hardware.cpu.logicalCores = 8;
         machine.hardware.memory.totalMB = 8'192;
         machine.ownedLogicalCores = 8;
         machine.ownedMemoryMB = 8'192;
         machine.ownedStorageMB = 4'096;
         machine.totalLogicalCores = 8;
         machine.totalMemoryMB = 8'192;
         machine.totalStorageMB = 4'096;
         machine.nLogicalCores_available = 8;
         machine.sharedCPUMillis_available = 0;
         machine.memoryMB_available = 8'192;
         machine.storageMB_available = 4'096;
         machine.neuron.machine = &machine;
         machine.neuron.fd = 100 + int(private4 & 0xffu);
         machine.neuron.isFixedFile = true;
         machine.neuron.fslot = sockets.adoptLeftIntoFixedFileSlot();
         machine.neuron.connected = (machine.neuron.fslot >= 0);
         rack.machines.insert(&machine);
         brain.machines.insert(&machine);
         return machine.neuron.connected;
      };

      Machine machineA = {};
      Machine machineB = {};
      Machine machineC = {};
      bool machinesReady = socketsReady
         && seedMachine(machineA, rackA, uint128_t(0x19051901), 0x0a00000b, "deploy-stateful-a"_ctv, socketA)
         && seedMachine(machineB, rackB, uint128_t(0x19051902), 0x0a00000c, "deploy-stateful-b"_ctv, socketB)
         && seedMachine(machineC, rackC, uint128_t(0x19051903), 0x0a00000d, "deploy-stateful-c"_ctv, socketC);

      suite.expect(machinesReady, "deploy_stateful_initial_schedule_seeds_machine_neuron_control_streams");

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, true);
      deployment.plan.config.type = ApplicationType::stateful;
      deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
      deployment.plan.stateful.clientPrefix = (uint64_t(991) << 48) | (uint64_t(1) << 40);
      deployment.plan.stateful.siblingPrefix = (uint64_t(991) << 48) | (uint64_t(2) << 40);
      deployment.plan.stateful.cousinPrefix = (uint64_t(991) << 48) | (uint64_t(3) << 40);
      deployment.plan.stateful.seedingPrefix = (uint64_t(991) << 48) | (uint64_t(4) << 40);
      deployment.plan.stateful.shardingPrefix = (uint64_t(991) << 48) | (uint64_t(5) << 40);
      deployment.plan.stateful.allMasters = true;
      deployment.plan.stateful.neverShard = false;
      deployment.plan.stateful.seedingAlways = false;
      deployment.plan.canaryCount = 0;
      deployment.plan.canariesMustLiveForMinutes = 0;
      deployment.plan.moveConstructively = true;
      deployment.plan.useHostNetworkNamespace = false;
      deployment.plan.requiresDatacenterUniqueTag = false;
      deployment.plan.config.msTilHealthy = 10'000;
      deployment.plan.config.sTilHealthcheck = 15;
      deployment.plan.config.sTilKillable = 30;
      brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

      if (machinesReady)
      {
         deployment.deploy();

         uint32_t queuedMachineCount = 0;
         uint32_t queuedPairingTopics = 0;
         uint32_t queuedSpinTopics = 0;
         Machine *queuedMachine = nullptr;
         for (Machine *machine : {&machineA, &machineB, &machineC})
         {
            if (machine->neuron.pendingSend && machine->neuron.wBuffer.size() > 0)
            {
               queuedMachineCount += 1;
               queuedMachine = machine;
            }

            forEachMessageInBuffer(machine->neuron.wBuffer, [&] (Message *message) {
               NeuronTopic topic = NeuronTopic(message->topic);
               if (topic == NeuronTopic::advertisementPairing || topic == NeuronTopic::subscriptionPairing)
               {
                  queuedPairingTopics += 1;
               }
               else if (topic == NeuronTopic::spinContainer)
               {
                  queuedSpinTopics += 1;
               }
            });
         }

         suite.expect(deployment.state == DeploymentState::deploying, "deploy_stateful_initial_schedule_keeps_deployment_deploying_until_health_ack");
         suite.expect(deployment.nTargetBase == 3, "deploy_stateful_initial_schedule_targets_three_replicas");
         suite.expect(deployment.nDeployedBase == 3, "deploy_stateful_initial_schedule_architects_three_replicas");
         suite.expect(deployment.containers.size() == 3, "deploy_stateful_initial_schedule_tracks_three_planned_containers");
         suite.expect(deployment.waitingOnContainers.size() == 3, "deploy_stateful_initial_schedule_waits_on_all_initial_constructs");
         suite.expect(deployment.toSchedule.size() == 0, "deploy_stateful_initial_schedule_drains_construct_queue");
         suite.expect(deployment.schedulingStack.execution != nullptr, "deploy_stateful_initial_schedule_suspends_scheduler_while_waiting_on_health");
         suite.expect(queuedMachineCount == 3, "deploy_stateful_initial_schedule_queues_all_initial_neuron_spins");
         suite.expect(queuedSpinTopics == 3, "deploy_stateful_initial_schedule_queues_three_spin_messages");
         suite.expect(queuedPairingTopics == 0, "deploy_stateful_initial_schedule_keeps_startup_pairings_out_of_live_queue");
         suite.expect(queuedMachine != nullptr && queuedMachine->neuron.pendingSendBytes > 0, "deploy_stateful_initial_schedule_marks_neuron_spins_pending_send");
         suite.expect(brain.finCount == 0, "deploy_stateful_initial_schedule_does_not_finish_before_first_health_ack");
         suite.expect(brain.failureCount == 0, "deploy_stateful_initial_schedule_does_not_fail_healthy_fixture");
      }

      brain.deployments.erase(deployment.plan.config.deploymentID());
      rackA.machines.erase(&machineA);
      rackB.machines.erase(&machineB);
      rackC.machines.erase(&machineC);
      brain.machines.erase(&machineA);
      brain.machines.erase(&machineB);
      brain.machines.erase(&machineC);
      brain.racks.erase(rackA.uuid);
      brain.racks.erase(rackB.uuid);
      brain.racks.erase(rackC.uuid);
      thisBrain = savedBrain;
   }

   {
      ScopedFreshRing ring;
      TestBrain brain;
      BrainBase *savedBrain = thisBrain;
      thisBrain = &brain;

      Rack rackA{};
      rackA.uuid = 1960'1001;
      Rack rackB{};
      rackB.uuid = 1960'1002;
      Rack rackC{};
      rackC.uuid = 1960'1003;
      brain.racks.insert_or_assign(rackA.uuid, &rackA);
      brain.racks.insert_or_assign(rackB.uuid, &rackB);
      brain.racks.insert_or_assign(rackC.uuid, &rackC);

      ScopedSocketPair socketA = {};
      ScopedSocketPair socketB = {};
      ScopedSocketPair socketC = {};
      bool socketsReady =
         socketA.create(suite, "deploy_stateless_single_instance_creates_socketpair_a")
         && socketB.create(suite, "deploy_stateless_single_instance_creates_socketpair_b")
         && socketC.create(suite, "deploy_stateless_single_instance_creates_socketpair_c");

      auto seedMachine = [&] (
         Machine& machine,
         Rack& rack,
         uint128_t uuid,
         uint32_t private4,
         const String& slug,
         ScopedSocketPair& sockets) -> bool {
         machine.uuid = uuid;
         machine.private4 = private4;
         machine.slug = slug;
         machine.rack = &rack;
         machine.state = MachineState::healthy;
         machine.lifetime = MachineLifetime::owned;
         machine.isBrain = true;
         machine.hardware.inventoryComplete = true;
         machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
         machine.hardware.cpu.logicalCores = 8;
         machine.hardware.memory.totalMB = 8'192;
         machine.ownedLogicalCores = 8;
         machine.ownedMemoryMB = 8'192;
         machine.ownedStorageMB = 4'096;
         machine.totalLogicalCores = 8;
         machine.totalMemoryMB = 8'192;
         machine.totalStorageMB = 4'096;
         machine.nLogicalCores_available = 8;
         machine.sharedCPUMillis_available = 0;
         machine.memoryMB_available = 8'192;
         machine.storageMB_available = 4'096;
         machine.neuron.machine = &machine;
         machine.neuron.fd = 150 + int(private4 & 0xffu);
         machine.neuron.isFixedFile = true;
         machine.neuron.fslot = sockets.adoptLeftIntoFixedFileSlot();
         machine.neuron.connected = (machine.neuron.fslot >= 0);
         rack.machines.insert(&machine);
         brain.machines.insert(&machine);
         return machine.neuron.connected;
      };

      Machine machineA = {};
      Machine machineB = {};
      Machine machineC = {};
      bool machinesReady = socketsReady
         && seedMachine(machineA, rackA, uint128_t(0x19601001), 0x0a000015, "deploy-stateless-a"_ctv, socketA)
         && seedMachine(machineB, rackB, uint128_t(0x19601002), 0x0a000016, "deploy-stateless-b"_ctv, socketB)
         && seedMachine(machineC, rackC, uint128_t(0x19601003), 0x0a000017, "deploy-stateless-c"_ctv, socketC);

      suite.expect(machinesReady, "deploy_stateless_single_instance_seeds_machine_neuron_control_streams");

      ApplicationDeployment deployment;
      seedCommonPlan(deployment, false);
      deployment.plan.config.type = ApplicationType::stateless;
      deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
      deployment.plan.stateless.nBase = 1;
      deployment.plan.stateless.maxPerRackRatio = 1.0f;
      deployment.plan.stateless.maxPerMachineRatio = 1.0f;
      deployment.plan.canaryCount = 0;
      deployment.plan.canariesMustLiveForMinutes = 0;
      deployment.plan.moveConstructively = true;
      deployment.plan.useHostNetworkNamespace = false;
      deployment.plan.requiresDatacenterUniqueTag = false;
      deployment.plan.config.msTilHealthy = 10'000;
      deployment.plan.config.sTilHealthcheck = 15;
      deployment.plan.config.sTilKillable = 30;
      brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

      if (machinesReady)
      {
         deployment.deploy();

         uint32_t queuedMachineCount = 0;
         for (Machine *machine : {&machineA, &machineB, &machineC})
         {
            if (machine->neuron.pendingSend && machine->neuron.wBuffer.size() > 0)
            {
               queuedMachineCount += 1;
            }
         }

         suite.expect(deployment.state == DeploymentState::deploying, "deploy_stateless_single_instance_keeps_deployment_deploying_until_health_ack");
         suite.expect(deployment.nTargetBase == 1, "deploy_stateless_single_instance_targets_one_base");
         suite.expect(deployment.nTargetSurge == 0, "deploy_stateless_single_instance_targets_zero_surge");
         suite.expect(deployment.nTargetCanary == 0, "deploy_stateless_single_instance_targets_zero_canary");
         suite.expect(deployment.nDeployedBase == 1, "deploy_stateless_single_instance_architects_one_base");
         suite.expect(deployment.nDeployedSurge == 0, "deploy_stateless_single_instance_architects_zero_surge");
         suite.expect(deployment.containers.size() == 1, "deploy_stateless_single_instance_tracks_one_planned_container");
         suite.expect(deployment.waitingOnContainers.size() == 1, "deploy_stateless_single_instance_waits_on_one_construct");
         suite.expect(deployment.toSchedule.size() == 0, "deploy_stateless_single_instance_drains_construct_queue");
         suite.expect(deployment.schedulingStack.execution != nullptr, "deploy_stateless_single_instance_suspends_scheduler_while_waiting_on_health");
         suite.expect(queuedMachineCount == 1, "deploy_stateless_single_instance_queues_one_neuron_spin");
         suite.expect(brain.finCount == 0, "deploy_stateless_single_instance_does_not_finish_before_health_ack");
         suite.expect(brain.failureCount == 0, "deploy_stateless_single_instance_does_not_fail_healthy_fixture");
      }

      brain.deployments.erase(deployment.plan.config.deploymentID());
      rackA.machines.erase(&machineA);
      rackB.machines.erase(&machineB);
      rackC.machines.erase(&machineC);
      brain.machines.erase(&machineA);
      brain.machines.erase(&machineB);
      brain.machines.erase(&machineC);
      brain.racks.erase(rackA.uuid);
      brain.racks.erase(rackB.uuid);
      brain.racks.erase(rackC.uuid);
      thisBrain = savedBrain;
   }

   return (suite.failed == 0) ? 0 : 1;
}
