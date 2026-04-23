#include <prodigy/remote.bootstrap.h>
#include "prodigy_test_ssh_keys.h"
#include <services/debug.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

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

static bool requireEnv(const char *name, String& value)
{
   const char *env = std::getenv(name);
   if (env == nullptr || env[0] == '\0')
   {
      basics_log("missing env: %s\n", name);
      return false;
   }

   value.assign(env);
   return true;
}

static bool readFile(const String& path, String& content)
{
   String pathText = {};
   pathText.assign(path);

   FILE *file = std::fopen(pathText.c_str(), "rb");
   if (file == nullptr)
   {
      return false;
   }

   content.clear();
   char buffer[4096];
   while (true)
   {
      size_t readBytes = std::fread(buffer, 1, sizeof(buffer), file);
      if (readBytes > 0)
      {
         content.append(reinterpret_cast<const uint8_t *>(buffer), readBytes);
      }

      if (readBytes < sizeof(buffer))
      {
         break;
      }
   }

   std::fclose(file);
   return true;
}

static bool fileExists(const String& path)
{
   String pathText = {};
   pathText.assign(path);

   struct stat status = {};
   return ::stat(pathText.c_str(), &status) == 0;
}

static bool stringContains(const String& haystack, const char *needle)
{
   String text = {};
   text.assign(haystack);
   return std::strstr(text.c_str(), needle) != nullptr;
}

static bool readLocalMachineResources(const String& stateDir, ProdigyRemoteMachineResources& resources)
{
   resources = {};
   (void)stateDir;

   long logicalCores = ::sysconf(_SC_NPROCESSORS_ONLN);
   if (logicalCores <= 0)
   {
      return false;
   }

   FILE *meminfo = std::fopen("/proc/meminfo", "rb");
   if (meminfo == nullptr)
   {
      return false;
   }

   char line[256];
   unsigned long long memKB = 0;
   while (std::fgets(line, sizeof(line), meminfo) != nullptr)
   {
      if (std::strncmp(line, "MemTotal:", 9) == 0)
      {
         char *cursor = line + 9;
         while (*cursor != '\0' && std::isspace(unsigned(*cursor)))
         {
            cursor += 1;
         }

         char *tail = nullptr;
         memKB = std::strtoull(cursor, &tail, 10);
         break;
      }
   }

   std::fclose(meminfo);
   if (memKB == 0)
   {
      return false;
   }

   resources.totalLogicalCores = uint32_t(logicalCores);
   resources.totalMemoryMB = uint32_t(memKB / 1024ULL);
    return true;
}

int main(void)
{
   TestSuite suite;

   String masterIP;
   String targetIP;
   String sshKeyPath;
   String bootstrapSeedKeyPath;
   String remoteBootstrapSeedKeyPath;
   String remoteRoot;
   String stateDir;
   String systemdDir;
   String systemctlLogPath;

   if (requireEnv("PRODIGY_REMOTE_BOOTSTRAP_MASTER_IP", masterIP) == false
      || requireEnv("PRODIGY_REMOTE_BOOTSTRAP_TARGET_IP", targetIP) == false
      || requireEnv("PRODIGY_REMOTE_BOOTSTRAP_SSH_KEY", sshKeyPath) == false
      || requireEnv("PRODIGY_REMOTE_BOOTSTRAP_SEED_KEY", bootstrapSeedKeyPath) == false
      || requireEnv("PRODIGY_REMOTE_BOOTSTRAP_REMOTE_SEED_KEY", remoteBootstrapSeedKeyPath) == false
      || requireEnv("PRODIGY_REMOTE_BOOTSTRAP_REMOTE_ROOT", remoteRoot) == false
      || requireEnv("PRODIGY_REMOTE_BOOTSTRAP_STATE_DIR", stateDir) == false
      || requireEnv("PRODIGY_REMOTE_BOOTSTRAP_SYSTEMD_DIR", systemdDir) == false
      || requireEnv("PRODIGY_REMOTE_BOOTSTRAP_SYSTEMCTL_LOG", systemctlLogPath) == false)
   {
      return EXIT_FAILURE;
   }

   ClusterTopology topology = {};
   topology.version = 1;
   ClusterMachine master = {};
   master.source = ClusterMachineSource::adopted;
   master.backing = ClusterMachineBacking::cloud;
   master.kind = MachineConfig::MachineKind::vm;
   master.lifetime = MachineLifetime::owned;
   master.isBrain = true;
   master.cloud.schema = "brain-vm"_ctv;
   master.cloud.providerMachineType = "brain-vm"_ctv;
   master.cloud.cloudID = "987654321000111"_ctv;
   prodigyAppendUniqueClusterMachineAddress(master.addresses.privateAddresses, masterIP);
   topology.machines.push_back(master);

   String failure;
   ClusterMachine target = {};
   target.source = ClusterMachineSource::adopted;
   target.backing = ClusterMachineBacking::cloud;
   target.kind = MachineConfig::MachineKind::vm;
   target.lifetime = MachineLifetime::owned;
   target.isBrain = true;
   target.cloud.schema = "brain-vm"_ctv;
   target.cloud.providerMachineType = "brain-vm"_ctv;
   target.cloud.cloudID = "987654321000222"_ctv;
   target.ssh.address = targetIP;
   target.ssh.port = 2222;
   target.ssh.user = "root"_ctv;
   target.ssh.privateKeyPath = sshKeyPath;
   suite.expect(
      prodigyReadBootstrapSSHPublicKey(prodigyTestSSHDHostPrivateKeyPath(), target.ssh.hostPublicKeyOpenSSH, &failure),
      "smoke_load_target_ssh_host_public_key");
   suite.expect(failure.size() == 0, "smoke_load_target_ssh_host_public_key_clears_failure");
   prodigyAppendUniqueClusterMachineAddress(target.addresses.privateAddresses, targetIP);
   topology.machines.push_back(target);

   AddMachines request = {};
   request.bootstrapSshPrivateKeyPath = remoteBootstrapSeedKeyPath;
   suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
         bootstrapSeedKeyPath,
         request.bootstrapSshKeyPackage,
         &failure),
      "smoke_load_bootstrap_ssh_key_package");
   suite.expect(failure.size() == 0, "smoke_load_bootstrap_ssh_key_package_clears_failure");
   suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
         prodigyTestSSHDHostPrivateKeyPath(),
         request.bootstrapSshHostKeyPackage,
         &failure),
      "smoke_load_bootstrap_ssh_host_key_package");
   suite.expect(failure.size() == 0, "smoke_load_bootstrap_ssh_host_key_package_clears_failure");
   request.remoteProdigyPath = remoteRoot;
   request.controlSocketPath = "/run/prodigy/control.sock"_ctv;
   request.clusterUUID = 0x55005500;
   request.architecture = MachineCpuArchitecture::x86_64;

   ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
   runtimeEnvironment.kind = ProdigyEnvironmentKind::aws;
   runtimeEnvironment.providerScope = "us-test-1"_ctv;
   runtimeEnvironment.providerCredentialMaterial = "integration-key"_ctv;

   ProdigyRemoteBootstrapPlan plan = {};
   ProdigyRemoteMachineResources expectedResources = {};
   suite.expect(readLocalMachineResources(stateDir, expectedResources), "smoke_read_local_machine_resources");

   ProdigyRemoteMachineResources probedResources = {};
   suite.expect(prodigyProbeRemoteMachineResources(target, probedResources, &failure), "smoke_probe_remote_machine_resources");
   suite.expect(probedResources.totalLogicalCores == expectedResources.totalLogicalCores, "smoke_probe_remote_machine_resources_match_cores");
   suite.expect(probedResources.totalMemoryMB == expectedResources.totalMemoryMB, "smoke_probe_remote_machine_resources_match_memory");
   suite.expect(probedResources.totalStorageMB > 0, "smoke_probe_remote_machine_resources_positive_storage");

   suite.expect(
      prodigyBuildRemoteBootstrapPlan(target, request, topology, runtimeEnvironment, plan, &failure),
      "smoke_build_plan"
   );
   suite.expect(plan.bootstrapSshKeyPackage == request.bootstrapSshKeyPackage, "smoke_plan_bootstrap_ssh_key_package");
   suite.expect(plan.remoteBootstrapSSHPrivateKeyPath == remoteBootstrapSeedKeyPath, "smoke_plan_remote_bootstrap_seed_key_path");
   if (suite.failed != 0)
   {
      return EXIT_FAILURE;
   }

   suite.expect(prodigyExecuteRemoteBootstrapPlan(plan, &failure), "smoke_execute_plan");
   if (suite.failed != 0)
   {
      basics_log("smoke_execute_plan failure=%s\n", failure.c_str());
      return EXIT_FAILURE;
   }

   suite.expect(fileExists(plan.installPaths.binaryPath), "smoke_remote_binary_exists");
   suite.expect(fileExists(plan.installPaths.libraryDirectory), "smoke_remote_library_directory_exists");
   suite.expect(fileExists(plan.installPaths.bundlePath), "smoke_remote_bundle_exists");
   suite.expect(fileExists(plan.remoteBootstrapSSHPrivateKeyPath), "smoke_remote_bootstrap_ssh_private_key_exists");
   suite.expect(fileExists(plan.remoteBootstrapSSHPublicKeyPath), "smoke_remote_bootstrap_ssh_public_key_exists");

   String remoteBootstrapSeedPrivateKey = {};
   String remoteBootstrapSeedPublicKey = {};
   suite.expect(readFile(plan.remoteBootstrapSSHPrivateKeyPath, remoteBootstrapSeedPrivateKey), "smoke_read_remote_bootstrap_seed_private_key");
   suite.expect(readFile(plan.remoteBootstrapSSHPublicKeyPath, remoteBootstrapSeedPublicKey), "smoke_read_remote_bootstrap_seed_public_key");
   suite.expect(remoteBootstrapSeedPrivateKey.equals(plan.bootstrapSshKeyPackage.privateKeyOpenSSH), "smoke_remote_bootstrap_seed_private_key_matches");
   suite.expect(remoteBootstrapSeedPublicKey.equals(plan.bootstrapSshKeyPackage.publicKeyOpenSSH), "smoke_remote_bootstrap_seed_public_key_matches");

   String installedEBPFPath = plan.installPaths.installRoot;
   if (installedEBPFPath[installedEBPFPath.size() - 1] != '/')
   {
      installedEBPFPath.append('/');
   }
   installedEBPFPath.append("balancer.ebpf.o"_ctv);
   suite.expect(fileExists(installedEBPFPath), "smoke_remote_balancer_ebpf_exists");
   installedEBPFPath = plan.installPaths.installRoot;
   if (installedEBPFPath[installedEBPFPath.size() - 1] != '/')
   {
      installedEBPFPath.append('/');
   }
   installedEBPFPath.append("host.ingress.router.ebpf.o"_ctv);
   suite.expect(fileExists(installedEBPFPath), "smoke_remote_host_ingress_ebpf_exists");
   installedEBPFPath = plan.installPaths.installRoot;
   if (installedEBPFPath[installedEBPFPath.size() - 1] != '/')
   {
      installedEBPFPath.append('/');
   }
   installedEBPFPath.append("host.egress.router.ebpf.o"_ctv);
   suite.expect(fileExists(installedEBPFPath), "smoke_remote_host_egress_ebpf_exists");
   installedEBPFPath = plan.installPaths.installRoot;
   if (installedEBPFPath[installedEBPFPath.size() - 1] != '/')
   {
      installedEBPFPath.append('/');
   }
   installedEBPFPath.append("container.ingress.router.ebpf.o"_ctv);
   suite.expect(fileExists(installedEBPFPath), "smoke_remote_container_ingress_ebpf_exists");
   installedEBPFPath = plan.installPaths.installRoot;
   if (installedEBPFPath[installedEBPFPath.size() - 1] != '/')
   {
      installedEBPFPath.append('/');
   }
   installedEBPFPath.append("container.egress.router.ebpf.o"_ctv);
   suite.expect(fileExists(installedEBPFPath), "smoke_remote_container_egress_ebpf_exists");
   installedEBPFPath = plan.installPaths.installRoot;
   if (installedEBPFPath[installedEBPFPath.size() - 1] != '/')
   {
      installedEBPFPath.append('/');
   }
   installedEBPFPath.append("tunnel_to_nic.ebpf.o"_ctv);
   suite.expect(fileExists(installedEBPFPath), "smoke_remote_tunnel_to_nic_ebpf_exists");

   String unitPath = systemdDir;
   if (unitPath[unitPath.size() - 1] != '/')
   {
      unitPath.append('/');
   }
   unitPath.append("prodigy.service"_ctv);

   String renderedUnit;
   suite.expect(readFile(unitPath, renderedUnit), "smoke_read_rendered_unit");
   suite.expect(renderedUnit == plan.systemdUnit, "smoke_rendered_unit_matches_plan");

   String systemctlLog;
   suite.expect(readFile(systemctlLogPath, systemctlLog), "smoke_read_systemctl_log");
   suite.expect(stringContains(systemctlLog, "daemon-reload"), "smoke_systemctl_daemon_reload");
   suite.expect(stringContains(systemctlLog, "enable prodigy"), "smoke_systemctl_enable");
   suite.expect(stringContains(systemctlLog, "restart prodigy"), "smoke_systemctl_restart");

   ProdigyPersistentStateStore store(stateDir);
   ProdigyPersistentBootState loadedBootState = {};
   suite.expect(store.loadBootState(loadedBootState, &failure), "smoke_load_boot_state");

   ProdigyPersistentBootState expectedBootState = {};
   suite.expect(parseProdigyPersistentBootStateJSON(plan.bootJSON, expectedBootState, &failure), "smoke_parse_expected_boot_state");
   suite.expect(loadedBootState == expectedBootState, "smoke_boot_state_roundtrip");

   if (suite.failed != 0)
   {
      basics_log("remote_bootstrap_smoke failed=%d\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("remote_bootstrap_smoke ok\n");
   return EXIT_SUCCESS;
}
