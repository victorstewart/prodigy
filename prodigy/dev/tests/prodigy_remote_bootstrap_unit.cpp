#include <prodigy/remote.bootstrap.h>
#include <prodigy/mothership/mothership.ssh.h>
#include <services/debug.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/dev/tests/prodigy_test_ssh_keys.h>

#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <filesystem>
#include <netinet/in.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
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
         if (name != nullptr)
         {
            (void)::write(STDERR_FILENO, "FAIL: ", 6);
            (void)::write(STDERR_FILENO, name, std::strlen(name));
            (void)::write(STDERR_FILENO, "\n", 1);
         }
         failed += 1;
      }
   }
};

class ScopedEnvVar
{
public:

   String name = {};
   String previousValue = {};
   bool hadPreviousValue = false;

   ScopedEnvVar(const char *envName, const String& value)
   {
      name.assign(envName);
      const char *existing = std::getenv(envName);
      if (existing != nullptr)
      {
         hadPreviousValue = true;
         previousValue.assign(existing);
      }

      String valueText = {};
      valueText.assign(value);
      setenv(envName, valueText.c_str(), 1);
   }

   ~ScopedEnvVar()
   {
      if (hadPreviousValue)
      {
         setenv(name.c_str(), previousValue.c_str(), 1);
      }
      else
      {
         unsetenv(name.c_str());
      }
   }
};

static bool stringContains(const String& haystack, const char *needle)
{
   String text = {};
   text.assign(haystack);
   return std::strstr(text.c_str(), needle) != nullptr;
}

static bool stringEndsWith(const String& haystack, const String& needle)
{
   if (needle.size() > haystack.size())
   {
      return false;
   }

   return std::memcmp(haystack.data() + (haystack.size() - needle.size()), needle.data(), size_t(needle.size())) == 0;
}

static void expectStringEqual(TestSuite& suite, const String& actual, const String& expected, const char *name)
{
   if (actual.equals(expected))
   {
      suite.expect(true, name);
      return;
   }

   String actualText = {};
   actualText.assign(actual);
   String expectedText = {};
   expectedText.assign(expected);
   basics_log("DETAIL: %s actual='%s' expected='%s'\n", name, actualText.c_str(), expectedText.c_str());
   suite.expect(false, name);
}

static void expectBootstrapPeerCandidate(TestSuite& suite, const ProdigyBootstrapConfig::BootstrapPeer& peer, uint32_t index, const String& expectedAddress, uint8_t expectedCidr, const char *name)
{
   if (peer.addresses.size() <= index)
   {
      suite.expect(false, name);
      return;
   }

   suite.expect(peer.addresses[index].address.equals(expectedAddress) && peer.addresses[index].cidr == expectedCidr, name);
}

static bool ensureDirectory(const String& path)
{
   String pathText = {};
   pathText.assign(path);
   if (::mkdir(pathText.c_str(), 0755) == 0)
   {
      return true;
   }

   return errno == EEXIST;
}

static bool readFile(const String& path, String& content)
{
   content.clear();
   String pathText = {};
   pathText.assign(path);
   FILE *file = std::fopen(pathText.c_str(), "rb");
   if (file == nullptr)
   {
      return false;
   }

   char buffer[4096];
   while (true)
   {
      size_t nRead = std::fread(buffer, 1, sizeof(buffer), file);
      if (nRead > 0)
      {
         content.append(buffer, nRead);
      }

      if (nRead < sizeof(buffer))
      {
         bool okay = std::feof(file) != 0;
         std::fclose(file);
         return okay;
      }
   }
}

static bool writeFileWithMode(const String& path, const String& content, mode_t mode)
{
   String pathText = {};
   pathText.assign(path);
   FILE *file = std::fopen(pathText.c_str(), "wb");
   if (file == nullptr)
   {
      return false;
   }

   if (content.size() > 0 && std::fwrite(content.data(), 1, size_t(content.size()), file) != size_t(content.size()))
   {
      std::fclose(file);
      return false;
   }

   if (std::fclose(file) != 0)
   {
      return false;
   }

   return ::chmod(pathText.c_str(), mode) == 0;
}

static bool resolveSSHDExecutablePath(String& path)
{
   constexpr const char *candidates[] = {
      "/usr/sbin/sshd",
      "/usr/bin/sshd",
   };

   path.clear();
   for (const char *candidate : candidates)
   {
      if (::access(candidate, X_OK) == 0)
      {
         path.assign(candidate);
         return true;
      }
   }

   return false;
}

static uint16_t reserveLoopbackPort(void)
{
   int fd = ::socket(AF_INET, SOCK_STREAM, 0);
   if (fd < 0)
   {
      return 0;
   }

   int reuse = 1;
   (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

   sockaddr_in address = {};
   address.sin_family = AF_INET;
   address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
   address.sin_port = 0;
   if (::bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0)
   {
      ::close(fd);
      return 0;
   }

   sockaddr_in bound = {};
   socklen_t boundSize = sizeof(bound);
   if (::getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &boundSize) != 0)
   {
      ::close(fd);
      return 0;
   }

   uint16_t port = ntohs(bound.sin_port);
   ::close(fd);
   return port;
}

static bool waitForLoopbackPort(uint16_t port, int timeoutMs)
{
   auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
   while (std::chrono::steady_clock::now() < deadline)
   {
      int fd = ::socket(AF_INET, SOCK_STREAM, 0);
      if (fd >= 0)
      {
         sockaddr_in address = {};
         address.sin_family = AF_INET;
         address.sin_port = htons(port);
         ::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

         int result = ::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address));
         ::close(fd);
         if (result == 0)
         {
            return true;
         }
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(50));
   }

   return false;
}

class ScopedSSHD
{
public:

   String root = {};
   String hostPublicKeyOpenSSH = {};
   String failure = {};
   uint16_t port = 0;
   pid_t pid = -1;

   ScopedSSHD()
   {
      char scratch[] = "/tmp/prodigy-remote-bootstrap-sshd-XXXXXX";
      char *created = ::mkdtemp(scratch);
      if (created == nullptr)
      {
         failure.assign("failed to create sshd temp directory"_ctv);
         return;
      }

      root.assign(created);
      port = reserveLoopbackPort();
      if (port == 0)
      {
         failure.assign("failed to reserve ssh loopback port"_ctv);
         return;
      }

      String hostPrivateKey = {};
      String hostPublicKey = {};
      String clientPublicKey = {};
      if (readFile(prodigyTestSSHDHostPrivateKeyPath(), hostPrivateKey) == false
         || readFile(prodigyTestSSHDHostPublicKeyPath(), hostPublicKey) == false
         || readFile(prodigyTestClientSSHPublicKeyPath(), clientPublicKey) == false)
      {
         failure.assign("failed to load ssh fixture keys"_ctv);
         return;
      }

      hostPublicKeyOpenSSH.assign(hostPublicKey);

      String hostKeyPath = {};
      hostKeyPath.snprintf<"{}/host_ed25519_key"_ctv>(root);
      String authorizedKeysPath = {};
      authorizedKeysPath.snprintf<"{}/authorized_keys"_ctv>(root);
      String pidPath = {};
      pidPath.snprintf<"{}/sshd.pid"_ctv>(root);
      String logPath = {};
      logPath.snprintf<"{}/sshd.log"_ctv>(root);
      String configPath = {};
      configPath.snprintf<"{}/sshd_config"_ctv>(root);

      if (writeFileWithMode(hostKeyPath, hostPrivateKey, 0600) == false
         || writeFileWithMode(authorizedKeysPath, clientPublicKey, 0600) == false)
      {
         failure.assign("failed to write sshd fixture files"_ctv);
         return;
      }

      String config = {};
      config.snprintf<"Port {itoa}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nPermitRootLogin yes\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nChallengeResponseAuthentication no\nUsePAM no\nStrictModes no\nAuthorizedKeysFile {}\nSubsystem sftp internal-sftp\nLogLevel VERBOSE\n"_ctv>(
         uint64_t(port),
         hostKeyPath,
         pidPath,
         authorizedKeysPath);
      if (writeFileWithMode(configPath, config, 0644) == false)
      {
         failure.assign("failed to write sshd config"_ctv);
         return;
      }

      String sshdPath = {};
      if (resolveSSHDExecutablePath(sshdPath) == false)
      {
         failure.assign("sshd executable not found"_ctv);
         return;
      }

      pid = ::fork();
      if (pid == 0)
      {
         execl(sshdPath.c_str(), sshdPath.c_str(), "-D", "-e", "-f", configPath.c_str(), "-E", logPath.c_str(), nullptr);
         _exit(127);
      }

      if (pid < 0)
      {
         failure.assign("failed to fork sshd"_ctv);
         pid = -1;
         return;
      }

      if (waitForLoopbackPort(port, 3000) == false)
      {
         String logContent = {};
         if (readFile(logPath, logContent) && logContent.size() > 0)
         {
            failure.assign(logContent);
         }
         else
         {
            failure.assign("sshd did not become ready"_ctv);
         }

         ::kill(pid, SIGTERM);
         (void)::waitpid(pid, nullptr, 0);
         pid = -1;
      }
   }

   ~ScopedSSHD()
   {
      if (pid > 0)
      {
         ::kill(pid, SIGTERM);
         (void)::waitpid(pid, nullptr, 0);
      }

      if (root.size() > 0)
      {
         String rootText = {};
         rootText.assign(root);
         std::error_code cleanupError = {};
         std::filesystem::remove_all(std::filesystem::path(rootText.c_str()), cleanupError);
      }
   }

   bool ready(void) const
   {
      return pid > 0 && failure.size() == 0;
   }
};

static void appendRootedPath(const String& root, const String& absolutePath, String& rootedPath)
{
   rootedPath.assign(root);
   if (absolutePath.size() > 0 && absolutePath[0] != '/')
   {
      rootedPath.append('/');
   }
   rootedPath.append(absolutePath);
}

static const ClusterMachine *findMachineByCloudID(const ClusterTopology& topology, const String& cloudID)
{
   for (const ClusterMachine& machine : topology.machines)
   {
      if (machine.cloud.cloudID.equals(cloudID))
      {
         return &machine;
      }
   }

   return nullptr;
}

static ClusterMachine makeBrainMachine(const String& cloudID, const String& privateAddress)
{
   ClusterMachine machine = {};
   machine.source = ClusterMachineSource::adopted;
   machine.backing = ClusterMachineBacking::cloud;
   machine.kind = MachineConfig::MachineKind::vm;
   machine.lifetime = MachineLifetime::owned;
   machine.isBrain = true;
   machine.cloud.schema.assign("brain-vm"_ctv);
   machine.cloud.providerMachineType.assign("brain-vm"_ctv);
   machine.cloud.cloudID.assign(cloudID);
   if (privateAddress.size() > 0)
   {
      prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, privateAddress);
   }
   return machine;
}

static bool topologyMatchesWithAssignedUUIDs(const ClusterTopology& expected, const ClusterTopology& actual)
{
   if (expected.version != actual.version || expected.machines.size() != actual.machines.size())
   {
      return false;
   }

   for (uint32_t index = 0; index < expected.machines.size(); ++index)
   {
      const ClusterMachine& actualMachine = actual.machines[index];
      if (actualMachine.uuid == 0)
      {
         return false;
      }

      ClusterMachine expectedMachine = expected.machines[index];
      expectedMachine.uuid = actualMachine.uuid;
      if (expectedMachine != actualMachine)
      {
         return false;
      }
   }

   return true;
}

class NestedCoroutineConsumeProbe : public CoroutineStack
{
public:

   bool leafResumed = false;
   bool middleResumed = false;
   bool rootResumed = false;

   void leaf(void)
   {
      co_await suspend();
      leafResumed = true;
   }

   void middle(void)
   {
      uint32_t suspendIndex = nextSuspendIndex();
      leaf();
      if (suspendIndex < nextSuspendIndex())
      {
         co_await suspendAtIndex(suspendIndex);
      }

      middleResumed = true;
   }

   void root(void)
   {
      uint32_t suspendIndex = nextSuspendIndex();
      middle();
      if (suspendIndex < nextSuspendIndex())
      {
         co_await suspendAtIndex(suspendIndex);
      }

      rootResumed = true;
   }
};

int main(void)
{
   TestSuite suite;
   String failure;

   String resolvedBootstrapUser = {};
   prodigyResolveBootstrapSSHUser(""_ctv, resolvedBootstrapUser);
   suite.expect(resolvedBootstrapUser.equals("root"_ctv), "bootstrap_ssh_user_defaults_to_root");
   prodigyResolveBootstrapSSHUser("ubuntu"_ctv, resolvedBootstrapUser);
   suite.expect(resolvedBootstrapUser.equals("ubuntu"_ctv), "bootstrap_ssh_user_preserves_configured_user");

   NestedCoroutineConsumeProbe coroutineProbe = {};
   coroutineProbe.root();
   suite.expect(coroutineProbe.hasSuspendedCoroutines(), "coroutine_stack_nested_probe_suspends");
   coroutineProbe.co_consume();
   suite.expect(coroutineProbe.leafResumed, "coroutine_stack_co_consume_unwinds_leaf");
   suite.expect(coroutineProbe.middleResumed, "coroutine_stack_co_consume_unwinds_middle");
   suite.expect(coroutineProbe.rootResumed, "coroutine_stack_co_consume_unwinds_root");
   suite.expect(coroutineProbe.hasSuspendedCoroutines() == false, "coroutine_stack_co_consume_drains_completed_stack");

   String bootstrapPublicKey = {};
   suite.expect(
      prodigyReadBootstrapSSHPublicKey(prodigyTestBootstrapSeedSSHPrivateKeyPath(), bootstrapPublicKey, &failure),
      "bootstrap_ssh_public_key_reads_from_fixture"
   );
   suite.expect(failure.size() == 0, "bootstrap_ssh_public_key_read_clears_failure");
   Vault::SSHKeyPackage bootstrapHostKeyPackage = {};
   suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
         prodigyTestSSHDHostPrivateKeyPath(),
         bootstrapHostKeyPackage,
         &failure),
      "bootstrap_ssh_host_key_package_reads_from_fixture"
   );
   suite.expect(failure.size() == 0, "bootstrap_ssh_host_key_package_read_clears_failure");

   String bootstrapUserData = {};
   prodigyBuildBootstrapSSHUserData(""_ctv, bootstrapPublicKey, bootstrapHostKeyPackage, bootstrapUserData);
   suite.expect(stringContains(bootstrapUserData, "BOOTSTRAP_USER='root'"), "bootstrap_user_data_defaults_root_user");
   suite.expect(stringContains(bootstrapUserData, "PermitRootLogin prohibit-password"), "bootstrap_user_data_enforces_pubkey_only_root_login");
   suite.expect(stringContains(bootstrapUserData, "PasswordAuthentication no"), "bootstrap_user_data_disables_password_auth");
   suite.expect(stringContains(bootstrapUserData, "PubkeyAuthentication yes"), "bootstrap_user_data_enables_pubkey_auth");
   suite.expect(stringContains(bootstrapUserData, "install_key \"$BOOTSTRAP_USER\" \"$BOOTSTRAP_HOME\""), "bootstrap_user_data_installs_authorized_key");
   suite.expect(stringContains(bootstrapUserData, "BOOTSTRAP_HOST_PRIVATE_KEY='-----BEGIN OPENSSH PRIVATE KEY-----"), "bootstrap_user_data_embeds_host_private_key");
   suite.expect(stringContains(bootstrapUserData, bootstrapHostKeyPackage.publicKeyOpenSSH.c_str()), "bootstrap_user_data_embeds_host_public_key");
   suite.expect(stringContains(bootstrapUserData, bootstrapPublicKey.c_str()), "bootstrap_user_data_embeds_public_key");

   String nonRootBootstrapUserData = {};
   prodigyBuildBootstrapSSHUserData("ubuntu"_ctv, bootstrapPublicKey, bootstrapHostKeyPackage, nonRootBootstrapUserData);
   suite.expect(stringContains(nonRootBootstrapUserData, "BOOTSTRAP_USER='ubuntu'"), "bootstrap_user_data_uses_configured_user");
   suite.expect(stringContains(nonRootBootstrapUserData, "ensure_user \"$BOOTSTRAP_USER\""), "bootstrap_user_data_creates_missing_non_root_user");
   suite.expect(stringContains(nonRootBootstrapUserData, "/etc/sudoers.d/99-prodigy-bootstrap") == false, "bootstrap_user_data_omits_non_root_sudo");

   String bootstrapCloudConfig = {};
   prodigyBuildBootstrapSSHCloudConfig(""_ctv, bootstrapPublicKey, bootstrapHostKeyPackage, bootstrapCloudConfig);
   suite.expect(stringContains(bootstrapCloudConfig, "#cloud-config"), "bootstrap_cloud_config_header");
   suite.expect(stringContains(bootstrapCloudConfig, "disable_root: false"), "bootstrap_cloud_config_disables_root_lockout");
   suite.expect(stringContains(bootstrapCloudConfig, "name: root"), "bootstrap_cloud_config_targets_root_user");
   suite.expect(stringContains(bootstrapCloudConfig, "PermitRootLogin prohibit-password"), "bootstrap_cloud_config_enables_root_pubkey_login");
   suite.expect(stringContains(bootstrapCloudConfig, "path: /etc/ssh/ssh_host_ed25519_key"), "bootstrap_cloud_config_writes_host_private_key");
   suite.expect(stringContains(bootstrapCloudConfig, bootstrapHostKeyPackage.publicKeyOpenSSH.c_str()), "bootstrap_cloud_config_embeds_host_public_key");
   suite.expect(stringContains(bootstrapCloudConfig, bootstrapPublicKey.c_str()), "bootstrap_cloud_config_embeds_public_key");

   String nonRootBootstrapCloudConfig = {};
   prodigyBuildBootstrapSSHCloudConfig("ubuntu"_ctv, bootstrapPublicKey, bootstrapHostKeyPackage, nonRootBootstrapCloudConfig);
   suite.expect(stringContains(nonRootBootstrapCloudConfig, "name: ubuntu"), "bootstrap_cloud_config_uses_configured_non_root_user");
   suite.expect(stringContains(nonRootBootstrapCloudConfig, "sudo: ALL=(ALL) NOPASSWD:ALL") == false, "bootstrap_cloud_config_omits_non_root_sudo");
   suite.expect(stringContains(nonRootBootstrapCloudConfig, "groups: [adm, sudo]") == false, "bootstrap_cloud_config_omits_non_root_sudo_groups");

   ScopedSSHD sshd = {};
   suite.expect(sshd.ready(), "blocking_ssh_fixture_ready");
   if (sshd.ready() == false && sshd.failure.size() > 0)
   {
      basics_log("DETAIL: blocking_ssh_fixture_failure='%s'\n", sshd.failure.c_str());
   }
   if (sshd.ready())
   {
      String expectedHostMismatchFailure = {};
      expectedHostMismatchFailure.snprintf<"ssh host key mismatch for 127.0.0.1:{itoa}"_ctv>(uint64_t(sshd.port));

      {
         LIBSSH2_SESSION *session = nullptr;
         int fd = -1;
         suite.expect(
            prodigyConnectBlockingSSHSession(
               "127.0.0.1"_ctv,
               sshd.port,
               sshd.hostPublicKeyOpenSSH,
               "root"_ctv,
               prodigyTestClientSSHPrivateKeyPath(),
               session,
               fd,
               &failure),
            "blocking_ssh_session_accepts_pinned_host_key");
         suite.expect(failure.size() == 0, "blocking_ssh_session_accepts_pinned_host_key_clears_failure");
         prodigyCloseBlockingSSHSession(session, fd);
      }

      {
         LIBSSH2_SESSION *session = nullptr;
         int fd = -1;
         suite.expect(
            prodigyConnectBlockingSSHSession(
               "127.0.0.1"_ctv,
               sshd.port,
               bootstrapPublicKey,
               "root"_ctv,
               prodigyTestClientSSHPrivateKeyPath(),
               session,
               fd,
               &failure) == false,
            "blocking_ssh_session_rejects_host_key_mismatch");
         suite.expect(failure.equals(expectedHostMismatchFailure), "blocking_ssh_session_rejects_host_key_mismatch_reason");
         prodigyCloseBlockingSSHSession(session, fd);
      }

      {
         MothershipProdigyClusterMachine machine = {};
         machine.ssh.address.assign("127.0.0.1"_ctv);
         machine.ssh.port = sshd.port;
         machine.ssh.user.assign("root"_ctv);
         machine.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
         machine.ssh.hostPublicKeyOpenSSH = sshd.hostPublicKeyOpenSSH;

         LIBSSH2_SESSION *session = nullptr;
         int fd = -1;
         suite.expect(
            mothershipConnectSSHSession(
               machine,
               session,
               fd,
               &failure),
            "mothership_ssh_session_accepts_pinned_host_key");
         suite.expect(failure.size() == 0, "mothership_ssh_session_accepts_pinned_host_key_clears_failure");
         mothershipCloseSSHSession(session, fd);

         machine.ssh.hostPublicKeyOpenSSH = bootstrapPublicKey;
         suite.expect(
            mothershipConnectSSHSession(
               machine,
               session,
               fd,
               &failure) == false,
            "mothership_ssh_session_rejects_host_key_mismatch");
         suite.expect(failure.equals(expectedHostMismatchFailure), "mothership_ssh_session_rejects_host_key_mismatch_reason");
         mothershipCloseSSHSession(session, fd);
      }
   }

   ClusterTopology topology = {};
   topology.version = 11;
   topology.machines.push_back(makeBrainMachine("brain-b"_ctv, "10.0.0.30"_ctv));
   topology.machines.push_back(makeBrainMachine("brain-a"_ctv, "10.0.0.29"_ctv));
   topology.machines.push_back(makeBrainMachine("brain-dup"_ctv, "10.0.0.30"_ctv));

   ClusterMachine worker = {};
   worker.source = ClusterMachineSource::adopted;
   worker.backing = ClusterMachineBacking::cloud;
   worker.kind = MachineConfig::MachineKind::vm;
   worker.lifetime = MachineLifetime::ondemand;
   worker.isBrain = false;
   worker.cloud.schema.assign("worker-vm"_ctv);
   worker.cloud.providerMachineType.assign("worker-vm"_ctv);
   worker.cloud.cloudID.assign("987654321000333"_ctv);
   prodigyAppendUniqueClusterMachineAddress(worker.addresses.privateAddresses, "10.0.0.40"_ctv);
   topology.machines.push_back(worker);

   AddMachines request = {};
   request.bootstrapSshPrivateKeyPath = prodigyTestBootstrapSeedSSHPrivateKeyPath();
   suite.expect(
      prodigyReadSSHKeyPackageFromPrivateKeyPath(
         request.bootstrapSshPrivateKeyPath,
         request.bootstrapSshKeyPackage,
         &failure),
      "load_bootstrap_ssh_key_package");
   suite.expect(failure.size() == 0, "load_bootstrap_ssh_key_package_clears_failure");
   request.bootstrapSshHostKeyPackage = bootstrapHostKeyPackage;
   request.remoteProdigyPath.assign("/opt/prodigy-root"_ctv);
   request.controlSocketPath.assign("/run/prodigy/control.sock"_ctv);
   request.clusterUUID = 0x44014401;
   request.architecture = MachineCpuArchitecture::x86_64;

   ClusterMachine target = {};
   target.source = ClusterMachineSource::created;
   target.backing = ClusterMachineBacking::cloud;
   target.kind = MachineConfig::MachineKind::vm;
   target.lifetime = MachineLifetime::ondemand;
   target.isBrain = true;
   target.cloud.schema.assign("brain-vm"_ctv);
   target.cloud.providerMachineType.assign("brain-vm"_ctv);
   target.cloud.cloudID.assign("987654321000444"_ctv);
   prodigyAppendUniqueClusterMachineAddress(target.addresses.privateAddresses, "10.0.0.31"_ctv);
   target.ssh.user.assign("root"_ctv);
   target.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   target.ssh.hostPublicKeyOpenSSH = bootstrapHostKeyPackage.publicKeyOpenSSH;

   ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
   runtimeEnvironment.kind = ProdigyEnvironmentKind::aws;
   runtimeEnvironment.providerScope.assign("us-east-1"_ctv);
   runtimeEnvironment.providerCredentialMaterial.assign("aws-secret"_ctv);
   runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.assign("aws configure export-credentials --format process"_ctv);
   runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.assign("run `aws sso login`"_ctv);
   runtimeEnvironment.aws.instanceProfileName.assign("prodigy-controller-profile"_ctv);
   ProdigyRuntimeEnvironmentConfig expectedRuntimeEnvironment = runtimeEnvironment;
   String resolvedRegion = {};
   suite.expect(prodigyResolveProviderScopeRegion(runtimeEnvironment.providerScope, resolvedRegion), "runtime_environment_region_resolves_without_scope_prefix");
   suite.expect(resolvedRegion.equals("us-east-1"_ctv), "runtime_environment_region_preserves_plain_region");
   suite.expect(prodigyResolveProviderScopeRegion("aws/us-east-1"_ctv, resolvedRegion), "runtime_environment_region_resolves_with_scope_prefix");
   suite.expect(resolvedRegion.equals("us-east-1"_ctv), "runtime_environment_region_extracts_suffix");
   expectedRuntimeEnvironment.providerCredentialMaterial.reset();
   expectedRuntimeEnvironment.aws.bootstrapCredentialRefreshCommand.reset();
   expectedRuntimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.reset();
   prodigyApplyInternalRuntimeEnvironmentDefaults(expectedRuntimeEnvironment);

   ProdigyRemoteBootstrapPlan plan = {};
   suite.expect(
      prodigyBuildRemoteBootstrapPlan(target, request, topology, runtimeEnvironment, plan, &failure),
      "build_remote_bootstrap_plan"
   );
   suite.expect(failure.size() == 0, "build_remote_bootstrap_plan_clears_failure");
   ProdigyRemoteBootstrapPlan multiBrainPlan = plan;
   suite.expect(plan.ssh.address.equals("10.0.0.31"_ctv), "plan_uses_private_address_when_ssh_address_missing");
   suite.expect(plan.ssh.port == 22, "plan_defaults_ssh_port");
   suite.expect(plan.ssh.hostPublicKeyOpenSSH.equals(request.bootstrapSshHostKeyPackage.publicKeyOpenSSH), "plan_carries_ssh_host_public_key");
   String localExecutablePath = {};
   suite.expect(prodigyResolveCurrentExecutablePath(localExecutablePath), "resolve_current_executable_path");
   String expectedLocalBundlePath = {};
   suite.expect(prodigyResolvePreferredBootstrapBundleArtifact(localExecutablePath, request.architecture, request.remoteProdigyPath, expectedLocalBundlePath, &failure), "resolve_expected_local_bundle_path");
   suite.expect(failure.size() == 0, "resolve_expected_local_bundle_path_clears_failure");
   expectStringEqual(suite, plan.localBundlePath, expectedLocalBundlePath, "plan_local_bundle_path");
   suite.expect(plan.bootstrapSshKeyPackage == request.bootstrapSshKeyPackage, "plan_bootstrap_ssh_key_package");
   expectStringEqual(suite, plan.remoteBootstrapSSHPrivateKeyPath, prodigyTestBootstrapSeedSSHPrivateKeyPath(), "plan_remote_bootstrap_ssh_private_key_path");
   expectStringEqual(suite, plan.remoteBootstrapSSHPublicKeyPath, prodigyTestBootstrapSeedSSHPublicKeyPath(), "plan_remote_bootstrap_ssh_public_key_path");
   String expectedBootstrapSSHDirectory = {};
   prodigyDirname(plan.remoteBootstrapSSHPrivateKeyPath, expectedBootstrapSSHDirectory);
   expectStringEqual(suite, plan.bootstrapSSHDirectory, expectedBootstrapSSHDirectory, "plan_bootstrap_ssh_directory");
   expectStringEqual(suite, plan.installPaths.binaryPath, "/opt/prodigy-root/prodigy"_ctv, "plan_remote_binary_path");
   expectStringEqual(suite, plan.installPaths.libraryDirectory, "/opt/prodigy-root/lib"_ctv, "plan_remote_library_directory");
   expectStringEqual(suite, plan.installPaths.bundlePath, "/opt/prodigy-root/prodigy.bundle.tar.zst"_ctv, "plan_remote_bundle_path");
   expectStringEqual(suite, plan.installPaths.bundleSHA256Path, "/opt/prodigy-root/prodigy.bundle.tar.zst.sha256"_ctv, "plan_remote_bundle_sha256_path");
   expectStringEqual(suite, plan.installPaths.bundleTempPath, "/opt/prodigy.bundle.tar.zst.tmp"_ctv, "plan_remote_bundle_temp_path");
   expectStringEqual(suite, plan.installPaths.bundleSHA256TempPath, "/root/prodigy.bundle.new.tar.zst.sha256"_ctv, "plan_remote_bundle_sha256_temp_path");
   expectStringEqual(suite, plan.remoteStagePayloadPath, "/tmp/prodigy.remote-bootstrap.payload.tar"_ctv, "plan_remote_stage_payload_path");
   expectStringEqual(suite, plan.remoteUnitPath, "/etc/systemd/system/prodigy.service"_ctv, "plan_remote_unit_path");
   expectStringEqual(suite, plan.remoteUnitTempPath, "/opt/prodigy.service.tmp"_ctv, "plan_remote_unit_temp_path");
   suite.expect(plan.controlSocketDirectory == "/run/prodigy"_ctv, "plan_control_socket_directory");
   suite.expect(plan.connectRetryBudgetMs == uint64_t(Time::minsToMs(10)), "plan_created_machine_retry_budget");

   ProdigyPreparedRemoteBootstrapPlan prepared = {};
   suite.expect(prodigyPrepareRemoteBootstrapPlan(target, plan, prepared, &failure), "prepare_remote_bootstrap_payload");
   suite.expect(failure.size() == 0, "prepare_remote_bootstrap_payload_clears_failure");
   suite.expect(prodigyFileReadable(prepared.localStagePayloadPath), "prepared_stage_payload_exists");
   suite.expect(prepared.stagePayloadBytes > prepared.bundleBytes, "prepared_stage_payload_has_wrapper_bytes");

   char payloadExtractScratch[] = "/tmp/prodigy-remote-bootstrap-unit-extract-XXXXXX";
   char *payloadExtractRootRaw = ::mkdtemp(payloadExtractScratch);
   suite.expect(payloadExtractRootRaw != nullptr, "prepared_stage_payload_extract_root_created");
   if (payloadExtractRootRaw != nullptr)
   {
      String payloadExtractRoot = {};
      payloadExtractRoot.assign(payloadExtractRootRaw);
      String extractPayloadCommand = {};
      extractPayloadCommand.assign("tar -xf "_ctv);
      prodigyAppendShellSingleQuoted(extractPayloadCommand, prepared.localStagePayloadPath);
      extractPayloadCommand.append(" -C "_ctv);
      prodigyAppendShellSingleQuoted(extractPayloadCommand, payloadExtractRoot);
      suite.expect(prodigyRunLocalShellCommand(extractPayloadCommand, &failure), "prepared_stage_payload_extracts");
      suite.expect(failure.size() == 0, "prepared_stage_payload_extracts_clears_failure");

      String extractedPath = {};
      String extractedContent = {};
      appendRootedPath(payloadExtractRoot, plan.remoteBootJSONPath, extractedPath);
      suite.expect(readFile(extractedPath, extractedContent), "prepared_stage_payload_boot_json_readable");
      suite.expect(extractedContent.equals(plan.bootJSON), "prepared_stage_payload_boot_json_matches");

      appendRootedPath(payloadExtractRoot, plan.remoteTransportTLSJSONPath, extractedPath);
      suite.expect(readFile(extractedPath, extractedContent), "prepared_stage_payload_transport_tls_json_readable");
      suite.expect(extractedContent.equals(plan.transportTLSJSON), "prepared_stage_payload_transport_tls_json_matches");

      appendRootedPath(payloadExtractRoot, plan.remoteUnitTempPath, extractedPath);
      suite.expect(readFile(extractedPath, extractedContent), "prepared_stage_payload_unit_readable");
      suite.expect(extractedContent.equals(plan.systemdUnit), "prepared_stage_payload_unit_matches");

      appendRootedPath(payloadExtractRoot, plan.installPaths.bundleSHA256TempPath, extractedPath);
      suite.expect(readFile(extractedPath, extractedContent), "prepared_stage_payload_bundle_sha256_readable");
      suite.expect(extractedContent.equals(prepared.bundleSHA256Content), "prepared_stage_payload_bundle_sha256_matches");

      appendRootedPath(payloadExtractRoot, plan.installPaths.bundleTempPath, extractedPath);
      suite.expect(prodigyFileReadable(extractedPath), "prepared_stage_payload_bundle_present");
      suite.expect(prodigyMeasureLocalFileSize(extractedPath) == prepared.bundleBytes, "prepared_stage_payload_bundle_size_matches");

      appendRootedPath(payloadExtractRoot, plan.remoteBootstrapSSHPrivateKeyPath, extractedPath);
      suite.expect(prodigyFileReadable(extractedPath), "prepared_stage_payload_bootstrap_private_key_present");
      suite.expect(prodigyMeasureLocalFileSize(extractedPath) == plan.bootstrapSshKeyPackage.privateKeyOpenSSH.size(), "prepared_stage_payload_bootstrap_private_key_size_matches");

      appendRootedPath(payloadExtractRoot, plan.remoteBootstrapSSHPublicKeyPath, extractedPath);
      suite.expect(prodigyFileReadable(extractedPath), "prepared_stage_payload_bootstrap_public_key_present");
      suite.expect(prodigyMeasureLocalFileSize(extractedPath) == plan.bootstrapSshKeyPackage.publicKeyOpenSSH.size(), "prepared_stage_payload_bootstrap_public_key_size_matches");

      std::error_code cleanupError = {};
      std::filesystem::remove_all(std::filesystem::path(payloadExtractRoot.c_str()), cleanupError);
   }
   prodigyCleanupPreparedRemoteBootstrapPayload(prepared);
   suite.expect(prepared.localStagePayloadPath.size() == 0, "prepared_stage_payload_cleanup_clears_path");

   char fallbackScratch[] = "/tmp/prodigy-remote-bootstrap-unit-XXXXXX";
   char *fallbackRootRaw = ::mkdtemp(fallbackScratch);
   suite.expect(fallbackRootRaw != nullptr, "fallback_bundle_mkdtemp_created");
   if (fallbackRootRaw != nullptr)
   {
      String fallbackRoot = {};
      fallbackRoot.assign(fallbackRootRaw);

      String fallbackXdgHome = {};
      fallbackXdgHome.snprintf<"{}/xdg-empty"_ctv>(fallbackRoot);
      suite.expect(ensureDirectory(fallbackXdgHome), "fallback_bundle_xdg_home_created");

      AddMachines fallbackRequest = request;
      fallbackRequest.remoteProdigyPath.snprintf<"{}/installed-root"_ctv>(fallbackRoot);
      suite.expect(ensureDirectory(fallbackRequest.remoteProdigyPath), "fallback_bundle_install_root_created");

      String fallbackInstalledBundlePath = {};
      prodigyResolveInstalledBundlePathForRoot(fallbackRequest.remoteProdigyPath, fallbackInstalledBundlePath);

      String sourceBundlePath = {};
      suite.expect(prodigyResolvePreferredBootstrapBundleArtifact(localExecutablePath, request.architecture, request.remoteProdigyPath, sourceBundlePath, &failure), "fallback_bundle_source_resolves");
      if (failure.size() == 0)
      {
         String sourceBundlePathText = {};
         sourceBundlePathText.assign(sourceBundlePath);
         String fallbackInstalledBundlePathText = {};
         fallbackInstalledBundlePathText.assign(fallbackInstalledBundlePath);
         suite.expect(::symlink(sourceBundlePathText.c_str(), fallbackInstalledBundlePathText.c_str()) == 0, "fallback_bundle_symlink_created");
      }

      {
         ScopedEnvVar xdgOverride("XDG_DATA_HOME", fallbackXdgHome);
         String fakeExecutablePath = {};
         fakeExecutablePath.snprintf<"{}/fake-bin/mothership"_ctv>(fallbackRoot);
         String fakeExecutableDir = {};
         prodigyDirname(fakeExecutablePath, fakeExecutableDir);
         suite.expect(ensureDirectory(fakeExecutableDir), "fallback_bundle_fake_executable_dir_created");

         String fallbackResolvedBundlePath = {};
         suite.expect(
            prodigyResolvePreferredBootstrapBundleArtifact(fakeExecutablePath, fallbackRequest.architecture, fallbackRequest.remoteProdigyPath, fallbackResolvedBundlePath, &failure),
            "build_remote_bootstrap_plan_fallback_installed_bundle"
         );
         suite.expect(failure.size() == 0, "build_remote_bootstrap_plan_fallback_installed_bundle_clears_failure");
         expectStringEqual(suite, fallbackResolvedBundlePath, fallbackInstalledBundlePath, "plan_local_bundle_path_fallback_installed_root");
      }
   }

   ProdigyPersistentBootState parsedBootState = {};
   suite.expect(parseProdigyPersistentBootStateJSON(plan.bootJSON, parsedBootState, &failure), "plan_boot_json_parses");
   suite.expect(parsedBootState.bootstrapConfig.nodeRole == ProdigyBootstrapNodeRole::brain, "plan_boot_json_node_role");
   suite.expect(parsedBootState.bootstrapConfig.controlSocketPath.equals(request.controlSocketPath), "plan_boot_json_control_socket");
   suite.expect(parsedBootState.bootstrapSshUser.equals(request.bootstrapSshUser), "plan_boot_json_bootstrap_ssh_user");
   suite.expect(parsedBootState.bootstrapSshKeyPackage == request.bootstrapSshKeyPackage, "plan_boot_json_bootstrap_ssh_key_package");
   suite.expect(parsedBootState.bootstrapSshHostKeyPackage == request.bootstrapSshHostKeyPackage, "plan_boot_json_bootstrap_ssh_host_key_package");
   suite.expect(parsedBootState.bootstrapSshPrivateKeyPath.equals(request.bootstrapSshPrivateKeyPath), "plan_boot_json_bootstrap_ssh_private_key_path");
   suite.expect(plan.transportTLSJSON.size() > 0, "plan_transport_tls_json_nonempty");
   expectStringEqual(suite, plan.remoteTransportTLSJSONPath, "/var/lib/prodigy/transport.tls.json"_ctv, "plan_remote_transport_tls_json_path");
   suite.expect(stringContains(plan.installCommand, "--transport-tls-json-path="), "plan_install_command_transport_tls_flag");
   suite.expect(stringContains(plan.installCommand, "/var/lib/prodigy/transport.tls.json"), "plan_install_command_transport_tls_path");
   suite.expect(stringContains(plan.installCommand, "/root/prodigy.bundle.new.tar.zst.sha256"), "plan_install_command_bundle_sha256_temp_path");
   suite.expect(stringContains(plan.installCommand, "/opt/prodigy-root.new/prodigy.bundle.tar.zst.sha256"), "plan_install_command_bundle_sha256_path");
   suite.expect(parsedBootState.bootstrapConfig.bootstrapPeers.size() == 2, "plan_boot_json_deduped_brain_peers");
   suite.expect(parsedBootState.bootstrapConfig.bootstrapPeers[0].addresses.size() == 1, "plan_boot_json_sorted_peer_0_candidate_count");
   expectBootstrapPeerCandidate(suite, parsedBootState.bootstrapConfig.bootstrapPeers[0], 0, "10.0.0.29"_ctv, 0, "plan_boot_json_sorted_peer_0");
   suite.expect(parsedBootState.bootstrapConfig.bootstrapPeers[1].addresses.size() == 1, "plan_boot_json_sorted_peer_1_candidate_count");
   expectBootstrapPeerCandidate(suite, parsedBootState.bootstrapConfig.bootstrapPeers[1], 0, "10.0.0.30"_ctv, 0, "plan_boot_json_sorted_peer_1");
   suite.expect(parsedBootState.runtimeEnvironment == expectedRuntimeEnvironment, "plan_boot_json_runtime_environment");
   suite.expect(parsedBootState.runtimeEnvironment.providerCredentialMaterial.size() == 0, "plan_boot_json_runtime_environment_secret_stripped");
   suite.expect(parsedBootState.runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.size() == 0, "plan_boot_json_runtime_environment_refresh_command_stripped");
   suite.expect(parsedBootState.runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.size() == 0, "plan_boot_json_runtime_environment_refresh_hint_stripped");
   suite.expect(parsedBootState.runtimeEnvironment.aws.instanceProfileName.equals("prodigy-controller-profile"_ctv), "plan_boot_json_runtime_environment_instance_profile_preserved");
   suite.expect(parsedBootState.initialTopology.version == topology.version, "plan_boot_json_initial_topology_version");
   suite.expect(parsedBootState.initialTopology.machines.size() == topology.machines.size() + 1, "plan_boot_json_initial_topology_machine_count");
   suite.expect(findMachineByCloudID(parsedBootState.initialTopology, target.cloud.cloudID) != nullptr, "plan_boot_json_initial_topology_target_found");
   suite.expect(findMachineByCloudID(parsedBootState.initialTopology, "brain-a"_ctv) != nullptr, "plan_boot_json_initial_topology_existing_peer_found");

   ProdigyPersistentLocalBrainState parsedTransportState = {};
   suite.expect(parseProdigyPersistentLocalBrainStateJSON(plan.transportTLSJSON, parsedTransportState, &failure), "plan_transport_tls_json_parses");
   suite.expect(parsedTransportState.ownerClusterUUID == request.clusterUUID, "plan_transport_tls_json_owner_cluster_uuid");
   suite.expect(parsedTransportState.transportTLSConfigured(), "plan_transport_tls_json_configured");
   suite.expect(parsedTransportState.canMintTransportTLS(), "plan_transport_tls_json_brain_has_mint_authority");
   const ClusterMachine *parsedTransportMachine = findMachineByCloudID(parsedBootState.initialTopology, target.cloud.cloudID);
   suite.expect(parsedTransportMachine != nullptr, "plan_transport_tls_topology_machine_found");
   if (parsedTransportMachine != nullptr)
   {
      suite.expect(parsedTransportMachine->uuid == parsedTransportState.uuid, "plan_transport_tls_uuid_matches_topology");
   }
   X509 *transportCert = VaultPem::x509FromPem(parsedTransportState.transportTLS.localCertPem);
   uint128_t transportCertUUID = 0;
   suite.expect(Vault::extractTransportCertificateUUID(transportCert, transportCertUUID), "plan_transport_tls_leaf_uuid_extracts");
   suite.expect(transportCertUUID == parsedTransportState.uuid, "plan_transport_tls_leaf_uuid_matches");
   if (transportCert)
   {
      X509_free(transportCert);
   }

   ClusterTopology partialTopology = {};
   partialTopology.version = topology.version;
   partialTopology.machines.push_back(makeBrainMachine("brain-a"_ctv, "10.0.0.29"_ctv));

   suite.expect(
      prodigyBuildRemoteBootstrapPlan(target, request, partialTopology, runtimeEnvironment, plan, &failure),
      "build_remote_bootstrap_plan_partial_topology"
   );
   suite.expect(failure.size() == 0, "build_remote_bootstrap_plan_partial_topology_clears_failure");

   ProdigyPersistentLocalBrainState partialTransportState = {};
   suite.expect(parseProdigyPersistentLocalBrainStateJSON(plan.transportTLSJSON, partialTransportState, &failure), "plan_transport_tls_json_partial_parses");
   suite.expect(partialTransportState.transportTLSConfigured(), "plan_transport_tls_json_partial_configured");

   ClusterTopology fullerTopology = partialTopology;
   fullerTopology.machines.push_back(makeBrainMachine("brain-b"_ctv, "10.0.0.30"_ctv));
   suite.expect(
      prodigyBuildRemoteBootstrapPlan(target, request, fullerTopology, runtimeEnvironment, plan, &failure),
      "build_remote_bootstrap_plan_fuller_topology"
   );
   suite.expect(failure.size() == 0, "build_remote_bootstrap_plan_fuller_topology_clears_failure");

   ProdigyPersistentLocalBrainState fullerTransportState = {};
   suite.expect(parseProdigyPersistentLocalBrainStateJSON(plan.transportTLSJSON, fullerTransportState, &failure), "plan_transport_tls_json_fuller_parses");
   suite.expect(fullerTransportState.transportTLSConfigured(), "plan_transport_tls_json_fuller_configured");
   suite.expect(partialTransportState.transportTLS.clusterRootCertPem.equals(fullerTransportState.transportTLS.clusterRootCertPem), "plan_transport_tls_partial_and_fuller_share_root_cert");
   suite.expect(partialTransportState.transportTLS.clusterRootKeyPem.equals(fullerTransportState.transportTLS.clusterRootKeyPem), "plan_transport_tls_partial_and_fuller_share_root_key");
   suite.expect(partialTransportState.uuid == fullerTransportState.uuid, "plan_transport_tls_partial_and_fuller_preserve_machine_uuid");

   ClusterMachine singleSeed = target;
   singleSeed.ssh.address.assign("44.0.0.31"_ctv);
   prodigyAppendUniqueClusterMachineAddress(singleSeed.addresses.publicAddresses, "44.0.0.31"_ctv);
   ClusterTopology singleSeedTopology = {};
   singleSeedTopology.version = 12;
   singleSeedTopology.machines.push_back(singleSeed);

   suite.expect(
      prodigyBuildRemoteBootstrapPlan(singleSeed, request, singleSeedTopology, runtimeEnvironment, plan, &failure),
      "build_remote_bootstrap_plan_single_seed"
   );
   suite.expect(failure.size() == 0, "build_remote_bootstrap_plan_single_seed_clears_failure");
   ProdigyRemoteBootstrapPlan singleSeedPlan = plan;

   ProdigyPersistentBootState singleSeedBootState = {};
   suite.expect(parseProdigyPersistentBootStateJSON(plan.bootJSON, singleSeedBootState, &failure), "plan_boot_json_single_seed_parses");
   suite.expect(singleSeedBootState.bootstrapConfig.bootstrapPeers.size() == 0, "plan_boot_json_single_seed_excludes_self_peer");
    suite.expect(singleSeedBootState.initialTopology.version == singleSeedTopology.version, "plan_boot_json_single_seed_initial_topology_version");
   suite.expect(singleSeedBootState.initialTopology.machines.size() == 1, "plan_boot_json_single_seed_initial_topology_machine_count");
   suite.expect(findMachineByCloudID(singleSeedBootState.initialTopology, singleSeed.cloud.cloudID) != nullptr, "plan_boot_json_single_seed_initial_topology_target_found");

   ClusterMachine publicSSHPeer = makeBrainMachine("brain-public-peer"_ctv, "10.0.0.29"_ctv);
   publicSSHPeer.ssh.address.assign("44.0.0.29"_ctv);
   prodigyAppendUniqueClusterMachineAddress(publicSSHPeer.addresses.publicAddresses, "44.0.0.29"_ctv);

   ClusterMachine publicSSHSeed = target;
   publicSSHSeed.ssh.address.assign("44.0.0.31"_ctv);
   prodigyAppendUniqueClusterMachineAddress(publicSSHSeed.addresses.publicAddresses, "44.0.0.31"_ctv);

   ClusterTopology publicSSHTopology = {};
   publicSSHTopology.version = 13;
   publicSSHTopology.machines.push_back(publicSSHSeed);
   publicSSHTopology.machines.push_back(publicSSHPeer);

   suite.expect(
      prodigyBuildRemoteBootstrapPlan(publicSSHSeed, request, publicSSHTopology, runtimeEnvironment, plan, &failure),
      "build_remote_bootstrap_plan_prefers_private_peer_connectivity"
   );
   suite.expect(failure.size() == 0, "build_remote_bootstrap_plan_prefers_private_peer_connectivity_clears_failure");
   suite.expect(plan.ssh.address.equals("44.0.0.31"_ctv), "plan_preserves_explicit_public_ssh_address");

   ProdigyPersistentBootState publicSSHBootState = {};
   suite.expect(parseProdigyPersistentBootStateJSON(plan.bootJSON, publicSSHBootState, &failure), "plan_boot_json_public_ssh_peer_parses");
   suite.expect(publicSSHBootState.bootstrapConfig.bootstrapPeers.size() == 1, "plan_boot_json_public_ssh_peer_count");
   suite.expect(publicSSHBootState.bootstrapConfig.bootstrapPeers[0].addresses.size() == 2, "plan_boot_json_public_ssh_peer_candidate_count");
   expectBootstrapPeerCandidate(suite, publicSSHBootState.bootstrapConfig.bootstrapPeers[0], 0, "10.0.0.29"_ctv, 0, "plan_boot_json_public_ssh_prefers_private_peer");
   expectBootstrapPeerCandidate(suite, publicSSHBootState.bootstrapConfig.bootstrapPeers[0], 1, "44.0.0.29"_ctv, 0, "plan_boot_json_public_ssh_falls_back_to_public_peer");

   ClusterMachine private6Peer = makeBrainMachine("brain-private6-peer"_ctv, "fd00:10::29"_ctv);
   ClusterMachine private6Seed = target;
   prodigyAppendUniqueClusterMachineAddress(private6Seed.addresses.privateAddresses, "fd00:10::31"_ctv);
   private6Seed.ssh.address.assign("2001:db8::31"_ctv);
   prodigyAppendUniqueClusterMachineAddress(private6Seed.addresses.publicAddresses, "2001:db8::31"_ctv);

   ClusterTopology private6Topology = {};
   private6Topology.version = 14;
   private6Topology.machines.push_back(private6Seed);
   private6Topology.machines.push_back(private6Peer);

   suite.expect(
      prodigyBuildRemoteBootstrapPlan(private6Seed, request, private6Topology, runtimeEnvironment, plan, &failure),
      "build_remote_bootstrap_plan_private6_peer_connectivity"
   );
   suite.expect(failure.size() == 0, "build_remote_bootstrap_plan_private6_peer_connectivity_clears_failure");
   suite.expect(plan.ssh.address.equals("2001:db8::31"_ctv), "plan_preserves_ipv6_ssh_address");

   ProdigyPersistentBootState private6BootState = {};
   suite.expect(parseProdigyPersistentBootStateJSON(plan.bootJSON, private6BootState, &failure), "plan_boot_json_private6_peer_parses");
   bool private6PeerCountOkay = private6BootState.bootstrapConfig.bootstrapPeers.size() == 1;
   suite.expect(private6PeerCountOkay, "plan_boot_json_private6_peer_count");
   if (private6PeerCountOkay)
   {
      bool private6CandidateCountOkay = private6BootState.bootstrapConfig.bootstrapPeers[0].addresses.size() == 1;
      suite.expect(private6CandidateCountOkay, "plan_boot_json_private6_peer_candidate_count");
      if (private6CandidateCountOkay)
      {
         expectBootstrapPeerCandidate(suite, private6BootState.bootstrapConfig.bootstrapPeers[0], 0, "fd00:10::29"_ctv, 0, "plan_boot_json_private6_peer_literal");
      }
   }

   ClusterMachine public6Peer = makeBrainMachine("brain-public6-peer"_ctv, ""_ctv);
   prodigyAppendUniqueClusterMachineAddress(public6Peer.addresses.publicAddresses, "2602:fac0:0:12ab:34cd::29"_ctv);
   public6Peer.ssh.address.assign("2602:fac0:0:12ab:34cd::29"_ctv);
   ClusterMachine public6Seed = target;
   public6Seed.addresses.privateAddresses.clear();
   prodigyAppendUniqueClusterMachineAddress(public6Seed.addresses.publicAddresses, "2602:fac0:0:12ab:34cd::31"_ctv);
   public6Seed.ssh.address.assign("2602:fac0:0:12ab:34cd::31"_ctv);

   ClusterTopology public6Topology = {};
   public6Topology.version = 15;
   public6Topology.machines.push_back(public6Seed);
   public6Topology.machines.push_back(public6Peer);

   suite.expect(
      prodigyBuildRemoteBootstrapPlan(public6Seed, request, public6Topology, runtimeEnvironment, plan, &failure),
      "build_remote_bootstrap_plan_public6_peer_connectivity"
   );
   suite.expect(failure.size() == 0, "build_remote_bootstrap_plan_public6_peer_connectivity_clears_failure");

   ProdigyPersistentBootState public6BootState = {};
   suite.expect(parseProdigyPersistentBootStateJSON(plan.bootJSON, public6BootState, &failure), "plan_boot_json_public6_peer_parses");
   bool public6PeerCountOkay = public6BootState.bootstrapConfig.bootstrapPeers.size() == 1;
   suite.expect(public6PeerCountOkay, "plan_boot_json_public6_peer_count");
   if (public6PeerCountOkay)
   {
      bool public6CandidateCountOkay = public6BootState.bootstrapConfig.bootstrapPeers[0].addresses.size() == 1;
      suite.expect(public6CandidateCountOkay, "plan_boot_json_public6_peer_candidate_count");
      if (public6CandidateCountOkay)
      {
         expectBootstrapPeerCandidate(suite, public6BootState.bootstrapConfig.bootstrapPeers[0], 0, "2602:fac0:0:12ab:34cd::29"_ctv, 0, "plan_boot_json_public6_peer_literal");
      }
   }

   String internalSSHAddress = {};
   suite.expect(prodigyResolveClusterMachineInternalSSHAddress(publicSSHSeed, internalSSHAddress), "resolve_internal_ssh_address_private_available");
   suite.expect(internalSSHAddress.equals("10.0.0.31"_ctv), "resolve_internal_ssh_address_prefers_private_over_public_ssh");
   suite.expect(prodigyResolveClusterMachineInternalSSHAddress(public6Seed, internalSSHAddress), "resolve_internal_ssh_address_public_ipv6_fallback");
   suite.expect(internalSSHAddress.equals("2602:fac0:0:12ab:34cd::31"_ctv), "resolve_internal_ssh_address_falls_back_to_public_when_private_missing");

   suite.expect(stringContains(plan.mkdirCommand, "mkdir -p"), "plan_mkdir_command_prefix");
   suite.expect(stringContains(plan.mkdirCommand, "/opt"), "plan_mkdir_command_remote_root_parent");
   suite.expect(stringContains(plan.mkdirCommand, "/var/lib/prodigy"), "plan_mkdir_command_var_lib");
   suite.expect(stringContains(plan.mkdirCommand, "/run/prodigy"), "plan_mkdir_command_control_dir");
   String expectedBootstrapSSHDirectoryQuoted = {};
   prodigyAppendShellSingleQuoted(expectedBootstrapSSHDirectoryQuoted, expectedBootstrapSSHDirectory);
   suite.expect(stringContains(plan.mkdirCommand, expectedBootstrapSSHDirectoryQuoted.c_str()), "plan_mkdir_command_bootstrap_ssh_dir");
   String expectedBootstrapSSHChmod = {};
   expectedBootstrapSSHChmod.snprintf<"chmod 700 {}"_ctv>(expectedBootstrapSSHDirectoryQuoted);
   suite.expect(stringContains(plan.mkdirCommand, expectedBootstrapSSHChmod.c_str()), "plan_mkdir_command_bootstrap_ssh_chmod");

   String controlSocketWaitCommand = {};
   prodigyAppendRemoteControlSocketWaitCommand(controlSocketWaitCommand, "/run/prodigy/control.sock"_ctv);
   String expectedWaitTimeoutSuffix = {};
   expectedWaitTimeoutSuffix.snprintf<" {itoa}"_ctv>(uint64_t(prodigyRemoteBootstrapControlSocketWaitSeconds));
   suite.expect(stringEndsWith(controlSocketWaitCommand, expectedWaitTimeoutSuffix), "control_socket_wait_command_uses_wait_seconds_knob");
   String expectedProbeTimeoutNeedle = {};
   expectedProbeTimeoutNeedle.snprintf<"probe_timeout_ms={itoa}"_ctv>(uint64_t(prodigyRemoteBootstrapControlSocketProbeTimeoutMs));
   suite.expect(stringContains(controlSocketWaitCommand, expectedProbeTimeoutNeedle.c_str()), "control_socket_wait_command_uses_probe_timeout_knob");
   String expectedProbeSleepNeedle = {};
   expectedProbeSleepNeedle.snprintf<"probe_sleep_ms={itoa}"_ctv>(uint64_t(prodigyRemoteBootstrapControlSocketProbeSleepMs));
   suite.expect(stringContains(controlSocketWaitCommand, expectedProbeSleepNeedle.c_str()), "control_socket_wait_command_uses_probe_sleep_knob");
   String socketDiagnosticsCommand = {};
   prodigyAppendRemoteBootstrapSocketFailureDiagnostics(socketDiagnosticsCommand);
   String expectedDiagnosticsTimeoutNeedle = {};
   expectedDiagnosticsTimeoutNeedle.snprintf<"timeout {itoa}s sh -lc"_ctv>(uint64_t(prodigyRemoteBootstrapSocketDiagnosticsTimeoutSeconds));
   suite.expect(stringContains(socketDiagnosticsCommand, expectedDiagnosticsTimeoutNeedle.c_str()), "control_socket_failure_diagnostics_use_timeout_knob");

   suite.expect(stringContains(singleSeedPlan.installCommand, "tar --zstd -xf"), "plan_install_command_extract_bundle");
    suite.expect(stringContains(singleSeedPlan.installCommand, "tar --no-same-owner --same-permissions -xf"), "plan_install_command_extract_stage_payload");
   suite.expect(stringContains(singleSeedPlan.installCommand, "/tmp/prodigy.remote-bootstrap.payload.tar"), "plan_install_command_stage_payload_path");
   suite.expect(stringContains(singleSeedPlan.installCommand, "rm -f '/tmp/prodigy.remote-bootstrap.payload.tar'"), "plan_install_command_removes_stage_payload");
   suite.expect(stringContains(singleSeedPlan.installCommand, "command -v zstd"), "plan_install_command_zstd_preflight");
   suite.expect(stringContains(singleSeedPlan.installCommand, "apt-get install -y zstd"), "plan_install_command_zstd_install_fallback");
   suite.expect(stringContains(singleSeedPlan.installCommand, "ldconfig -p") == false, "plan_install_command_skips_libatomic_preflight");
   suite.expect(stringContains(singleSeedPlan.installCommand, "apt-get install -y libatomic1") == false, "plan_install_command_skips_libatomic_install_fallback");
   suite.expect(stringContains(singleSeedPlan.installCommand, "systemctl stop prodigy || true;"), "plan_install_command_stops_before_replace");
   suite.expect(stringContains(singleSeedPlan.installCommand, "/opt/prodigy.bundle.tar.zst.tmp"), "plan_install_command_bundle_temp");
   suite.expect(stringContains(singleSeedPlan.installCommand, "/opt/prodigy-root.new"), "plan_install_command_install_root_temp");
   suite.expect(stringContains(singleSeedPlan.installCommand, "/opt/prodigy-root.prev"), "plan_install_command_install_root_previous");
   suite.expect(stringContains(singleSeedPlan.installCommand, "/opt/prodigy-root.new/prodigy.bundle.tar.zst"), "plan_install_command_installed_bundle_path");
   suite.expect(stringContains(singleSeedPlan.installCommand, "LD_LIBRARY_PATH='/opt/prodigy-root/lib'"), "plan_install_command_ld_library_path");
   suite.expect(stringContains(singleSeedPlan.installCommand, "/etc/systemd/system/prodigy.service"), "plan_install_command_unit_path");
   suite.expect(stringContains(singleSeedPlan.installCommand, "--persist-only --reset-brain-snapshot --boot-json-path="), "plan_install_command_persist_only");
   suite.expect(stringContains(singleSeedPlan.installCommand, "/var/lib/prodigy/boot.json"), "plan_install_command_boot_json_path");
   suite.expect(stringContains(singleSeedPlan.installCommand, "--boot-json='") == false, "plan_install_command_does_not_inline_boot_json");
   suite.expect(stringContains(singleSeedPlan.installCommand, "ufw status"), "plan_install_command_ufw_detects_active_firewall");
   suite.expect(stringContains(singleSeedPlan.installCommand, "ufw allow 312/tcp"), "plan_install_command_ufw_allows_neuron_port");
   suite.expect(stringContains(singleSeedPlan.installCommand, "ufw allow 313/tcp"), "plan_install_command_ufw_allows_brain_port");
   suite.expect(stringContains(singleSeedPlan.installCommand, "systemctl daemon-reload"), "plan_install_command_daemon_reload");
   suite.expect(stringContains(singleSeedPlan.installCommand, "systemctl enable prodigy"), "plan_install_command_enable");
   suite.expect(stringContains(singleSeedPlan.installCommand, "systemctl restart prodigy"), "plan_install_command_restart");
   suite.expect(stringContains(singleSeedPlan.installCommand, "python3 -c"), "plan_install_command_waits_for_control_socket_with_python");
   suite.expect(stringContains(singleSeedPlan.installCommand, "/run/prodigy/control.sock"), "plan_install_command_waits_for_control_socket_path");
   suite.expect(stringContains(singleSeedPlan.installCommand, "systemctl restart prodigy && python3 -c"), "plan_install_command_restart_waits_for_socket");
   String expectedPlanDiagnosticsNeedle = {};
   expectedPlanDiagnosticsNeedle.snprintf<"|| { timeout {itoa}s sh -lc"_ctv>(uint64_t(prodigyRemoteBootstrapSocketDiagnosticsTimeoutSeconds));
   suite.expect(stringContains(singleSeedPlan.installCommand, expectedPlanDiagnosticsNeedle.c_str()), "plan_install_command_wait_failure_collects_diagnostics");
   suite.expect(stringContains(singleSeedPlan.installCommand, "journalctl -u prodigy -n 120 --no-pager"), "plan_install_command_wait_failure_dumps_journal");
   suite.expect(stringContains(singleSeedPlan.installCommand, "systemctl status prodigy --no-pager -l"), "plan_install_command_wait_failure_dumps_systemctl");
   suite.expect(stringContains(singleSeedPlan.installCommand, "python3 -c") && stringContains(singleSeedPlan.installCommand, "&& rm -rf"), "plan_install_command_socket_wait_keeps_failure");
   suite.expect(stringContains(singleSeedPlan.installCommand, "systemctl restart prodigy; rm -rf") == false, "plan_install_command_restart_never_masks_failure");
   suite.expect(stringContains(multiBrainPlan.installCommand, "systemctl restart prodigy && python3 -c") == false, "plan_install_command_skips_control_socket_wait_for_multi_brain");
   suite.expect(stringContains(multiBrainPlan.installCommand, expectedPlanDiagnosticsNeedle.c_str()) == false, "plan_install_command_skips_socket_diagnostics_for_multi_brain");
   suite.expect(stringContains(multiBrainPlan.installCommand, "systemctl restart prodigy && rm -rf"), "plan_install_command_multi_brain_restarts_without_socket_wait");

   suite.expect(stringContains(plan.systemdUnit, "Environment=LD_LIBRARY_PATH=/opt/prodigy-root/lib"), "plan_systemd_ld_library_path");
   suite.expect(stringContains(plan.systemdUnit, "ExecStart=/opt/prodigy-root/prodigy"), "plan_systemd_execstart");
   suite.expect(stringContains(plan.systemdUnit, "ExecStartPre=/usr/bin/mkdir -p /run/prodigy /var/lib/prodigy /opt/prodigy-root/lib"), "plan_systemd_execstartpre");
   suite.expect(stringContains(plan.systemdUnit, "WantedBy=multi-user.target"), "plan_systemd_wanted_by");

   String probeCommand;
   prodigyRenderRemoteMachineResourceProbeCommand(probeCommand);
   suite.expect(stringContains(probeCommand, "getconf _NPROCESSORS_ONLN"), "probe_command_uses_getconf");
   suite.expect(stringContains(probeCommand, "/proc/meminfo"), "probe_command_uses_meminfo");
   suite.expect(stringContains(probeCommand, "df -Pm /var/lib/prodigy"), "probe_command_uses_var_lib_df");
   suite.expect(stringContains(probeCommand, "ip -o -4 addr show scope global"), "probe_command_lists_global_ipv4_candidates");
   suite.expect(stringContains(probeCommand, "ip -o -6 addr show scope global"), "probe_command_lists_global_ipv6_candidates");
   suite.expect(stringContains(probeCommand, "printf '%s|%s|%s\\n'"), "probe_command_emits_address_cidr_gateway");

   ProdigyRemoteMachineResources probedResources = {};
   suite.expect(prodigyParseRemoteMachineResources("8\n32768\n204800\n10.1.2.3|24|10.1.2.1\nfd00:10::23|64|fd00:10::1\n"_ctv, probedResources, &failure), "probe_parse_valid_output");
   suite.expect(probedResources.totalLogicalCores == 8, "probe_parse_valid_output_cores");
   suite.expect(probedResources.totalMemoryMB == 32768, "probe_parse_valid_output_memory");
   suite.expect(probedResources.totalStorageMB == 204800, "probe_parse_valid_output_storage");
   suite.expect(probedResources.peerAddresses.size() == 2, "probe_parse_valid_output_peer_address_count");
   suite.expect(probedResources.peerAddresses[0].address.equals("10.1.2.3"_ctv) && probedResources.peerAddresses[0].cidr == 24 && probedResources.peerAddresses[0].gateway.equals("10.1.2.1"_ctv), "probe_parse_valid_output_private4_candidate");
   suite.expect(probedResources.peerAddresses[1].address.equals("fd00:10::23"_ctv) && probedResources.peerAddresses[1].cidr == 64 && probedResources.peerAddresses[1].gateway.equals("fd00:10::1"_ctv), "probe_parse_valid_output_private6_candidate");
   suite.expect(prodigyParseRemoteMachineResources("8\n32768\n204800\nfd00:10::23|64|fd00:10::1\n"_ctv, probedResources, &failure), "probe_parse_valid_output_ipv6");
   suite.expect(probedResources.peerAddresses.size() == 1, "probe_parse_valid_output_ipv6_candidate_count");
   suite.expect(probedResources.peerAddresses[0].address.equals("fd00:10::23"_ctv) && probedResources.peerAddresses[0].cidr == 64 && probedResources.peerAddresses[0].gateway.equals("fd00:10::1"_ctv), "probe_parse_valid_output_ipv6_private_address");
   suite.expect(prodigyParseRemoteMachineResources("8\n0\n204800\n10.1.2.3|24|10.1.2.1\n"_ctv, probedResources, &failure) == false, "probe_parse_reject_zero_resource");
   suite.expect(failure.equals("remote resource probe returned zero resources"_ctv), "probe_parse_reject_zero_resource_failure");
   suite.expect(prodigyParseRemoteMachineResources("bogus\n32768\n204800\n10.1.2.3|24|10.1.2.1\n"_ctv, probedResources, &failure) == false, "probe_parse_reject_invalid_numeric");
   suite.expect(failure.equals("remote resource probe returned invalid numeric output"_ctv), "probe_parse_reject_invalid_numeric_failure");

   ClusterMachine adoptedTarget = target;
   adoptedTarget.source = ClusterMachineSource::adopted;
   suite.expect(
      prodigyBuildRemoteBootstrapPlan(adoptedTarget, request, topology, runtimeEnvironment, plan, &failure),
      "build_remote_bootstrap_plan_adopted"
   );
   suite.expect(plan.connectRetryBudgetMs == uint64_t(Time::minsToMs(2)), "plan_adopted_machine_retry_budget");

   ClusterMachine workerTarget = worker;
   workerTarget.ssh.user.assign("root"_ctv);
   workerTarget.ssh.privateKeyPath = prodigyTestClientSSHPrivateKeyPath();
   workerTarget.ssh.hostPublicKeyOpenSSH = bootstrapHostKeyPackage.publicKeyOpenSSH;
   suite.expect(
      prodigyBuildRemoteBootstrapPlan(workerTarget, request, topology, runtimeEnvironment, plan, &failure),
      "build_remote_bootstrap_plan_worker"
   );
   suite.expect(failure.size() == 0, "build_remote_bootstrap_plan_worker_clears_failure");
   ProdigyRemoteBootstrapPlan workerPlan = plan;

   ProdigyPersistentBootState workerBootState = {};
   suite.expect(parseProdigyPersistentBootStateJSON(plan.bootJSON, workerBootState, &failure), "plan_boot_json_worker_parses");
   suite.expect(workerBootState.bootstrapConfig.nodeRole == ProdigyBootstrapNodeRole::neuron, "plan_boot_json_worker_node_role");
   suite.expect(stringContains(workerPlan.installCommand, "systemctl restart prodigy && python3 -c") == false, "plan_install_command_skips_control_socket_wait_for_worker");
   suite.expect(stringContains(workerPlan.installCommand, expectedPlanDiagnosticsNeedle.c_str()) == false, "plan_install_command_skips_socket_diagnostics_for_worker");

   ProdigyPersistentLocalBrainState workerTransportState = {};
   suite.expect(parseProdigyPersistentLocalBrainStateJSON(plan.transportTLSJSON, workerTransportState, &failure), "plan_transport_tls_json_worker_parses");
   suite.expect(workerTransportState.ownerClusterUUID == request.clusterUUID, "plan_transport_tls_json_worker_owner_cluster_uuid");
   suite.expect(workerTransportState.transportTLSConfigured(), "plan_transport_tls_json_worker_configured");
   suite.expect(workerTransportState.canMintTransportTLS() == false, "plan_transport_tls_json_worker_no_mint_authority");
   suite.expect(workerTransportState.transportTLS.clusterRootKeyPem.size() == 0, "plan_transport_tls_json_worker_no_root_key");
   const ClusterMachine *workerTransportMachine = findMachineByCloudID(workerBootState.initialTopology, workerTarget.cloud.cloudID);
   suite.expect(workerTransportMachine != nullptr, "plan_transport_tls_worker_topology_machine_found");
   if (workerTransportMachine != nullptr)
   {
      suite.expect(workerTransportMachine->uuid == workerTransportState.uuid, "plan_transport_tls_worker_uuid_matches_topology");
   }
   X509 *workerTransportCert = VaultPem::x509FromPem(workerTransportState.transportTLS.localCertPem);
   uint128_t workerTransportCertUUID = 0;
   suite.expect(Vault::extractTransportCertificateUUID(workerTransportCert, workerTransportCertUUID), "plan_transport_tls_worker_leaf_uuid_extracts");
   suite.expect(workerTransportCertUUID == workerTransportState.uuid, "plan_transport_tls_worker_leaf_uuid_matches");
   if (workerTransportCert)
   {
      X509_free(workerTransportCert);
   }

   AddMachines invalidRequest = request;
   invalidRequest.controlSocketPath.clear();
   suite.expect(
      prodigyBuildRemoteBootstrapPlan(target, invalidRequest, topology, runtimeEnvironment, plan, &failure) == false,
      "reject_missing_control_socket_path"
   );
   suite.expect(failure.equals("addMachines controlSocketPath required"_ctv), "reject_missing_control_socket_path_failure");

   invalidRequest = request;
   invalidRequest.remoteProdigyPath.clear();
   suite.expect(
      prodigyBuildRemoteBootstrapPlan(target, invalidRequest, topology, runtimeEnvironment, plan, &failure) == false,
      "reject_missing_remote_prodigy_path"
   );
   suite.expect(failure.equals("addMachines remoteProdigyPath required"_ctv), "reject_missing_remote_prodigy_path_failure");

   ClusterMachine noSSHAddress = target;
   noSSHAddress.addresses.privateAddresses.clear();
   noSSHAddress.addresses.publicAddresses.clear();
    String noSSHAddressLabel = {};
   noSSHAddress.renderIdentityLabel(noSSHAddressLabel);
   suite.expect(
      prodigyBuildRemoteBootstrapPlan(noSSHAddress, request, topology, runtimeEnvironment, plan, &failure) == false,
      "reject_missing_ssh_address"
   );
   String expectedMissingSSHAddressFailure = {};
   expectedMissingSSHAddressFailure.snprintf<"machine '{}' has no ssh address"_ctv>(noSSHAddressLabel);
   suite.expect(failure.equals(expectedMissingSSHAddressFailure), "reject_missing_ssh_address_failure");

   ClusterMachine noSSHKey = target;
   noSSHKey.ssh.privateKeyPath.clear();
   suite.expect(
      prodigyBuildRemoteBootstrapPlan(noSSHKey, request, topology, runtimeEnvironment, plan, &failure),
      "allow_missing_ssh_private_key_with_bootstrap_key_package"
   );
   suite.expect(failure.size() == 0, "allow_missing_ssh_private_key_with_bootstrap_key_package_clears_failure");
   suite.expect(plan.ssh.privateKeyPath.size() == 0, "plan_preserves_missing_ssh_private_key_with_bootstrap_key_package");
   suite.expect(plan.bootstrapSshKeyPackage == request.bootstrapSshKeyPackage, "plan_uses_bootstrap_key_package_when_ssh_private_key_missing");

   ClusterMachine noSSHHostKey = target;
   noSSHHostKey.ssh.hostPublicKeyOpenSSH.clear();
   String noSSHHostKeyLabel = {};
   noSSHHostKey.renderIdentityLabel(noSSHHostKeyLabel);
   suite.expect(
      prodigyBuildRemoteBootstrapPlan(noSSHHostKey, request, topology, runtimeEnvironment, plan, &failure) == false,
      "reject_missing_ssh_host_public_key"
   );
   String expectedMissingSSHHostKeyFailure = {};
   expectedMissingSSHHostKeyFailure.snprintf<"machine '{}' has no ssh.hostPublicKeyOpenSSH"_ctv>(noSSHHostKeyLabel);
   suite.expect(failure.equals(expectedMissingSSHHostKeyFailure), "reject_missing_ssh_host_public_key_failure");

   invalidRequest = request;
   invalidRequest.bootstrapSshKeyPackage.clear();
   String noSSHKeyLabel = {};
   noSSHKey.renderIdentityLabel(noSSHKeyLabel);
   suite.expect(
      prodigyBuildRemoteBootstrapPlan(noSSHKey, invalidRequest, topology, runtimeEnvironment, plan, &failure) == false,
      "reject_missing_ssh_private_key_without_bootstrap_key_package"
   );
   String expectedMissingSSHKeyFailure = {};
   expectedMissingSSHKeyFailure.snprintf<"machine '{}' has no sshPrivateKeyPath"_ctv>(noSSHKeyLabel);
   suite.expect(failure.equals(expectedMissingSSHKeyFailure), "reject_missing_ssh_private_key_without_bootstrap_key_package_failure");

   invalidRequest = request;
   invalidRequest.clusterUUID = 0;
   suite.expect(
      prodigyBuildRemoteBootstrapPlan(target, invalidRequest, topology, runtimeEnvironment, plan, &failure) == false,
      "reject_missing_cluster_uuid"
   );
   suite.expect(failure.equals("addMachines clusterUUID required"_ctv), "reject_missing_cluster_uuid_failure");

   ProdigyRemoteBootstrapPlan executePlan = {};
   executePlan.ssh.address.assign("203.0.113.250"_ctv);
   executePlan.ssh.port = 22;
   executePlan.ssh.user.assign("root"_ctv);
   executePlan.ssh.privateKeyPath.assign("/tmp/nonexistent-prodigy-test-key"_ctv);
   executePlan.localBundlePath.assign("/tmp/nonexistent-prodigy-test.bundle.tar.zst"_ctv);
   executePlan.connectRetryBudgetMs = 1;
   suite.expect(
      prodigyExecuteRemoteBootstrapPlan(executePlan, &failure) == false,
      "execute_remote_bootstrap_plan_rejects_missing_bundle_before_connect"
   );
   String expectedMissingBundleFailure = {};
   expectedMissingBundleFailure.assign("bundle sha256 sidecar is not readable: /tmp/nonexistent-prodigy-test.bundle.tar.zst.sha256"_ctv);
   suite.expect(
      failure.equals(expectedMissingBundleFailure),
      "execute_remote_bootstrap_plan_missing_bundle_failure"
   );

   if (suite.failed != 0)
   {
      basics_log("remote_bootstrap_unit failed=%d\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("remote_bootstrap_unit ok\n");
   return EXIT_SUCCESS;
}
