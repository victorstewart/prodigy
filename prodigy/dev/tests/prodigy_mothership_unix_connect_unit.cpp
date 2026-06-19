#include <atomic>
#include <services/debug.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>

#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PRODIGY_TEST_BINARY_DIR
#define PRODIGY_TEST_BINARY_DIR ""
#endif

#define PRODIGY_MOTHERSHIP_TEST_ACCESS 1
#define main nametag_mothership_main_disabled
#include <prodigy/mothership/mothership.cpp>
#undef main
#include <prodigy/mothership/mothership.tunnel.gateway.h>

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

struct MothershipWireHeader {
  uint32_t size = 0;
  uint16_t topic = 0;
  uint8_t padding = 0;
  uint8_t headerSize = 0;
};

static_assert(sizeof(MothershipWireHeader) == 8);

struct ControlServerState {
  std::atomic<bool> stopRequested = false;
  uint32_t acceptCount = 0;
  String failure;
};

class ScopedUnixListener {
public:

  String path;
  int fd = -1;

  ~ScopedUnixListener()
  {
    if (fd >= 0)
    {
      ::close(fd);
    }

    if (path.size() > 0)
    {
      (void)::unlink(path.c_str());
    }
  }
};

class ScopedTcpListener {
public:

  int fd = -1;
  uint16_t port = 0;

  ~ScopedTcpListener()
  {
    if (fd >= 0)
    {
      ::close(fd);
    }
  }
};

class ScopedProcess {
public:

  pid_t pid = -1;

  void terminate(void)
  {
    if (pid <= 0)
    {
      return;
    }
    (void)::kill(pid, SIGTERM);
    (void)::waitpid(pid, nullptr, 0);
    pid = -1;
  }

  ~ScopedProcess()
  {
    terminate();
  }
};

class ScopedEnvVar {
public:

  const char *name = nullptr;
  std::string previous;
  bool hadPrevious = false;

  ScopedEnvVar(const char *envName, const String& value) : name(envName)
  {
    if (const char *existing = ::getenv(name))
    {
      hadPrevious = true;
      previous.assign(existing);
    }
    String owned = {};
    owned.assign(value);
    (void)::setenv(name, owned.c_str(), 1);
  }

  ScopedEnvVar(const char *envName, const char *value) : name(envName)
  {
    if (const char *existing = ::getenv(name))
    {
      hadPrevious = true;
      previous.assign(existing);
    }
    (void)::setenv(name, value, 1);
  }

  ~ScopedEnvVar()
  {
    if (hadPrevious)
    {
      (void)::setenv(name, previous.c_str(), 1);
    }
    else
    {
      (void)::unsetenv(name);
    }
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

class TemporaryDirectory {
public:

  String path = {};

  bool create(const char *pattern)
  {
    char scratch[128] = {};
    std::snprintf(scratch, sizeof(scratch), "/tmp/%s-XXXXXX", pattern);
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
    if (path.size() > 0)
    {
      std::error_code ignored;
      std::filesystem::remove_all(filesystemPathFromString(path), ignored);
    }
  }
};

static bool writeFileFixture(const std::filesystem::path& path, const String& payload)
{
  std::error_code createError;
  std::filesystem::create_directories(path.parent_path(), createError);
  return createError.value() == 0 && Filesystem::openWriteAtClose(-1, stringFromFilesystemPath(path), payload) >= 0;
}

static bool parseConnectivityFixture(String json, MothershipConnectivity& connectivity)
{
  json.need(simdjson::SIMDJSON_PADDING);
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  String providerContainerBlobPath = {};
  return parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS && parseMothershipConnectivityJSON(doc, connectivity, providerContainerBlobPath, "connectivity");
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
    config.vmImageURI = "image://unit-test"_ctv;
  }
  return config;
}

static MothershipProdigyClusterControl makeUnixControl(const String& path)
{
  return MothershipProdigyClusterControl {
      .kind = MothershipClusterControlKind::unixSocket,
      .path = path};
}

static ClusterMachine makeTopologyMachine(const String& privateAddress, bool isBrain)
{
  ClusterMachine machine = {};
  machine.source = ClusterMachineSource::adopted;
  machine.backing = ClusterMachineBacking::owned;
  machine.lifetime = MachineLifetime::owned;
  machine.kind = MachineConfig::MachineKind::vm;
  machine.isBrain = isBrain;
  prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, privateAddress);
  machine.ssh.address = privateAddress;
  machine.ssh.user = "root"_ctv;
  machine.ssh.privateKeyPath = "/tmp/unit-test-key"_ctv;
  machine.ownership.mode = ClusterMachineOwnershipMode::wholeMachine;
  machine.totalLogicalCores = 4;
  machine.totalMemoryMB = 8192;
  machine.totalStorageMB = 65'536;
  machine.ownedLogicalCores = 4;
  machine.ownedMemoryMB = 8192;
  machine.ownedStorageMB = 65'536;
  return machine;
}

static ClusterMachine makeAdoptedMachine(const String& privateAddress, bool isBrain)
{
  ClusterMachine machine = {};
  machine.source = ClusterMachineSource::adopted;
  machine.backing = ClusterMachineBacking::owned;
  machine.lifetime = MachineLifetime::owned;
  machine.kind = MachineConfig::MachineKind::vm;
  machine.isBrain = isBrain;
  prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, privateAddress);
  machine.ssh.address = privateAddress;
  machine.ssh.user = "root"_ctv;
  machine.ssh.privateKeyPath = "/tmp/unit-test-key"_ctv;
  machine.ownership.mode = ClusterMachineOwnershipMode::hardCaps;
  machine.ownership.nLogicalCoresCap = 4;
  machine.ownership.nMemoryMBCap = 8192;
  machine.ownership.nStorageMBCap = 65'536;
  machine.ownedLogicalCores = 4;
  machine.ownedMemoryMB = 8192;
  machine.ownedStorageMB = 65'536;
  return machine;
}

static BrainConfig makeBrainConfig(uint128_t clusterUUID, uint32_t datacenterFragment, const String& slug)
{
  BrainConfig config = {};
  config.clusterUUID = clusterUUID;
  config.datacenterFragment = datacenterFragment;
  config.autoscaleIntervalSeconds = 30;
  MachineConfig machineConfig = makeMachineConfig(slug, MachineConfig::MachineKind::vm, 4, 8192, 65'536);
  config.configBySlug.insert_or_assign(machineConfig.slug, machineConfig);
  return config;
}

static bool readExact(int fd, uint8_t *buffer, size_t length, String& failure)
{
  while (length > 0)
  {
    ssize_t rc = ::recv(fd, buffer, length, 0);
    if (rc > 0)
    {
      buffer += size_t(rc);
      length -= size_t(rc);
      continue;
    }

    if (rc < 0 && errno == EINTR)
    {
      continue;
    }

    if (rc == 0)
    {
      failure.assign("unexpected eof while reading unix control frame"_ctv);
    }
    else
    {
      failure.snprintf<"recv failed: {}"_ctv>(String(std::strerror(errno)));
    }
    return false;
  }

  failure.clear();
  return true;
}

static bool sendAll(int fd, const String& frame, String& failure)
{
  const uint8_t *buffer = frame.data();
  size_t remaining = size_t(frame.size());

  while (remaining > 0)
  {
    ssize_t rc = ::send(fd, buffer, remaining, 0);
    if (rc > 0)
    {
      buffer += size_t(rc);
      remaining -= size_t(rc);
      continue;
    }

    if (rc < 0 && errno == EINTR)
    {
      continue;
    }

    failure.snprintf<"send failed: {}"_ctv>(String(std::strerror(errno)));
    return false;
  }

  failure.clear();
  return true;
}

static bool recvOneMessageFrame(int fd, String& frame, String& failure)
{
  MothershipWireHeader header = {};
  if (readExact(fd, reinterpret_cast<uint8_t *>(&header), sizeof(header), failure) == false)
  {
    return false;
  }

  if (header.size < sizeof(Message))
  {
    failure.assign("received framed message smaller than Message header"_ctv);
    return false;
  }

  frame.clear();
  frame.append(reinterpret_cast<uint8_t *>(&header), sizeof(header));

  uint32_t remaining = header.size - uint32_t(sizeof(header));
  if (remaining == 0)
  {
    failure.clear();
    return true;
  }

  uint8_t scratch[4096];
  while (remaining > 0)
  {
    uint32_t chunk = (remaining < sizeof(scratch)) ? remaining : uint32_t(sizeof(scratch));
    if (readExact(fd, scratch, chunk, failure) == false)
    {
      return false;
    }

    frame.append(scratch, chunk);
    remaining -= chunk;
  }

  failure.clear();
  return true;
}

static bool extractSerializedPayload(const String& frame, String& serialized, String& failure)
{
  if (frame.size() < sizeof(Message))
  {
    failure.assign("frame too small for Message"_ctv);
    return false;
  }

  Message *message = reinterpret_cast<Message *>(const_cast<uint8_t *>(frame.data()));
  uint8_t *cursor = message->args;
  Message::extractToStringView(cursor, serialized);
  if (cursor > message->terminal())
  {
    failure.assign("message payload overflow"_ctv);
    return false;
  }

  failure.clear();
  return true;
}

static bool decodeConfigureRequest(const String& frame, BrainConfig& config, String& failure)
{
  config = {};

  Message *message = reinterpret_cast<Message *>(const_cast<uint8_t *>(frame.data()));
  if (MothershipTopic(message->topic) != MothershipTopic::configure)
  {
    failure.assign("unexpected topic for configure request"_ctv);
    return false;
  }

  String serialized = {};
  if (extractSerializedPayload(frame, serialized, failure) == false)
  {
    return false;
  }

  if (BitseryEngine::deserializeSafe(serialized, config) == false)
  {
    failure.assign("configure request decode failed"_ctv);
    return false;
  }

  failure.clear();
  return true;
}

static bool decodeAddMachinesRequest(const String& frame, AddMachines& request, String& failure)
{
  request = {};

  Message *message = reinterpret_cast<Message *>(const_cast<uint8_t *>(frame.data()));
  if (MothershipTopic(message->topic) != MothershipTopic::addMachines)
  {
    failure.assign("unexpected topic for addMachines request"_ctv);
    return false;
  }

  String serialized = {};
  if (extractSerializedPayload(frame, serialized, failure) == false)
  {
    return false;
  }

  if (BitseryEngine::deserializeSafe(serialized, request) == false)
  {
    failure.assign("addMachines request decode failed"_ctv);
    return false;
  }

  failure.clear();
  return true;
}

static bool sendConfigureResponse(int fd, const BrainConfig& config, String& failure)
{
  String serialized = {};
  BrainConfig responseConfig = config;
  BitseryEngine::serialize(serialized, responseConfig);

  String response = {};
  Message::construct(response, MothershipTopic::configure, serialized);
  return sendAll(fd, response, failure);
}

static bool sendAddMachinesResponse(int fd, const AddMachines& responsePayload, String& failure)
{
  String serialized = {};
  AddMachines payloadCopy = responsePayload;
  BitseryEngine::serialize(serialized, payloadCopy);

  String response = {};
  Message::construct(response, MothershipTopic::addMachines, serialized);
  return sendAll(fd, response, failure);
}

static bool acceptNextClient(int listenerFD, ControlServerState& state, int& clientFD)
{
  clientFD = -1;

  while (state.stopRequested.load() == false)
  {
    struct pollfd pollFD = {};
    pollFD.fd = listenerFD;
    pollFD.events = POLLIN;

    int rc = ::poll(&pollFD, 1, 100);
    if (rc > 0 && (pollFD.revents & POLLIN))
    {
      clientFD = ::accept(listenerFD, nullptr, nullptr);
      if (clientFD >= 0)
      {
        state.acceptCount += 1;
        return true;
      }

      if (errno == EINTR)
      {
        continue;
      }

      state.failure.snprintf<"accept failed: {}"_ctv>(String(std::strerror(errno)));
      return false;
    }

    if (rc == 0)
    {
      continue;
    }

    if (rc < 0 && errno == EINTR)
    {
      continue;
    }

    state.failure.snprintf<"poll failed: {}"_ctv>(String(std::strerror(errno)));
    return false;
  }

  return false;
}

static bool handleConfigureStep(int clientFD, uint128_t expectedClusterUUID, uint32_t expectedDatacenterFragment, const String& expectedSlug, String& failure)
{
  String frame = {};
  if (recvOneMessageFrame(clientFD, frame, failure) == false)
  {
    return false;
  }

  BrainConfig config = {};
  if (decodeConfigureRequest(frame, config, failure) == false)
  {
    return false;
  }

  if (config.clusterUUID != expectedClusterUUID)
  {
    failure.assign("configure clusterUUID mismatch"_ctv);
    return false;
  }

  if (config.datacenterFragment != expectedDatacenterFragment)
  {
    failure.assign("configure datacenterFragment mismatch"_ctv);
    return false;
  }

  auto it = config.configBySlug.find(expectedSlug);
  if (it == config.configBySlug.end())
  {
    failure.assign("configure machine config slug missing"_ctv);
    return false;
  }

  return sendConfigureResponse(clientFD, config, failure);
}

static bool handleFetchTopologyStep(int clientFD, uint64_t expectedVersion, uint32_t expectedMachines, String& failure)
{
  String frame = {};
  if (recvOneMessageFrame(clientFD, frame, failure) == false)
  {
    return false;
  }

  AddMachines request = {};
  if (decodeAddMachinesRequest(frame, request, failure) == false)
  {
    return false;
  }

  if (request.adoptedMachines.empty() == false || request.readyMachines.empty() == false || request.removedMachines.empty() == false)
  {
    failure.assign("fetchTopology request unexpectedly carried machine mutations"_ctv);
    return false;
  }

  AddMachines response = {};
  response.success = true;
  response.hasTopology = true;
  response.topology.version = expectedVersion;
  for (uint32_t index = 0; index < expectedMachines; index += 1)
  {
    response.topology.machines.push_back(makeTopologyMachine("fd00::1"_ctv, true));
  }

  return sendAddMachinesResponse(clientFD, response, failure);
}

static bool handleApplyAddMachinesStep(int clientFD, uint64_t expectedFinalVersion, String& failure)
{
  String frame = {};
  if (recvOneMessageFrame(clientFD, frame, failure) == false)
  {
    return false;
  }

  AddMachines request = {};
  if (decodeAddMachinesRequest(frame, request, failure) == false)
  {
    return false;
  }

  if (request.adoptedMachines.size() != 1 || request.readyMachines.empty() == false || request.removedMachines.empty() == false)
  {
    failure.assign("applyAddMachines request shape mismatch"_ctv);
    return false;
  }

  const ClusterMachine& adopted = request.adoptedMachines[0];
  if (adopted.backing != ClusterMachineBacking::owned || adopted.cloud.schema.size() != 0 || adopted.ssh.address != "fd00::20"_ctv)
  {
    failure.assign("applyAddMachines adopted machine payload mismatch"_ctv);
    return false;
  }

  AddMachines progress = {};
  progress.isProgress = true;
  MachineProvisioningProgress provisioning = {};
  provisioning.cloud.schema = "aws-brain-vm"_ctv;
  provisioning.cloud.providerMachineType = "c7i-flex.large"_ctv;
  provisioning.cloud.cloudID = "i-progress"_ctv;
  provisioning.ssh.address = "fd00::20"_ctv;
  provisioning.ssh.port = 22;
  provisioning.ssh.user = "root"_ctv;
  provisioning.ssh.privateKeyPath = "/tmp/unit-test-key"_ctv;
  prodigyAppendUniqueClusterMachineAddress(provisioning.addresses.privateAddresses, "fd00::20"_ctv);
  provisioning.providerName = "brain-1"_ctv;
  provisioning.status = "bootstrap-started"_ctv;
  progress.provisioningProgress.push_back(provisioning);

  if (sendAddMachinesResponse(clientFD, progress, failure) == false)
  {
    return false;
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  AddMachines finalResponse = {};
  finalResponse.success = true;
  finalResponse.hasTopology = true;
  finalResponse.topology.version = expectedFinalVersion;
  finalResponse.topology.machines.push_back(makeTopologyMachine("fd00::1"_ctv, true));
  finalResponse.topology.machines.push_back(makeTopologyMachine("fd00::20"_ctv, true));
  return sendAddMachinesResponse(clientFD, finalResponse, failure);
}

static bool createUnixListener(ScopedUnixListener& listener, String& failure)
{
  failure.clear();

  static std::atomic<uint64_t> unixListenerCounter = 0;
  char pathBuffer[sizeof(sockaddr_un::sun_path)] = {};
  std::snprintf(
      pathBuffer,
      sizeof(pathBuffer),
      "/tmp/nametag-mship-%d-%llu.sock",
      int(::getpid()),
      (unsigned long long)unixListenerCounter.fetch_add(1, std::memory_order_relaxed));
  listener.path.assign(pathBuffer);

  (void)::unlink(listener.path.c_str());

  listener.fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (listener.fd < 0)
  {
    failure.snprintf<"socket failed: {}"_ctv>(String(std::strerror(errno)));
    return false;
  }

  struct sockaddr_un address = {};
  address.sun_family = AF_UNIX;
  std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", listener.path.c_str());
  socklen_t addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));

  if (::bind(listener.fd, reinterpret_cast<struct sockaddr *>(&address), addressLen) != 0)
  {
    failure.snprintf<"bind failed: {}"_ctv>(String(std::strerror(errno)));
    return false;
  }

  if (::listen(listener.fd, 16) != 0)
  {
    failure.snprintf<"listen failed: {}"_ctv>(String(std::strerror(errno)));
    return false;
  }

  return true;
}

static bool createTcpListener(ScopedTcpListener& listener, String& failure)
{
  failure.clear();
  listener.fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (listener.fd < 0)
  {
    failure.snprintf<"tcp socket failed: {}"_ctv>(String(std::strerror(errno)));
    return false;
  }

  int one = 1;
  (void)::setsockopt(listener.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (::bind(listener.fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 || ::listen(listener.fd, 1) != 0)
  {
    failure.snprintf<"tcp listen failed: {}"_ctv>(String(std::strerror(errno)));
    return false;
  }

  socklen_t addressLen = sizeof(address);
  if (::getsockname(listener.fd, reinterpret_cast<sockaddr *>(&address), &addressLen) != 0)
  {
    failure.snprintf<"tcp getsockname failed: {}"_ctv>(String(std::strerror(errno)));
    return false;
  }

  listener.port = ntohs(address.sin_port);
  return listener.port != 0;
}

static bool acceptWithTimeout(int listenerFD, int& acceptedFD, String& failure)
{
  acceptedFD = -1;
  pollfd pollFD = {};
  pollFD.fd = listenerFD;
  pollFD.events = POLLIN;
  int rc = ::poll(&pollFD, 1, 3000);
  if (rc <= 0)
  {
    failure.assign(rc == 0 ? "accept timed out"_ctv : String(std::strerror(errno)));
    return false;
  }
  acceptedFD = ::accept(listenerFD, nullptr, nullptr);
  if (acceptedFD < 0)
  {
    failure.snprintf<"accept failed: {}"_ctv>(String(std::strerror(errno)));
    return false;
  }
  failure.clear();
  return true;
}

static void setReceiveTimeout(int fd)
{
  timeval timeout = {};
  timeout.tv_sec = 3;
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

static bool spawnTunnelProvider(const String& binaryPath, ScopedProcess& process, String& failure)
{
  String ownedPath = {};
  ownedPath.assign(binaryPath);
  pid_t pid = ::fork();
  if (pid < 0)
  {
    failure.snprintf<"fork failed: {}"_ctv>(String(std::strerror(errno)));
    return false;
  }
  if (pid == 0)
  {
    ::execl(ownedPath.c_str(), "mothership-tunnel-provider", nullptr);
    _exit(127);
  }
  process.pid = pid;
  failure.clear();
  return true;
}

int main(void)
{
  TestSuite suite;
  Mothership mothership = {};

#if PRODIGY_DEBUG
  {
    MothershipConnectivity connectivity = {};
    suite.expect(parseConnectivityFixture("{\"kind\":\"ssh\"}"_ctv, connectivity) && connectivity.kind == MothershipConnectivityKind::ssh, "mothership_connectivity_parse_ssh_without_artifact");
    suite.expect(parseConnectivityFixture("{\"kind\":\"ssh\",\"providerContainerBlobPath\":\"x\"}"_ctv, connectivity) == false, "mothership_connectivity_parse_ssh_rejects_tunnel_artifact");
    suite.expect(parseConnectivityFixture("{\"kind\":\"tunnelProvider\",\"providerContainerBlobPath\":\"x\",\"dialEndpoint\":\"control.example.net:443\",\"egressHost\":\"1.1.1.1\",\"egressPort\":443}"_ctv, connectivity) && connectivity.tunnelProvider.egressHost.equal("1.1.1.1"_ctv) && connectivity.tunnelProvider.egressPort == 443, "mothership_connectivity_parse_tunnel_endpoint");
    suite.expect(parseConnectivityFixture("{\"kind\":\"tunnelProvider\",\"dialEndpoint\":\"control.example.net:443\",\"egressHost\":\"1.1.1.1\",\"egressPort\":443}"_ctv, connectivity) == false, "mothership_connectivity_parse_tunnel_rejects_missing_artifact");
    suite.expect(parseConnectivityFixture("{\"kind\":\"tunnelProvider\",\"providerContainerBlobPath\":\"x\",\"dialEndpoint\":\"\",\"egressHost\":\"1.1.1.1\",\"egressPort\":443}"_ctv, connectivity) == false, "mothership_connectivity_parse_tunnel_rejects_empty_endpoint");
    suite.expect(parseConnectivityFixture("{\"kind\":\"tunnelProvider\",\"providerContainerBlobPath\":\"x\",\"dialEndpoint\":\"control.example.net:443\",\"egressHost\":\"1.1.1.1\",\"egressPort\":0}"_ctv, connectivity) == false, "mothership_connectivity_parse_tunnel_rejects_zero_egress_port");
    suite.expect(parseConnectivityFixture("{\"kind\":\"tunnelProvider\",\"providerContainerBlobPath\":\"x\",\"dialEndpoint\":\"control.example.net:443\",\"egressPort\":443}"_ctv, connectivity) == false, "mothership_connectivity_parse_tunnel_rejects_missing_egress_host");
    suite.expect(parseConnectivityFixture("{\"kind\":\"tunnelProvider\",\"providerContainerBlobPath\":\"x\",\"dialEndpoint\":\"control.example.net:443\",\"egressHost\":\"1.1.1.1\"}"_ctv, connectivity) == false, "mothership_connectivity_parse_tunnel_rejects_missing_egress_port");
    suite.expect(parseConnectivityFixture("{\"kind\":\"tunnelProvider\",\"providerContainerBlobPath\":\"x\",\"dialEndpoint\":\"control.example.net:443\",\"egressHost\":\"edge.example.net\",\"egressPort\":443}"_ctv, connectivity) == false, "mothership_connectivity_parse_tunnel_rejects_hostname_egress");
    suite.expect(parseConnectivityFixture("{\"kind\":\"tunnelProvider\",\"providerContainerBlobPath\":\"x\",\"dialEndpoint\":\"control.example.net:443\",\"egressHost\":\"169.254.169.254\",\"egressPort\":443}"_ctv, connectivity) == false, "mothership_connectivity_parse_tunnel_rejects_metadata_egress");

  }

  {
    TemporaryDirectory workspace = {};
    TemporaryDirectory systemStoreRoot = {};
    suite.expect(workspace.create("prodigy-mothership-artifact"), "tunnel_provider_artifact_workspace_created");
    suite.expect(systemStoreRoot.create("prodigy-system-store"), "tunnel_provider_artifact_store_created");
    if (workspace.path.size() > 0 && systemStoreRoot.path.size() > 0)
    {
      String tunnelBlob = {};
      tunnelBlob.assign(prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText());
      tunnelBlob.append("tunnel-provider-payload"_ctv);
      std::filesystem::path tunnelBlobPath = filesystemPathFromString(workspace.path) / "mothership-tunnel-provider.blob";
      String tunnelBlobPathText = stringFromFilesystemPath(tunnelBlobPath);
      suite.expect(writeFileFixture(tunnelBlobPath, tunnelBlob), "tunnel_provider_artifact_fixture_written");

      MothershipTunnelProviderSpec spec = {};
      String failure = {};
      bool prepared = mothership.unitTestPrepareTunnelProviderArtifact(spec, tunnelBlobPathText, systemStoreRoot.path, &failure);
      suite.expect(prepared, "tunnel_provider_artifact_preflight_accepts_valid_blob");
      suite.expect(failure.size() == 0, "tunnel_provider_artifact_preflight_valid_no_failure");
      suite.expect(spec.artifactBytes == tunnelBlob.size(), "tunnel_provider_artifact_preflight_sets_size");
      suite.expect(ContainerStore::systemVerify(spec.artifactSha256, spec.artifactBytes, nullptr, nullptr, &failure, &systemStoreRoot.path), "tunnel_provider_artifact_preflight_stores_blob");
      uint128_t clusterUUID = 0xABC1;
      suite.expect(mothership.unitTestPrepareTunnelProviderGatewayAuth(spec, &failure), "tunnel_provider_gateway_auth_preflight_generates");
      suite.expect(spec.clientAuth.configured(), "tunnel_provider_gateway_auth_preflight_sets_client_auth");
      suite.expect(spec.gatewayAuth.configured(), "tunnel_provider_gateway_auth_preflight_sets_gateway_auth");
      String appBlob = {};
      appBlob.assign(prodigyDiscombobulatorBlobHeaderText());
      for (uint32_t index = 0; index < 32; ++index)
      {
        appBlob.append("app-payload"_ctv);
      }
      std::filesystem::path appBlobPath = filesystemPathFromString(workspace.path) / "app.blob";
      String appBlobPathText = stringFromFilesystemPath(appBlobPath);
      suite.expect(writeFileFixture(appBlobPath, appBlob), "tunnel_provider_artifact_app_fixture_written");
      MothershipTunnelProviderSpec appSpec = {};
      suite.expect(mothership.unitTestPrepareTunnelProviderArtifact(appSpec, appBlobPathText, systemStoreRoot.path, &failure) == false, "tunnel_provider_artifact_preflight_rejects_app_blob");
    }
  }
#endif

  {
    ScopedTcpListener edgeListener = {};
    ScopedUnixListener gatewayListener = {};
    String relayFailure = {};
    suite.expect(createTcpListener(edgeListener, relayFailure), "tunnel_provider_relay_edge_listener_created");
    suite.expect(createUnixListener(gatewayListener, relayFailure), "tunnel_provider_relay_gateway_listener_created");
    if (edgeListener.port != 0 && gatewayListener.fd >= 0)
    {
      String providerBinary = PRODIGY_TEST_BINARY_DIR "/mothership-tunnel-provider";
      ScopedEnvVar socketEnv("PRODIGY_MOTHERSHIP_SOCKET", gatewayListener.path);
      String edgePort = {};
      edgePort.assignItoa(edgeListener.port);
      ScopedEnvVar edgeHostEnv("PRODIGY_TUNNEL_EGRESS_HOST", "127.0.0.1");
      ScopedEnvVar edgePortEnv("PRODIGY_TUNNEL_EGRESS_PORT", edgePort);
      ScopedProcess provider = {};
      suite.expect(spawnTunnelProvider(providerBinary, provider, relayFailure), "tunnel_provider_relay_started");

      int edgeFD = -1;
      int gatewayFD = -1;
      bool edgeAccepted = provider.pid > 0 && acceptWithTimeout(edgeListener.fd, edgeFD, relayFailure);
      suite.expect(edgeAccepted, "tunnel_provider_relay_dials_policy_tcp_endpoint");
      bool gatewayAccepted = edgeAccepted && acceptWithTimeout(gatewayListener.fd, gatewayFD, relayFailure);
      suite.expect(gatewayAccepted, "tunnel_provider_relay_opens_gateway_socket");
      if (gatewayAccepted)
      {
        setReceiveTimeout(edgeFD);
        setReceiveTimeout(gatewayFD);

        String edgePayload = "edge-to-gateway"_ctv;
        uint8_t edgeBuffer[32] = {};
        suite.expect(sendAll(edgeFD, edgePayload, relayFailure), "tunnel_provider_relay_accepts_edge_bytes");
        suite.expect(readExact(gatewayFD, edgeBuffer, edgePayload.size(), relayFailure) && std::memcmp(edgeBuffer, edgePayload.data(), edgePayload.size()) == 0, "tunnel_provider_relay_edge_to_gateway");

        String gatewayPayload = "gateway-to-edge"_ctv;
        uint8_t gatewayBuffer[32] = {};
        suite.expect(sendAll(gatewayFD, gatewayPayload, relayFailure), "tunnel_provider_relay_accepts_gateway_bytes");
        suite.expect(readExact(edgeFD, gatewayBuffer, gatewayPayload.size(), relayFailure) && std::memcmp(gatewayBuffer, gatewayPayload.data(), gatewayPayload.size()) == 0, "tunnel_provider_relay_gateway_to_edge");
      }
      if (edgeFD >= 0)
      {
        ::close(edgeFD);
      }
      if (gatewayFD >= 0)
      {
        ::close(gatewayFD);
      }
      provider.terminate();
    }
  }

  {
    String endpointHost = {};
    uint16_t endpointPort = 0;
    String endpointFailure = {};
    suite.expect(mothershipParseEndpointHostPort("control.example.net:443"_ctv, endpointHost, endpointPort, &endpointFailure) && endpointHost.equal("control.example.net"_ctv) && endpointPort == 443, "mothership_connectivity_parse_gateway_endpoint_host_port");
    suite.expect(mothershipParseEndpointHostPort("[2001:db8::1]:443"_ctv, endpointHost, endpointPort, &endpointFailure) == false, "mothership_connectivity_parse_gateway_endpoint_rejects_ipv6");
  }

  ScopedUnixListener listener = {};
  String setupFailure = {};
  bool listenerReady = createUnixListener(listener, setupFailure);
  suite.expect(listenerReady, "unix_listener_created");
  if (listenerReady == false)
  {
    if (setupFailure.size() > 0)
    {
      basics_log("listener setup failure: %s\n", setupFailure.c_str());
    }
    return EXIT_FAILURE;
  }

  {
    MothershipProdigyCluster remoteCluster = {};
    remoteCluster.name = "remote-candidate-test"_ctv;
    remoteCluster.deploymentMode = MothershipClusterDeploymentMode::remote;
    remoteCluster.controls.push_back(makeUnixControl(listener.path));
    remoteCluster.bootstrapSshUser = "root"_ctv;
    remoteCluster.bootstrapSshPrivateKeyPath = "/tmp/unit-test-key"_ctv;

    ClusterMachine topologyBrain = {};
    topologyBrain.source = ClusterMachineSource::created;
    topologyBrain.backing = ClusterMachineBacking::cloud;
    topologyBrain.lifetime = MachineLifetime::ondemand;
    topologyBrain.kind = MachineConfig::MachineKind::vm;
    topologyBrain.isBrain = true;
    prodigyAppendUniqueClusterMachineAddress(topologyBrain.addresses.privateAddresses, "10.0.0.5"_ctv);
    prodigyAppendUniqueClusterMachineAddress(topologyBrain.addresses.publicAddresses, "203.0.113.10"_ctv);
    remoteCluster.topology.machines.push_back(topologyBrain);

    Vector<MothershipProdigyClusterMachine> remoteCandidates = {};
    String failure = {};
    bool remoteConfigureOK = mothership.unitTestConfigureClusterSocket(remoteCluster, remoteCandidates, &failure);
    suite.expect(remoteConfigureOK, "remote_topology_candidate_configure_ok");
    suite.expect(failure.size() == 0, "remote_topology_candidate_configure_no_failure");
    suite.expect(remoteCandidates.size() == 1, "remote_topology_candidate_count");
    if (remoteCandidates.size() == 1)
    {
      suite.expect(remoteCandidates[0].ssh.address == "203.0.113.10"_ctv, "remote_topology_candidate_prefers_public_address");
      suite.expect(remoteCandidates[0].ssh.port == 22, "remote_topology_candidate_ssh_port");
      suite.expect(remoteCandidates[0].ssh.user == "root"_ctv, "remote_topology_candidate_ssh_user");
      suite.expect(remoteCandidates[0].ssh.privateKeyPath == "/tmp/unit-test-key"_ctv, "remote_topology_candidate_ssh_key");
      suite.expect(remoteCandidates[0].isBrain, "remote_topology_candidate_is_brain");
    }

    MothershipProdigyCluster tunnelCluster = remoteCluster;
    tunnelCluster.clusterUUID = 0x7101;
    tunnelCluster.name = "remote-tunnel-provider-test"_ctv;
    tunnelCluster.mothershipConnectivity.kind = MothershipConnectivityKind::tunnelProvider;
    MothershipTunnelProviderSpec& tunnelProvider = tunnelCluster.mothershipConnectivity.tunnelProvider;
    tunnelProvider.artifactSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv;
    tunnelProvider.artifactBytes = 128;
    tunnelProvider.dialEndpoint = "gateway.example.net:443"_ctv;
    tunnelProvider.egressHost = "1.1.1.1"_ctv;
    tunnelProvider.egressPort = 443;
    bool tunnelConfigureOK = mothership.unitTestConfigureClusterSocket(tunnelCluster, remoteCandidates, &failure);
    suite.expect(tunnelConfigureOK == false, "tunnel_provider_configure_rejects_missing_client_auth");
    suite.expect(remoteCandidates.empty(), "tunnel_provider_configure_missing_auth_no_ssh_candidates");
    suite.expect(failure.equals("tunnelProvider client auth required for gateway dialing"_ctv), "tunnel_provider_configure_missing_auth_failure_reason");

    MothershipTunnelGatewayAuth ignoredGatewayAuth = {};
    bool authFixture = mothershipGenerateTunnelGatewayAuth(tunnelProvider.clientAuth, ignoredGatewayAuth, &failure);
    suite.expect(authFixture, "tunnel_provider_configure_client_auth_fixture");
    if (authFixture)
    {
      tunnelConfigureOK = mothership.unitTestConfigureClusterSocket(tunnelCluster, remoteCandidates, &failure);
      suite.expect(tunnelConfigureOK, "tunnel_provider_configure_selects_gateway_target");
      suite.expect(remoteCandidates.empty(), "tunnel_provider_configure_gateway_target_has_no_ssh_candidates");
      suite.expect(failure.size() == 0, "tunnel_provider_configure_gateway_target_no_failure");

      MothershipProdigyCluster malformedEndpointCluster = tunnelCluster;
      malformedEndpointCluster.mothershipConnectivity.tunnelProvider.dialEndpoint = "gateway.example.net"_ctv;
      tunnelConfigureOK = mothership.unitTestConfigureClusterSocket(malformedEndpointCluster, remoteCandidates, &failure);
      suite.expect(tunnelConfigureOK, "tunnel_provider_configure_accepts_nonempty_endpoint_metadata");
      suite.expect(mothership.unitTestConnectConfiguredSocket(failure) == false && failure.equal("tunnelProvider gateway endpoint invalid: endpoint must be host:port"_ctv), "tunnel_provider_connect_malformed_endpoint_fails_closed");

      MothershipProdigyCluster malformedAuthCluster = tunnelCluster;
      malformedAuthCluster.mothershipConnectivity.tunnelProvider.clientAuth.clientKeyPem.assign("not-a-key"_ctv);
      tunnelConfigureOK = mothership.unitTestConfigureClusterSocket(malformedAuthCluster, remoteCandidates, &failure);
      suite.expect(tunnelConfigureOK == false, "tunnel_provider_configure_rejects_malformed_client_auth");
      suite.expect(remoteCandidates.empty(), "tunnel_provider_configure_malformed_auth_no_ssh_candidates");
      suite.expect(failure.equals("mothership tunnel gateway client auth certificate material invalid"_ctv), "tunnel_provider_configure_malformed_auth_failure_reason");
    }
  }

  ControlServerState server = {};
  std::thread serverThread([&]() {
    String stepFailure = {};

    auto closeClient = [](int clientFD) -> void {
      if (clientFD >= 0)
      {
        (void)::shutdown(clientFD, SHUT_RDWR);
        ::close(clientFD);
      }
    };

    int clientFD = -1;
    if (acceptNextClient(listener.fd, server, clientFD) == false)
    {
      return;
    }
    if (handleConfigureStep(clientFD, uint128_t(0x1001), 11, "seed-brain"_ctv, stepFailure) == false)
    {
      server.failure = stepFailure;
      server.stopRequested.store(true);
      closeClient(clientFD);
      return;
    }
    closeClient(clientFD);

    clientFD = -1;
    if (acceptNextClient(listener.fd, server, clientFD) == false)
    {
      return;
    }
    if (handleFetchTopologyStep(clientFD, 0x11, 1, stepFailure) == false)
    {
      server.failure = stepFailure;
      server.stopRequested.store(true);
      closeClient(clientFD);
      return;
    }
    closeClient(clientFD);

    clientFD = -1;
    if (acceptNextClient(listener.fd, server, clientFD) == false)
    {
      return;
    }
    if (handleConfigureStep(clientFD, uint128_t(0x1001), 12, "seed-brain"_ctv, stepFailure) == false)
    {
      server.failure = stepFailure;
      server.stopRequested.store(true);
      closeClient(clientFD);
      return;
    }
    closeClient(clientFD);

    clientFD = -1;
    if (acceptNextClient(listener.fd, server, clientFD) == false)
    {
      return;
    }
    if (handleApplyAddMachinesStep(clientFD, 0x22, stepFailure) == false)
    {
      server.failure = stepFailure;
      server.stopRequested.store(true);
      closeClient(clientFD);
      return;
    }
    closeClient(clientFD);

    clientFD = -1;
    if (acceptNextClient(listener.fd, server, clientFD) == false)
    {
      return;
    }
    if (handleConfigureStep(clientFD, uint128_t(0x1001), 13, "seed-brain"_ctv, stepFailure) == false)
    {
      server.failure = stepFailure;
      server.stopRequested.store(true);
      closeClient(clientFD);
      return;
    }
    closeClient(clientFD);
  });

  MothershipProdigyCluster cluster = {};
  cluster.name = "unix-control-test"_ctv;
  cluster.deploymentMode = MothershipClusterDeploymentMode::local;
  cluster.controls.push_back(makeUnixControl(listener.path));

  String failure = {};

  BrainConfig configureA = makeBrainConfig(uint128_t(0x1001), 11, "seed-brain"_ctv);
  bool configureAOK = mothership.unitTestConfigureSeedCluster(cluster, configureA, &failure);
  suite.expect(configureAOK, "unix_control_configure_first_ok");
  suite.expect(failure.size() == 0, "unix_control_configure_first_no_failure");
  if (configureAOK == false && failure.size() > 0)
  {
    basics_log("configureA failure: %s\n", failure.c_str());
    server.stopRequested.store(true);
  }

  ClusterTopology fetchedTopology = {};
  if (configureAOK)
  {
    MothershipProdigyCluster tunnelBootstrapCluster = cluster;
    tunnelBootstrapCluster.mothershipConnectivity.kind = MothershipConnectivityKind::tunnelProvider;
    bool fetchTopologyOK = mothership.unitTestFetchSeedTopology(tunnelBootstrapCluster, fetchedTopology, &failure);
    suite.expect(fetchTopologyOK, "unix_control_fetch_topology_uses_bootstrap_for_tunnel_create");
    suite.expect(failure.size() == 0, "unix_control_fetch_topology_no_failure");
    suite.expect(fetchedTopology.version == 0x11, "unix_control_fetch_topology_version");
    suite.expect(fetchedTopology.machines.size() == 1, "unix_control_fetch_topology_machine_count");
    if (fetchTopologyOK == false && failure.size() > 0)
    {
      basics_log("fetchTopology failure: %s\n", failure.c_str());
      server.stopRequested.store(true);
    }
  }

  BrainConfig configureB = makeBrainConfig(uint128_t(0x1001), 12, "seed-brain"_ctv);
  if (server.stopRequested.load() == false)
  {
    bool configureBOK = mothership.unitTestConfigureSeedCluster(cluster, configureB, &failure);
    suite.expect(configureBOK, "unix_control_configure_second_ok");
    suite.expect(failure.size() == 0, "unix_control_configure_second_no_failure");
    if (configureBOK == false && failure.size() > 0)
    {
      basics_log("configureB failure: %s\n", failure.c_str());
      server.stopRequested.store(true);
    }
  }

  AddMachines addMachinesRequest = {};
  addMachinesRequest.adoptedMachines.push_back(makeAdoptedMachine("fd00::20"_ctv, true));

  ClusterTopology finalTopology = {};
  if (server.stopRequested.load() == false)
  {
    bool addMachinesOK = mothership.unitTestApplyAddMachines(cluster, addMachinesRequest, finalTopology, &failure);
    suite.expect(addMachinesOK, "unix_control_addmachines_ok");
    suite.expect(failure.size() == 0, "unix_control_addmachines_no_failure");
    suite.expect(finalTopology.version == 0x22, "unix_control_addmachines_topology_version");
    suite.expect(finalTopology.machines.size() == 2, "unix_control_addmachines_machine_count");
    if (addMachinesOK == false && failure.size() > 0)
    {
      basics_log("addMachines failure: %s\n", failure.c_str());
      server.stopRequested.store(true);
    }
  }

  BrainConfig configureC = makeBrainConfig(uint128_t(0x1001), 13, "seed-brain"_ctv);
  if (server.stopRequested.load() == false)
  {
    bool configureCOK = mothership.unitTestConfigureSeedCluster(cluster, configureC, &failure);
    suite.expect(configureCOK, "unix_control_configure_after_addmachines_ok");
    suite.expect(failure.size() == 0, "unix_control_configure_after_addmachines_no_failure");
    if (configureCOK == false && failure.size() > 0)
    {
      basics_log("configureC failure: %s\n", failure.c_str());
      server.stopRequested.store(true);
    }
  }

  server.stopRequested.store(true);
  serverThread.join();

  suite.expect(server.failure.size() == 0, "unix_control_server_sequence_no_failure");
  suite.expect(server.acceptCount == 5, "unix_control_server_accept_count");
  if (server.failure.size() > 0)
  {
    basics_log("server failure: %s\n", server.failure.c_str());
  }

  {
    ScopedTcpListener gatewayListener = {};
    ScopedUnixListener gatewayControl = {};
    String gatewayFailure = {};
    bool gatewayListenerReady = createTcpListener(gatewayListener, gatewayFailure);
    suite.expect(gatewayListenerReady, "tunnel_gateway_tls_listener_created");
    bool gatewayControlReady = createUnixListener(gatewayControl, gatewayFailure);
    suite.expect(gatewayControlReady, "tunnel_gateway_control_listener_created");
    if (gatewayListenerReady && gatewayControlReady)
    {
      MothershipProdigyCluster gatewayCluster = {};
      gatewayCluster.clusterUUID = 0x7201;
      gatewayCluster.name = "loopback-tunnel-gateway-test"_ctv;
      gatewayCluster.mothershipConnectivity.kind = MothershipConnectivityKind::tunnelProvider;
      MothershipTunnelProviderSpec& provider = gatewayCluster.mothershipConnectivity.tunnelProvider;
      provider.artifactSha256 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv;
      provider.artifactBytes = 128;
      provider.dialEndpoint.snprintf<"127.0.0.1:{itoa}"_ctv>(unsigned(gatewayListener.port));
      provider.egressHost = "1.1.1.1"_ctv;
      provider.egressPort = 443;
      MothershipTunnelGatewayAuth gatewayAuth = {};
      MothershipTunnelGatewayTLSContext gatewayTLS = {};
      bool gatewayTLSReady = mothershipGenerateTunnelGatewayAuth(provider.clientAuth, gatewayAuth, &gatewayFailure) && gatewayTLS.configure(gatewayAuth, &gatewayFailure);
      suite.expect(gatewayTLSReady, "tunnel_gateway_tls_auth_fixture_created");
      if (gatewayTLSReady)
      {
        {
          ScopedUnixListener rejectedControl = {};
          bool rejectedControlReady = createUnixListener(rejectedControl, gatewayFailure);
          suite.expect(rejectedControlReady, "tunnel_gateway_reject_control_listener_created");
          if (rejectedControlReady)
          {
            MothershipTunnelGatewayUnixListener rejectedGateway = {};
            String rejectedGatewayPath = rejectedControl.path;
            rejectedGatewayPath.append(".gateway"_ctv);
            bool rejectedGatewayReady = mothershipTunnelGatewayCreateUnixListener(rejectedGatewayPath, rejectedGateway, &gatewayFailure);
            suite.expect(rejectedGatewayReady, "tunnel_gateway_unix_listener_created");
            if (rejectedGatewayReady)
            {
              struct stat gatewayStat = {};
              suite.expect(::stat(rejectedGateway.path.c_str(), &gatewayStat) == 0 && gatewayStat.st_uid == prodigyMothershipTunnelProviderRuntimeUID && gatewayStat.st_gid == prodigyMothershipTunnelProviderRuntimeUID, "tunnel_gateway_unix_listener_provider_owner");
              suite.expect((gatewayStat.st_mode & 0777) == 0600, "tunnel_gateway_unix_listener_provider_mode");

              int clientFD = -1;
              MothershipTunnelGatewaySessionResult rejectedResult = {};
              String rejectedFailure = {};
              bool rejectedProxy = true;
              bool connected = mothershipTunnelGatewayOpenUnixControlSocket(rejectedGateway.path, clientFD, &rejectedFailure);
              suite.expect(connected, "tunnel_gateway_unix_listener_accepts_local_stream");
              if (connected)
              {
                std::thread rejectedThread([&]() {
                  int rejectedFD = -1;
                  rejectedProxy = mothershipTunnelGatewayAcceptUnixStream(rejectedGateway.fd, rejectedFD, &rejectedFailure) &&
                      mothershipTunnelGatewayProxyAuthenticatedControlStream(rejectedFD, rejectedControl.path, gatewayTLS, &rejectedResult, &rejectedFailure);
                  if (rejectedFD >= 0)
                  {
                    (void)::shutdown(rejectedFD, SHUT_RDWR);
                    ::close(rejectedFD);
                  }
                });

                String garbage = "not-tls"_ctv;
                (void)::send(clientFD, garbage.data(), garbage.size(), 0);
                (void)::shutdown(clientFD, SHUT_RDWR);
                ::close(clientFD);
                rejectedThread.join();
              }

              pollfd rejectedPoll = {};
              rejectedPoll.fd = rejectedControl.fd;
              rejectedPoll.events = POLLIN;
              int rejectedReady = ::poll(&rejectedPoll, 1, 50);
              suite.expect(rejectedProxy == false && rejectedResult.authenticated == false && rejectedResult.openedControlSocket == false, "tunnel_gateway_rejects_malformed_auth_before_control_open");
              suite.expect(rejectedReady == 0, "tunnel_gateway_reject_does_not_touch_control_socket");
            }
          }
        }

        {
          MothershipTunnelGatewayUnixListener peerGateway = {};
          String peerGatewayPath = gatewayControl.path;
          peerGatewayPath.append(".peer"_ctv);
          bool peerGatewayReady = mothershipTunnelGatewayCreateUnixListener(peerGatewayPath, peerGateway, &gatewayFailure);
          suite.expect(peerGatewayReady, "tunnel_gateway_peer_listener_created");
          if (peerGatewayReady)
          {
            int clientFD = -1;
            int acceptedFD = -1;
            bool peerConnected = mothershipTunnelGatewayOpenUnixControlSocket(peerGateway.path, clientFD, &gatewayFailure);
            suite.expect(peerConnected || gatewayFailure.size() > 0, "tunnel_gateway_peer_reject_client_attempted");
            if (peerConnected)
            {
              suite.expect(mothershipTunnelGatewayAcceptUnixStream(peerGateway.fd, acceptedFD, &gatewayFailure) == false && acceptedFD < 0, "tunnel_gateway_peer_credentials_rejected");
            }
            if (clientFD >= 0)
            {
              ::close(clientFD);
            }
          }
        }

        {
          String cgroupFailure = {};
          suite.expect(mothershipTunnelGatewayPeerCgroupAllowed(getpid(), ""_ctv, &cgroupFailure), "tunnel_gateway_peer_cgroup_empty_policy_allows");
          suite.expect(mothershipTunnelGatewayPeerCgroupAllowed(getpid(), "/containers.slice/not-current.slice/leaf"_ctv, &cgroupFailure) == false &&
                           cgroupFailure.equal("mothership tunnel gateway peer cgroup rejected"_ctv),
                       "tunnel_gateway_peer_cgroup_mismatch_rejected");
        }

        {
          ScopedUnixListener idleControl = {};
          bool idleControlReady = createUnixListener(idleControl, gatewayFailure);
          suite.expect(idleControlReady, "tunnel_gateway_idle_control_listener_created");
          if (idleControlReady)
          {
            MothershipTunnelGatewaySessionResult idleResult = {};
            String idleFailure = {};
            bool idleProxy = true;
            std::thread idleGatewayThread([&]() {
              int gatewayFD = ::accept(gatewayListener.fd, nullptr, nullptr);
              if (gatewayFD < 0)
              {
                idleFailure.snprintf<"gateway idle accept failed: {}"_ctv>(String(std::strerror(errno)));
                return;
              }
              idleProxy = mothershipTunnelGatewayProxyAuthenticatedControlStream(gatewayFD, idleControl.path, gatewayTLS, &idleResult, &idleFailure, 100);
              (void)::shutdown(gatewayFD, SHUT_RDWR);
              ::close(gatewayFD);
            });

            MothershipSocket idleSocket = {};
            bool idleConnected = idleSocket.configureCluster(gatewayCluster, &failure) && idleSocket.connect() == 0;
            suite.expect(idleConnected, "tunnel_gateway_idle_client_connects");
            if (idleConnected)
            {
              std::this_thread::sleep_for(std::chrono::milliseconds(500));
              idleSocket.close();
            }
            else
            {
              int unblockFD = -1;
              if (mothershipOpenConnectedSocket("127.0.0.1"_ctv, gatewayListener.port, unblockFD))
              {
                ::close(unblockFD);
              }
            }
            idleGatewayThread.join();
            suite.expect(idleProxy == false && idleResult.authenticated && idleResult.openedControlSocket, "tunnel_gateway_idle_timeout_closes_authenticated_session");
            suite.expect(idleFailure.equal("mothership tunnel gateway proxy idle timeout"_ctv), "tunnel_gateway_idle_timeout_failure_reason");
          }
        }

        MothershipTunnelGatewaySessionResult gatewayResult = {};
        ControlServerState gatewayControlState = {};
        String gatewayControlFailure = {};
        String gatewayProxyFailure = {};
        std::thread controlThread([&]() {
          int controlFD = -1;
          if (acceptNextClient(gatewayControl.fd, gatewayControlState, controlFD) == false)
          {
            return;
          }

          String frame = {};
          if (recvOneMessageFrame(controlFD, frame, gatewayControlFailure))
          {
            (void)sendAll(controlFD, frame, gatewayControlFailure);
          }
          ::close(controlFD);
        });

        std::thread gatewayThread([&]() {
          int gatewayFD = ::accept(gatewayListener.fd, nullptr, nullptr);
          if (gatewayFD < 0)
          {
            gatewayFailure.snprintf<"gateway accept failed: {}"_ctv>(String(std::strerror(errno)));
            return;
          }

          bool proxied = mothershipTunnelGatewayProxyAuthenticatedControlStream(
              gatewayFD,
              gatewayControl.path,
              gatewayTLS,
              &gatewayResult,
              &gatewayProxyFailure);
          (void)::shutdown(gatewayFD, SHUT_RDWR);
          ::close(gatewayFD);
          if (proxied == false)
          {
            basics_log("gateway tls fixture failure: %s\n", gatewayProxyFailure.c_str());
          }
        });

        MothershipSocket tunnelSocket = {};
        bool configured = tunnelSocket.configureCluster(gatewayCluster, &failure);
        bool connected = configured && tunnelSocket.connect() == 0;
        suite.expect(connected, "tunnel_gateway_tls_client_connects_with_persisted_auth");
        bool echoed = false;
        if (connected)
        {
          Message::construct(tunnelSocket.wBuffer, MothershipTopic::pullClusterReport);
          echoed = tunnelSocket.send() && tunnelSocket.recvExpectedTopic(MothershipTopic::pullClusterReport) != nullptr;
        }
        suite.expect(echoed, "tunnel_gateway_tls_proxies_control_bytes_after_auth");
        tunnelSocket.close();
        if (connected == false || echoed == false)
        {
          gatewayControlState.stopRequested.store(true);
          int unblockFD = -1;
          if (mothershipOpenConnectedSocket("127.0.0.1"_ctv, gatewayListener.port, unblockFD))
          {
            ::close(unblockFD);
          }
          if ((unblockFD = ::socket(AF_UNIX, SOCK_STREAM, 0)) >= 0)
          {
            sockaddr_un address = {};
            address.sun_family = AF_UNIX;
            std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", gatewayControl.path.c_str());
            (void)::connect(unblockFD, reinterpret_cast<sockaddr *>(&address), socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path)));
            ::close(unblockFD);
          }
        }
        gatewayThread.join();
        gatewayControlState.stopRequested.store(true);
        controlThread.join();
        suite.expect(gatewayProxyFailure.size() == 0 && gatewayControlFailure.size() == 0, "tunnel_gateway_tls_server_authorizes_client");
        suite.expect(gatewayResult.authenticated && gatewayResult.openedControlSocket, "tunnel_gateway_tls_opens_control_socket_after_auth");
      }
    }
  }

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
