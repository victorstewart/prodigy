#include <atomic>
#include <services/debug.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define PRODIGY_MOTHERSHIP_TEST_ACCESS 1
#define main nametag_mothership_main_disabled
#include <prodigy/mothership/mothership.cpp>
#undef main

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

struct MothershipWireHeader
{
   uint32_t size = 0;
   uint16_t topic = 0;
   uint8_t padding = 0;
   uint8_t headerSize = 0;
};

static_assert(sizeof(MothershipWireHeader) == 8);

struct ControlServerState
{
   std::atomic<bool> stopRequested = false;
   uint32_t acceptCount = 0;
   String failure;
};

class ScopedUnixListener
{
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
      .path = path
   };
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
   machine.totalStorageMB = 65536;
   machine.ownedLogicalCores = 4;
   machine.ownedMemoryMB = 8192;
   machine.ownedStorageMB = 65536;
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
   machine.ownership.nStorageMBCap = 65536;
   machine.ownedLogicalCores = 4;
   machine.ownedMemoryMB = 8192;
   machine.ownedStorageMB = 65536;
   return machine;
}

static BrainConfig makeBrainConfig(uint128_t clusterUUID, uint32_t datacenterFragment, const String& slug)
{
   BrainConfig config = {};
   config.clusterUUID = clusterUUID;
   config.datacenterFragment = datacenterFragment;
   config.autoscaleIntervalSeconds = 30;
   MachineConfig machineConfig = makeMachineConfig(slug, MachineConfig::MachineKind::vm, 4, 8192, 65536);
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

   if (request.adoptedMachines.empty() == false
      || request.readyMachines.empty() == false
      || request.removedMachines.empty() == false)
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

   if (request.adoptedMachines.size() != 1
      || request.readyMachines.empty() == false
      || request.removedMachines.empty() == false)
   {
      failure.assign("applyAddMachines request shape mismatch"_ctv);
      return false;
   }

   const ClusterMachine& adopted = request.adoptedMachines[0];
   if (adopted.backing != ClusterMachineBacking::owned
      || adopted.cloud.schema.size() != 0
      || adopted.ssh.address != "fd00::20"_ctv)
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

   char pathBuffer[sizeof(sockaddr_un::sun_path)] = {};
   std::snprintf(
      pathBuffer,
      sizeof(pathBuffer),
      "/tmp/nametag-mship-%d-%u.sock",
      int(::getpid()),
      unsigned(Time::now<TimeResolution::ms>() & 0xffffffffu));
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

int main(void)
{
   TestSuite suite;
   Mothership mothership = {};

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
   }

   ControlServerState server = {};
   std::thread serverThread([&] () {
      String stepFailure = {};

      auto closeClient = [] (int clientFD) -> void {
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
      bool fetchTopologyOK = mothership.unitTestFetchSeedTopology(cluster, fetchedTopology, &failure);
      suite.expect(fetchTopologyOK, "unix_control_fetch_topology_ok");
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

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
