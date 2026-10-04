#pragma once

#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <services/time.h>

#include <prodigy/bootstrap.peers.h>
#include <prodigy/bundle.artifact.h>
#include <prodigy/mothership/mothership.cluster.test.h>
#include <prodigy/mothership/mothership.cluster.types.h>
#include <prodigy/persistent.state.h>
#include <prodigy/remote.bootstrap.h>

constexpr static const char *mothershipVirtualDatacenterPIDFilename = "virtual-datacenter.pid";
constexpr static const char *mothershipVirtualDatacenterReadyFilename = "virtual-datacenter.ready";
constexpr static const char *mothershipVirtualDatacenterProvisionedFilename = "virtual-datacenter.provisioned";
constexpr static const char *mothershipVirtualDatacenterMembersProvisionedFilename = "virtual-datacenter.members-provisioned";
constexpr static const char *mothershipVirtualDatacenterSeedRuntimeFilename = "virtual-datacenter.seed-runtime";
constexpr static const char *mothershipVirtualDatacenterRuntimeFilename = "virtual-datacenter.runtime";
constexpr static const char *mothershipVirtualDatacenterPairBoundaryRoot = "/mnt/prodigy-vdc-pairs";

// This is an Mothership-owned, test-provider descriptor.  It deliberately has
// no application or controller authority: its sole purpose is to bind a
// provider boundary to identities Mothership has already admitted and durably
// recorded.  The provider rechecks the live runtime and selected machine
// against these fields before it changes a namespace.
class MothershipVirtualDatacenterPairBoundaryDescriptor {
public:
  String operationID;
  String sourceClusterUUID;
  String targetClusterUUID;
  String sourceWorkspace;
  String targetWorkspace;
  String sourceRuntimeIdentity;
  String targetRuntimeIdentity;
  String sourceParentNamespace;
  String targetParentNamespace;
  uint32_t sourceMachineIndex = 0;
  uint32_t targetMachineIndex = 0;
  String sourceMachinePrivate4;
  String targetMachinePrivate4;
  String endpointIPv4;
  uint16_t endpointPort = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipVirtualDatacenterPairBoundaryDescriptor& descriptor)
{
  serializer.text1b(descriptor.operationID, 34);
  serializer.text1b(descriptor.sourceClusterUUID, 34);
  serializer.text1b(descriptor.targetClusterUUID, 34);
  serializer.text1b(descriptor.sourceWorkspace, UINT32_MAX);
  serializer.text1b(descriptor.targetWorkspace, UINT32_MAX);
  serializer.text1b(descriptor.sourceRuntimeIdentity, 32);
  serializer.text1b(descriptor.targetRuntimeIdentity, 32);
  serializer.text1b(descriptor.sourceParentNamespace, 32);
  serializer.text1b(descriptor.targetParentNamespace, 32);
  serializer.value4b(descriptor.sourceMachineIndex);
  serializer.value4b(descriptor.targetMachineIndex);
  serializer.text1b(descriptor.sourceMachinePrivate4, 15);
  serializer.text1b(descriptor.targetMachinePrivate4, 15);
  serializer.text1b(descriptor.endpointIPv4, 15);
  serializer.value2b(descriptor.endpointPort);
}

static inline bool mothershipVirtualDatacenterPairBoundaryTokenValid(const String& value, uint32_t minimum, uint32_t maximum)
{
  if (value.size() < minimum || value.size() > maximum)
  {
    return false;
  }
  for (char byte : value)
  {
    if (byte <= ' ' || byte == '/' || byte == '\\')
    {
      return false;
    }
  }
  return true;
}

static inline bool mothershipVirtualDatacenterPairBoundaryHexIDValid(const String& value)
{
  uint128_t parsed = 0;
  return prodigyParseCanonicalHex128(value, parsed);
}

static inline bool mothershipVirtualDatacenterPairBoundaryRuntimeValid(const String& value)
{
  if (value.empty() || value[0] == '0')
  {
    return false;
  }
  uint64_t parsed = 0;
  for (char byte : value)
  {
    if (byte < '0' || byte > '9' || parsed > (UINT64_MAX - uint64_t(byte - '0')) / 10)
    {
      return false;
    }
    parsed = parsed * 10 + uint64_t(byte - '0');
  }
  return parsed > 1;
}

static inline bool mothershipVirtualDatacenterPairBoundaryDescriptorValid(
    const MothershipVirtualDatacenterPairBoundaryDescriptor& descriptor, String *failure = nullptr)
{
  String sourceWorkspace = descriptor.sourceWorkspace, targetWorkspace = descriptor.targetWorkspace;
  String endpointText = descriptor.endpointIPv4, sourceIP = descriptor.sourceMachinePrivate4, targetIP = descriptor.targetMachinePrivate4;
  auto reject = [&](const char *reason) -> bool {
    if (failure) failure->assign(reason);
    return false;
  };
  if (!mothershipVirtualDatacenterPairBoundaryHexIDValid(descriptor.operationID) ||
      !mothershipVirtualDatacenterPairBoundaryHexIDValid(descriptor.sourceClusterUUID) ||
      !mothershipVirtualDatacenterPairBoundaryHexIDValid(descriptor.targetClusterUUID) ||
      descriptor.sourceClusterUUID == descriptor.targetClusterUUID)
  {
    return reject("pair boundary requires distinct canonical operation and cluster IDs");
  }
  if (descriptor.sourceWorkspace.size() < 2 || descriptor.targetWorkspace.size() < 2 ||
      descriptor.sourceWorkspace[0] != '/' || descriptor.targetWorkspace[0] != '/' ||
      descriptor.sourceWorkspace == descriptor.targetWorkspace || descriptor.sourceWorkspace[descriptor.sourceWorkspace.size() - 1] == '/' ||
      descriptor.targetWorkspace[descriptor.targetWorkspace.size() - 1] == '/' ||
      std::strstr(sourceWorkspace.c_str(), "/../") != nullptr || std::strstr(targetWorkspace.c_str(), "/../") != nullptr ||
      std::strchr(sourceWorkspace.c_str(), '\n') != nullptr || std::strchr(targetWorkspace.c_str(), '\n') != nullptr)
  {
    return reject("pair boundary requires distinct canonical workspaces");
  }
  if (!mothershipVirtualDatacenterPairBoundaryRuntimeValid(descriptor.sourceRuntimeIdentity) ||
      !mothershipVirtualDatacenterPairBoundaryRuntimeValid(descriptor.targetRuntimeIdentity) ||
      descriptor.sourceRuntimeIdentity == descriptor.targetRuntimeIdentity ||
      descriptor.sourceMachineIndex == 0 || descriptor.targetMachineIndex == 0 ||
      descriptor.sourceMachineIndex > 128 || descriptor.targetMachineIndex > 128 ||
      !mothershipVirtualDatacenterPairBoundaryTokenValid(descriptor.sourceMachinePrivate4, 7, 15) ||
      !mothershipVirtualDatacenterPairBoundaryTokenValid(descriptor.targetMachinePrivate4, 7, 15))
  {
    return reject("pair boundary runtime or selected machine identity is invalid");
  }
  String expectedSourceNamespace = {};
  expectedSourceNamespace.snprintf<"pvd-p-{}"_ctv>(descriptor.sourceRuntimeIdentity);
  String expectedTargetNamespace = {};
  expectedTargetNamespace.snprintf<"pvd-p-{}"_ctv>(descriptor.targetRuntimeIdentity);
  if (descriptor.sourceParentNamespace != expectedSourceNamespace || descriptor.targetParentNamespace != expectedTargetNamespace)
  {
    return reject("pair boundary parent namespace does not match runtime identity");
  }
  in_addr endpoint = {}, sourcePrivate4 = {}, targetPrivate4 = {};
  if (::inet_pton(AF_INET, endpointText.c_str(), &endpoint) != 1 || descriptor.endpointPort == 0 ||
      (ntohl(endpoint.s_addr) & 0xfffe0000u) != 0xc6120000u ||
      ::inet_pton(AF_INET, sourceIP.c_str(), &sourcePrivate4) != 1 ||
      ::inet_pton(AF_INET, targetIP.c_str(), &targetPrivate4) != 1 ||
      (ntohl(sourcePrivate4.s_addr) & 0xff000000u) != 0x0a000000u || (ntohl(targetPrivate4.s_addr) & 0xff000000u) != 0x0a000000u)
  {
    return reject("pair boundary endpoint or machine IPv4 identity is invalid");
  }
  if (failure) failure->clear();
  return true;
}


// The provider has no retirement authority.  This is a typed observation of
// its current pair-router state, bound to the descriptor Mothership admitted.
class MothershipVirtualDatacenterPairDrainObservation {
public:
  uint32_t version = 1;
  String operationID;
  String sourceClusterUUID;
  String targetClusterUUID;
  String sourceRuntimeIdentity;
  String targetRuntimeIdentity;
  uint32_t sourceMachineIndex = 0;
  uint32_t targetMachineIndex = 0;
  bool selectedTarget = false;
  bool drainCapability = false;
  uint64_t sourceFlows = 0;
  uint64_t targetFlows = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipVirtualDatacenterPairDrainObservation& observation)
{
  serializer.value4b(observation.version);
  serializer.text1b(observation.operationID, 34);
  serializer.text1b(observation.sourceClusterUUID, 34);
  serializer.text1b(observation.targetClusterUUID, 34);
  serializer.text1b(observation.sourceRuntimeIdentity, 32);
  serializer.text1b(observation.targetRuntimeIdentity, 32);
  serializer.value4b(observation.sourceMachineIndex);
  serializer.value4b(observation.targetMachineIndex);
  serializer.value1b(observation.selectedTarget);
  serializer.value1b(observation.drainCapability);
  serializer.value8b(observation.sourceFlows);
  serializer.value8b(observation.targetFlows);
}

static inline bool mothershipVirtualDatacenterPairDrainObservationBoundValid(
    const MothershipVirtualDatacenterPairBoundaryDescriptor& boundary,
    const MothershipVirtualDatacenterPairDrainObservation& observation, String *failure = nullptr)
{
  auto reject = [&](const char *reason) -> bool { if (failure) failure->assign(reason); return false; };
  if (!mothershipVirtualDatacenterPairBoundaryDescriptorValid(boundary, failure)) return false;
  if (observation.version != 1 || observation.operationID != boundary.operationID ||
      observation.sourceClusterUUID != boundary.sourceClusterUUID || observation.targetClusterUUID != boundary.targetClusterUUID ||
      observation.sourceRuntimeIdentity != boundary.sourceRuntimeIdentity || observation.targetRuntimeIdentity != boundary.targetRuntimeIdentity ||
      observation.sourceMachineIndex != boundary.sourceMachineIndex || observation.targetMachineIndex != boundary.targetMachineIndex)
    return reject("pair drain observation does not match the admitted boundary");
  if (failure) failure->clear();
  return true;
}

static inline bool mothershipVirtualDatacenterParsePairDrainUnsigned(const String& text, uint64_t& value)
{
  if (text.empty() || (text.size() > 1 && text[0] == '0')) return false;
  uint64_t parsed = 0;
  for (char byte : text)
  {
    if (byte < '0' || byte > '9' || parsed > (UINT64_MAX - uint64_t(byte - '0')) / 10) return false;
    parsed = parsed * 10 + uint64_t(byte - '0');
  }
  value = parsed;
  return true;
}

static inline bool mothershipVirtualDatacenterParsePairDrainObservation(
    const String& output, const MothershipVirtualDatacenterPairBoundaryDescriptor& expected,
    MothershipVirtualDatacenterPairDrainObservation& observation, String *failure = nullptr)
{
  auto reject = [&](const char *reason) -> bool { observation = {}; if (failure) failure->assign(reason); return false; };
  if (!mothershipVirtualDatacenterPairBoundaryDescriptorValid(expected, failure)) return false;
  constexpr const char prefix[] = "PAIR_BOUNDARY";
  const char *cursor = reinterpret_cast<const char *>(output.data()), *terminal = reinterpret_cast<const char *>(output.data()) + output.size();
  auto match = [&](const char *text) {
    for (; *text != 0; ++text) { if (cursor == terminal || *cursor++ != *text) return false; }
    return true;
  };
  auto field = [&](const char *name, String& value) {
    if (cursor == terminal || *cursor++ != ' ' || !match(name) || cursor == terminal || *cursor++ != '=') return false;
    const char *begin = cursor;
    while (cursor != terminal && *cursor != ' ' && *cursor != '\n' && *cursor != '\r')
    {
      const unsigned char byte = static_cast<unsigned char>(*cursor);
      if (byte < 0x21 || byte > 0x7e) return false;
      ++cursor;
    }
    if (cursor == begin) return false;
    value.clear(); value.append(begin, uint64_t(cursor - begin));
    return true;
  };
  String operation = {}, sourceCluster = {}, targetCluster = {}, sourceRuntime = {}, targetRuntime = {};
  String sourceMachine = {}, targetMachine = {}, selected = {}, capability = {}, sourceFlows = {}, targetFlows = {};
  if (!match(prefix) || !field("operationID", operation) || !field("sourceClusterUUID", sourceCluster) ||
      !field("targetClusterUUID", targetCluster) || !field("sourceRuntimeIdentity", sourceRuntime) ||
      !field("targetRuntimeIdentity", targetRuntime) || !field("sourceMachineIndex", sourceMachine) ||
      !field("targetMachineIndex", targetMachine) || !field("selected", selected) ||
      !field("drainCapability", capability) || !field("sourceFlows", sourceFlows) || !field("targetFlows", targetFlows))
    return reject("pair drain observation is malformed");
  if (cursor != terminal)
  {
    if (*cursor == '\n') ++cursor;
    else if (*cursor == '\r' && cursor + 1 != terminal && cursor[1] == '\n') cursor += 2;
    else return reject("pair drain observation has invalid line ending");
  }
  if (cursor != terminal) return reject("pair drain observation has trailing data");
  uint64_t sourceIndex = 0, targetIndex = 0, selectedValue = 0, capabilityValue = 0, sourceCount = 0, targetCount = 0;
  if (!mothershipVirtualDatacenterParsePairDrainUnsigned(sourceMachine, sourceIndex) || sourceIndex > UINT32_MAX ||
      !mothershipVirtualDatacenterParsePairDrainUnsigned(targetMachine, targetIndex) || targetIndex > UINT32_MAX ||
      !mothershipVirtualDatacenterParsePairDrainUnsigned(selected, selectedValue) || (selectedValue != 1 && selectedValue != 2) ||
      !mothershipVirtualDatacenterParsePairDrainUnsigned(capability, capabilityValue) || capabilityValue != 1 ||
      !mothershipVirtualDatacenterParsePairDrainUnsigned(sourceFlows, sourceCount) ||
      !mothershipVirtualDatacenterParsePairDrainUnsigned(targetFlows, targetCount))
    return reject("pair drain observation has invalid counters or selector");
  observation.version = 1; observation.operationID = std::move(operation);
  observation.sourceClusterUUID = std::move(sourceCluster); observation.targetClusterUUID = std::move(targetCluster);
  observation.sourceRuntimeIdentity = std::move(sourceRuntime); observation.targetRuntimeIdentity = std::move(targetRuntime);
  observation.sourceMachineIndex = uint32_t(sourceIndex); observation.targetMachineIndex = uint32_t(targetIndex);
  observation.selectedTarget = selectedValue == 2; observation.drainCapability = true;
  observation.sourceFlows = sourceCount; observation.targetFlows = targetCount;
  if (!mothershipVirtualDatacenterPairDrainObservationBoundValid(expected, observation, failure)) { observation = {}; return false; }
  return true;
}


class MothershipVirtualDatacenterPairGuestResetFence {
public:
  String operationID;
  String descriptorSHA256;
  String bootID;
  String guestID;
};

template <typename S>
static void serialize(S&& serializer, MothershipVirtualDatacenterPairGuestResetFence& fence)
{
  serializer.text1b(fence.operationID, 34);
  serializer.text1b(fence.descriptorSHA256, 64);
  serializer.text1b(fence.bootID, 36);
  serializer.text1b(fence.guestID, 128);
}

static inline bool mothershipVirtualDatacenterBootIDValid(const String& value)
{
  if (value.size() != 36) return false;
  bool nonzero = false;
  for (uint32_t i = 0; i < value.size(); ++i)
  {
    if (i == 8 || i == 13 || i == 18 || i == 23) { if (value[i] != '-') return false; }
    else
    {
      if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
      nonzero = nonzero || value[i] != '0';
    }
  }
  return nonzero;
}

static inline bool mothershipVirtualDatacenterPairDescriptorSHA256(
    const MothershipVirtualDatacenterPairBoundaryDescriptor& boundary, String& digest)
{
  if (!mothershipVirtualDatacenterPairBoundaryDescriptorValid(boundary)) return false;
  String encoded = {}, value = {};
  auto line = [&](const String& field) { encoded.append(field); encoded.append("\n"_ctv); };
  value.assign(mothershipVirtualDatacenterPairBoundaryRoot); value.append("/"_ctv); value.append(boundary.operationID); line(value);
  line(boundary.operationID); line(boundary.sourceClusterUUID); line(boundary.targetClusterUUID);
  line(boundary.sourceWorkspace); line(boundary.sourceRuntimeIdentity);
  value.clear(); value.assignItoa(boundary.sourceMachineIndex); line(value); line(boundary.sourceMachinePrivate4);
  line(boundary.targetWorkspace); line(boundary.targetRuntimeIdentity);
  value.clear(); value.assignItoa(boundary.targetMachineIndex); line(value); line(boundary.targetMachinePrivate4);
  line(boundary.endpointIPv4); value.clear(); value.assignItoa(boundary.endpointPort); line(value);
  return prodigyComputeSHA256Hex(encoded, digest);
}

static inline bool mothershipVirtualDatacenterPairGuestResetFenceValid(
    const MothershipVirtualDatacenterPairGuestResetFence& fence,
    const MothershipVirtualDatacenterPairBoundaryDescriptor& boundary)
{
  if (fence.operationID != boundary.operationID || !mothershipVirtualDatacenterBootIDValid(fence.bootID) ||
      fence.guestID.empty() || fence.guestID.size() > 128) return false;
  for (uint32_t i = 0; i < fence.guestID.size(); ++i)
  {
    const char ch = fence.guestID[i];
    if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
          (i > 0 && (ch == '-' || ch == '_' || ch == '.')))) return false;
  }
  String digest = {};
  return mothershipVirtualDatacenterPairDescriptorSHA256(boundary, digest) && digest == fence.descriptorSHA256;
}

// One bounded provider line; no caller-supplied reset assertion is accepted.
// Completion additionally names the observed post-reset kernel boot.
static inline bool mothershipVirtualDatacenterParsePairGuestResetObservation(
    const String& output, const MothershipVirtualDatacenterPairBoundaryDescriptor& boundary,
    MothershipVirtualDatacenterPairGuestResetFence& fence, String *completedBootID = nullptr)
{
  fence = {};
  if (completedBootID) completedBootID->clear();
  MothershipVirtualDatacenterPairGuestResetFence parsed = {};
  String parsedCompletion = {};
  if (output.empty() || output.size() > 512) return false;
  const char *cursor = reinterpret_cast<const char *>(output.data());
  const char *end = cursor + output.size();
  auto match = [&](const char *literal) {
    size_t n = std::strlen(literal);
    if (size_t(end - cursor) < n || std::memcmp(cursor, literal, n) != 0) return false;
    cursor += n; return true;
  };
  auto field = [&](const char *name, String& value) {
    if (!match(" ") || !match(name) || !match("=")) return false;
    const char *begin = cursor;
    while (cursor < end && *cursor > ' ' && *cursor < 127) ++cursor;
    if (cursor == begin) return false;
    value.append(begin, uint64_t(cursor - begin)); return true;
  };
  if (!match(completedBootID ? "PAIR_GUEST_RESET_COMPLETE" : "PAIR_GUEST_RESET") ||
      !field("operationID", parsed.operationID) || !field("descriptorSHA256", parsed.descriptorSHA256) ||
      !field("bootID", parsed.bootID) || !field("guestID", parsed.guestID) ||
      (completedBootID && !field("completedBootID", parsedCompletion))) return false;
  if (cursor < end && *cursor == '\n') ++cursor;
  if (cursor != end || !mothershipVirtualDatacenterPairGuestResetFenceValid(parsed, boundary) ||
      (completedBootID && (!mothershipVirtualDatacenterBootIDValid(parsedCompletion) || parsedCompletion == parsed.bootID))) return false;
  fence = std::move(parsed);
  if (completedBootID) *completedBootID = std::move(parsedCompletion);
  return true;
}

static inline void mothershipVirtualDatacenterPath(const String& workspaceRoot, const char *name, String& path)
{
  path.assign(workspaceRoot);
  if (path.size() > 0 && path[path.size() - 1] != '/')
  {
    path.append('/');
  }
  path.append(name);
}

static inline bool mothershipVirtualDatacenterWriteFile(String& path, const String& contents, mode_t mode, String *failure = nullptr)
{
  String temporary = {};
  temporary.snprintf<"{}.{itoa}.tmp"_ctv>(path, uint64_t(::getpid()));
  int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0)
  {
    if (failure)
    {
      failure->snprintf<"failed to open {}: {}"_ctv>(temporary, String(std::strerror(errno)));
    }
    return false;
  }

  uint64_t offset = 0;
  while (offset < contents.size())
  {
    ssize_t written = ::write(fd, contents.data() + offset, size_t(contents.size() - offset));
    if (written < 0 && errno == EINTR)
    {
      continue;
    }
    if (written <= 0)
    {
      int saved = errno;
      ::close(fd);
      ::unlink(temporary.c_str());
      if (failure)
      {
        failure->snprintf<"failed to write {}: {}"_ctv>(path, String(std::strerror(saved)));
      }
      return false;
    }
    offset += uint64_t(written);
  }

  if (::fsync(fd) != 0)
  {
    int saved = errno;
    ::close(fd);
    ::unlink(temporary.c_str());
    if (failure)
    {
      failure->snprintf<"failed to sync {}: {}"_ctv>(path, String(std::strerror(saved)));
    }
    return false;
  }
  ::close(fd);

  if (::rename(temporary.c_str(), path.c_str()) != 0)
  {
    int saved = errno;
    ::unlink(temporary.c_str());
    if (failure)
    {
      failure->snprintf<"failed to publish {}: {}"_ctv>(path, String(std::strerror(saved)));
    }
    return false;
  }
  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline void mothershipVirtualDatacenterMachineAddresses(
    uint32_t index, uint8_t datacenterFragment, bool fakeIpv4Boundary,
    String& private4, String& private6, String& public6)
{
  const uint32_t domain = uint32_t(datacenterFragment) - 1;
  char host[9] = {};
  char private6Domain[9] = {};
  std::snprintf(host, sizeof(host), "%x", 9 + index);
  std::snprintf(private6Domain, sizeof(private6Domain), "%x", domain);
  private4.snprintf<"10.0.{itoa}.{itoa}"_ctv>(uint64_t(domain), uint64_t(9 + index));
  if (domain == 0)
  {
    private6.snprintf<"fd00:10::{}"_ctv>(String(host));
  }
  else
  {
    private6.snprintf<"fd00:10:{}::{}"_ctv>(String(private6Domain), String(host));
  }
  if (fakeIpv4Boundary)
  {
    public6.snprintf<"2602:fac0:0:12ab:34cd::{}"_ctv>(String(host));
  }
  else
  {
    public6.snprintf<"2001:db8:100::{}"_ctv>(String(host));
  }
}

static inline bool mothershipBuildVirtualDatacenterTopology(const MothershipProdigyCluster& cluster, ClusterTopology& topology, String *failure = nullptr)
{
  topology = {};
  topology.version = 1;
  if (cluster.deploymentMode != MothershipClusterDeploymentMode::test || cluster.datacenterFragment == 0 ||
      cluster.test.machineCount == 0 || cluster.nBrains == 0 || cluster.nBrains > cluster.test.machineCount)
  {
    if (failure)
    {
      failure->assign("invalid test cluster shape for virtual datacenter"_ctv);
    }
    return false;
  }

  String schema = {};
  if (cluster.machineSchemas.empty() == false)
  {
    schema = cluster.machineSchemas[0].schema;
  }

  for (uint32_t index = 1; index <= cluster.test.machineCount; ++index)
  {
    String private4 = {};
    String private6 = {};
    String public6 = {};
    mothershipVirtualDatacenterMachineAddresses(index, cluster.datacenterFragment, cluster.test.enableFakeIpv4Boundary, private4, private6, public6);

    ClusterMachine machine = {};
    machine.source = ClusterMachineSource::created;
    machine.backing = ClusterMachineBacking::owned;
    machine.kind = MachineConfig::MachineKind::vm;
    machine.lifetime = MachineLifetime::reserved;
    machine.isBrain = index <= cluster.nBrains;
    machine.rackUUID = index;
    machine.creationTimeMs = Time::now<TimeResolution::ms>();
    machine.hasCloud = schema.size() > 0;
    machine.cloud.schema = schema;
    prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, private4, 24);
    prodigyAppendUniqueClusterMachineAddress(machine.addresses.privateAddresses, private6, 64);
    prodigyAppendUniqueClusterMachineAddress(machine.addresses.publicAddresses, public6, 64);

    switch (cluster.test.brainBootstrapFamily)
    {
      case MothershipClusterTestBootstrapFamily::ipv4:
        prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress {private4, 24});
        break;
      case MothershipClusterTestBootstrapFamily::private6:
        prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress {private6, 64});
        break;
      case MothershipClusterTestBootstrapFamily::public6:
        prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress {public6, 64});
        break;
      case MothershipClusterTestBootstrapFamily::multihome6:
        prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress {private6, 64});
        prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress {public6, 64});
        break;
    }
    topology.machines.push_back(std::move(machine));
  }

  prodigyNormalizeClusterTopologyPeerAddresses(topology);
  if (failure)
  {
    failure->clear();
  }
  return true;
}

// Member boot material contains the local TLS identity.  Allocate and retain
// every member identity before any boot material is written, so the same
// topology is later admitted through readyMachines.  The seed has already
// published its durable identity and must be preserved exactly.
static inline bool mothershipAssignVirtualDatacenterMachineUUIDs(
    const ClusterTopology& seedTopology,
    ClusterTopology& topology,
    String *failure = nullptr)
{
  if (seedTopology.machines.size() != 1 || seedTopology.machines[0].uuid == 0 || topology.machines.empty())
  {
    if (failure) failure->assign("virtual datacenter identity assignment requires one identified seed"_ctv);
    return false;
  }

  for (uint32_t index = 0; index < topology.machines.size(); ++index)
  {
    if (topology.machines[index].uuid == 0)
    {
      continue;
    }
    for (uint32_t prior = 0; prior < index; ++prior)
    {
      if (topology.machines[prior].uuid == topology.machines[index].uuid)
      {
        if (failure) failure->assign("virtual datacenter topology contains duplicate machine UUIDs"_ctv);
        return false;
      }
    }
  }

  uint32_t seedIndex = uint32_t(topology.machines.size());
  for (uint32_t index = 0; index < topology.machines.size(); ++index)
  {
    if (topology.machines[index].sameIdentityAs(seedTopology.machines[0]) == false)
    {
      continue;
    }
    if (seedIndex != topology.machines.size() ||
        (topology.machines[index].uuid != 0 && topology.machines[index].uuid != seedTopology.machines[0].uuid))
    {
      if (failure)
      {
        if (seedIndex != topology.machines.size() && topology.machines[seedIndex].uuid == 0 &&
            topology.machines[index].uuid == seedTopology.machines[0].uuid)
        {
          failure->assign("virtual datacenter member UUID conflicts with configured seed"_ctv);
        }
        else
        {
          failure->assign("virtual datacenter seed identity is ambiguous"_ctv);
        }
      }
      return false;
    }
    seedIndex = index;
  }
  if (seedIndex == topology.machines.size())
  {
    if (failure) failure->assign("virtual datacenter topology does not contain the configured seed"_ctv);
    return false;
  }
  topology.machines[seedIndex].uuid = seedTopology.machines[0].uuid;

  for (ClusterMachine& machine : topology.machines)
  {
    if (machine.uuid != 0)
    {
      continue;
    }
    for (;;)
    {
      uint128_t candidate = Random::generateNumberWithNBits<128, uint128_t>();
      if (candidate == 0)
      {
        continue;
      }
      bool duplicate = false;
      for (const ClusterMachine& other : topology.machines)
      {
        if (&machine != &other && other.uuid == candidate)
        {
          duplicate = true;
          break;
        }
      }
      if (duplicate == false)
      {
        machine.uuid = candidate;
        break;
      }
    }
  }

  if (failure) failure->clear();
  return true;
}

static inline bool mothershipWriteVirtualDatacenterBootstrapMaterial(
    const MothershipProdigyCluster& cluster,
    uint32_t machineIndex,
    const String& bootJSON,
    const String& transportTLSJSON,
    String *failure = nullptr)
{
  String bootPath = {};
  bootPath.snprintf<"{}/boot/{itoa}.json"_ctv>(cluster.test.workspaceRoot, uint64_t(machineIndex));
  if (mothershipVirtualDatacenterWriteFile(bootPath, bootJSON, 0600, failure) == false)
  {
    return false;
  }
  String transportTLSPath = {};
  transportTLSPath.snprintf<"{}/transport-tls/{itoa}.json"_ctv>(cluster.test.workspaceRoot, uint64_t(machineIndex));
  return mothershipVirtualDatacenterWriteFile(transportTLSPath, transportTLSJSON, 0600, failure);
}

static inline bool mothershipProvisionVirtualDatacenterSeed(
    const MothershipProdigyCluster& cluster,
    const ClusterTopology& seedTopology,
    const AddMachines& request,
    const ProdigyRuntimeEnvironmentConfig& runtimeEnvironment,
    const String& bundlePath,
    String *failure = nullptr)
{
  String approvedDigest = {};
  if (prodigyApproveBundleArtifact(bundlePath, approvedDigest, failure) == false)
  {
    return false;
  }

  // The provider has already created every disposable root, but only this
  // phase authorizes the seed executable. Followers cannot start before their
  // configured, cluster-owned transport state exists.
  for (uint32_t index = 0; index < cluster.test.machineCount; ++index)
  {
    String installRoot = {};
    installRoot.snprintf<"{}/machines/{itoa}/root/prodigy"_ctv>(cluster.test.workspaceRoot, uint64_t(index + 1));
    if (prodigyInstallBundleToRoot(bundlePath, installRoot, failure) == false)
    {
      return false;
    }

  }

  if (seedTopology.machines.size() != 1)
  {
    if (failure) failure->assign("virtual datacenter seed bootstrap requires one-machine topology"_ctv);
    return false;
  }
  String bootJSON = {}, transportTLSJSON = {};
  if (prodigyBuildRemoteBootstrapBootMaterial(seedTopology.machines[0], request, seedTopology,
                                              runtimeEnvironment, bootJSON, transportTLSJSON, failure) == false ||
      mothershipWriteVirtualDatacenterBootstrapMaterial(cluster, 1, bootJSON, transportTLSJSON, failure) == false)
  {
    return false;
  }

  String provisionedPath = {};
  mothershipVirtualDatacenterPath(cluster.test.workspaceRoot, mothershipVirtualDatacenterProvisionedFilename, provisionedPath);
  return mothershipVirtualDatacenterWriteFile(provisionedPath, approvedDigest, 0600, failure);
}

static inline bool mothershipProvisionVirtualDatacenterMembers(
    const MothershipProdigyCluster& cluster,
    const ClusterTopology& topology,
    const AddMachines& request,
    const ProdigyRuntimeEnvironmentConfig& runtimeEnvironment,
    String *failure = nullptr)
{
  if (topology.machines.size() != cluster.test.machineCount || topology.machines.empty())
  {
    if (failure) failure->assign("virtual datacenter member bootstrap topology is invalid"_ctv);
    return false;
  }
  for (uint32_t index = 1; index < topology.machines.size(); ++index)
  {
    String bootJSON = {}, transportTLSJSON = {};
    if (prodigyBuildRemoteBootstrapBootMaterial(topology.machines[index], request, topology, runtimeEnvironment,
                                                bootJSON, transportTLSJSON, failure) == false ||
        mothershipWriteVirtualDatacenterBootstrapMaterial(cluster, index + 1, bootJSON, transportTLSJSON, failure) == false)
    {
      return false;
    }
  }
  String membersProvisionedPath = {};
  mothershipVirtualDatacenterPath(cluster.test.workspaceRoot, mothershipVirtualDatacenterMembersProvisionedFilename,
                                  membersProvisionedPath);
  return mothershipVirtualDatacenterWriteFile(membersProvisionedPath, "members\n"_ctv, 0600, failure);
}
