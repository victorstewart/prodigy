#pragma once

#include <prodigy/mothership/mothership.virtual.datacenter.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sched.h>
#include <climits>

// The provider keeps resource plumbing. Mothership owns the exact process
// identities, approved artifact, durable intent and ordering of recovery.
enum class MothershipVDCRecoveryPhase : uint8_t {
  accepted, frozen, ready, committed, workerStopped, workerKilled,
  rootInstalled, launchRequested, replaced, complete
};

class MothershipVDCProcessIdentity {
public:
  uint64_t pid = 0;
  uint64_t startTime = 0;
  uint64_t mountNamespace = 0;
  uint64_t networkNamespace = 0;
  uint64_t cgroupNamespace = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipVDCProcessIdentity& identity)
{
  serializer.value8b(identity.pid);
  serializer.value8b(identity.startTime);
  serializer.value8b(identity.mountNamespace);
  serializer.value8b(identity.networkNamespace);
  serializer.value8b(identity.cgroupNamespace);
}

class MothershipVDCBundleRecovery {
public:
  uint8_t version = 2;
  uint128_t clusterUUID = 0;
  uint128_t operationID = 0;
  uint64_t runtimeIdentity = 0;
  uint32_t machineIndex = 0;
  MothershipVDCRecoveryPhase phase = MothershipVDCRecoveryPhase::accepted;
  MothershipVDCProcessIdentity supervisor, worker, adopter, replacement;
  String expectedOldBundle, successorBundle, oldExecutable, successorExecutable;
  String expectedIncompleteWorkerBundle, previousBootSHA256, successorBootSHA256;
  String providerCgroup, workerCgroup;
  String providerArguments[12];
};

template <typename S>
static void serialize(S&& serializer, MothershipVDCBundleRecovery& operation)
{
  serializer.value1b(operation.version);
  serializer.value16b(operation.clusterUUID);
  serializer.value16b(operation.operationID);
  serializer.value8b(operation.runtimeIdentity);
  serializer.value4b(operation.machineIndex);
  serializer.value1b(operation.phase);
  serializer.object(operation.supervisor);
  serializer.object(operation.worker);
  serializer.object(operation.adopter);
  serializer.object(operation.replacement);
  serializer.text1b(operation.expectedOldBundle, 64);
  serializer.text1b(operation.successorBundle, 64);
  serializer.text1b(operation.oldExecutable, 64);
  serializer.text1b(operation.successorExecutable, 64);
  serializer.text1b(operation.expectedIncompleteWorkerBundle, 64);
  serializer.text1b(operation.previousBootSHA256, 64);
  serializer.text1b(operation.successorBootSHA256, 64);
  serializer.text1b(operation.providerCgroup, 4096);
  serializer.text1b(operation.workerCgroup, 4096);
  for (String& argument : operation.providerArguments) serializer.text1b(argument, 4096);
}

static inline bool mothershipVDCRead(const String& path, String& output, uint64_t maximum = 65536)
{
  output.clear();
  String ownedPath = path;
  int fd = ::open(ownedPath.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  char buffer[4096];
  bool okay = true;
  while (true)
  {
    ssize_t count = ::read(fd, buffer, sizeof(buffer));
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) { okay = false; break; }
    if (count == 0) break;
    if (output.size() + uint64_t(count) > maximum) { okay = false; break; }
    output.append(buffer, uint64_t(count));
  }
  ::close(fd);
  return okay;
}

static inline bool mothershipVDCParseUnsigned(const char *begin, const char *end, uint64_t& value)
{
  value = 0;
  if (begin == end) return false;
  for (const char *cursor = begin; cursor != end; ++cursor)
  {
    if (*cursor < '0' || *cursor > '9' || value > (UINT64_MAX - uint64_t(*cursor - '0')) / 10) return false;
    value = value * 10 + uint64_t(*cursor - '0');
  }
  return true;
}

static inline bool mothershipVDCReadNumber(const String& path, uint64_t& value)
{
  String text = {};
  if (mothershipVDCRead(path, text, 64) == false) return false;
  const char *begin = reinterpret_cast<const char *>(text.data());
  const char *end = begin + text.size();
  if (end != begin && end[-1] == '\n') --end;
  return mothershipVDCParseUnsigned(begin, end, value);
}

// stat's comm may itself contain spaces and closing parentheses. Field 22
// follows the final closing parenthesis, not a whitespace tokenized command.
static inline bool mothershipVDCParseStat(const String& text, uint64_t expectedPID, uint64_t& startTime, char& state)
{
  if (text.empty()) return false;
  const char *begin = reinterpret_cast<const char *>(text.data());
  const char *end = begin + text.size();
  const char *space = static_cast<const char *>(std::memchr(begin, ' ', text.size()));
  uint64_t actualPID = 0;
  if (space == nullptr || mothershipVDCParseUnsigned(begin, space, actualPID) == false || actualPID != expectedPID) return false;
  const char *close = end;
  while (close != begin && close[-1] != ')') --close;
  if (close == begin || end - close < 4 || close[0] != ' ' || close[2] != ' ') return false;
  state = close[1];
  const char *cursor = close + 3;
  for (unsigned field = 4; field <= 22; ++field)
  {
    const char *terminal = cursor;
    while (terminal != end && *terminal != ' ' && *terminal != '\n') ++terminal;
    if (field == 22) return mothershipVDCParseUnsigned(cursor, terminal, startTime) && startTime != 0;
    if (terminal == end || *terminal != ' ') return false;
    cursor = terminal + 1;
  }
  return false;
}

static inline bool mothershipVDCReadProcess(uint64_t pid, MothershipVDCProcessIdentity& identity, char *state = nullptr)
{
  if (pid < 2 || pid > INT_MAX) return false;
  String path = {}, text = {};
  path.snprintf<"/proc/{itoa}/stat"_ctv>(pid);
  char processState = 0;
  MothershipVDCProcessIdentity observed = {};
  observed.pid = pid;
  if (mothershipVDCRead(path, text, 4096) == false ||
      mothershipVDCParseStat(text, pid, observed.startTime, processState) == false || processState == 'Z') return false;
  struct stat metadata = {};
  path.snprintf<"/proc/{itoa}/ns/mnt"_ctv>(pid);
  if (::stat(path.c_str(), &metadata) != 0) return false;
  observed.mountNamespace = metadata.st_ino;
  path.snprintf<"/proc/{itoa}/ns/net"_ctv>(pid);
  if (::stat(path.c_str(), &metadata) != 0) return false;
  observed.networkNamespace = metadata.st_ino;
  path.snprintf<"/proc/{itoa}/ns/cgroup"_ctv>(pid);
  if (::stat(path.c_str(), &metadata) != 0) return false;
  observed.cgroupNamespace = metadata.st_ino;
  // Detect an exit/PID reuse while reading the namespace identities.
  path.snprintf<"/proc/{itoa}/stat"_ctv>(pid);
  uint64_t secondStart = 0;
  if (mothershipVDCRead(path, text, 4096) == false ||
      mothershipVDCParseStat(text, pid, secondStart, processState) == false ||
      secondStart != observed.startTime || processState == 'Z') return false;
  identity = observed;
  if (state) *state = processState;
  return true;
}

static inline bool mothershipVDCSameProcess(const MothershipVDCProcessIdentity& a, const MothershipVDCProcessIdentity& b)
{
  return a.pid > 1 && a.pid == b.pid && a.startTime != 0 && a.startTime == b.startTime &&
         a.mountNamespace == b.mountNamespace && a.networkNamespace == b.networkNamespace && a.cgroupNamespace == b.cgroupNamespace;
}

static inline bool mothershipVDCProcessMatches(const MothershipVDCProcessIdentity& expected, char *state = nullptr)
{
  MothershipVDCProcessIdentity actual = {};
  return mothershipVDCReadProcess(expected.pid, actual, state) && mothershipVDCSameProcess(expected, actual);
}

static inline bool mothershipVDCSignal(const MothershipVDCProcessIdentity& expected, int signal)
{
  int fd = int(::syscall(SYS_pidfd_open, pid_t(expected.pid), 0));
  if (fd < 0) return false;
  bool okay = mothershipVDCProcessMatches(expected) && ::syscall(SYS_pidfd_send_signal, fd, signal, nullptr, 0) == 0;
  ::close(fd);
  return okay;
}

static inline bool mothershipVDCDurableWrite(const String& directory, const char *name, const String& text, String *failure)
{
  String path = {};
  mothershipVirtualDatacenterPath(directory, name, path);
  if (mothershipVirtualDatacenterWriteFile(path, text, 0600, failure) == false) return false;
  String ownedDirectory = directory;
  int fd = ::open(ownedDirectory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  bool okay = fd >= 0 && ::fsync(fd) == 0;
  if (fd >= 0) ::close(fd);
  if (okay == false && failure) failure->assign("failed to sync provider recovery directory"_ctv);
  return okay;
}

static inline bool mothershipVDCWriteRecovery(const String& directory, MothershipVDCBundleRecovery& operation, String *failure)
{
  String serialized = {};
  BitseryEngine::serialize(serialized, operation);
  return mothershipVDCDurableWrite(directory, "operation", serialized, failure);
}

static inline bool mothershipVDCReadRecovery(const String& directory, MothershipVDCBundleRecovery& operation)
{
  String path = {}, serialized = {};
  mothershipVirtualDatacenterPath(directory, "operation", path);
  return mothershipVDCRead(path, serialized) && BitseryEngine::deserializeSafe(serialized, operation) &&
         operation.version == 2 && operation.clusterUUID != 0 && operation.operationID != 0 &&
         operation.runtimeIdentity > 1 && operation.machineIndex > 0 &&
         operation.phase <= MothershipVDCRecoveryPhase::complete;
}

// Prepare through the boot-state owner before stopping anything. The caller
// installs these exact bytes only after the selected Brain is stopped.
static inline bool mothershipVDCPrepareSupersessionBoot(const String& original,
    const MothershipVDCBundleRecovery& operation, String& successor, String *failure)
{
  ProdigyPersistentBootState boot = {};
  if (operation.machineIndex != 1 || operation.operationID == 0 || operation.clusterUUID == 0 ||
      prodigyIsSHA256HexDigest(operation.expectedIncompleteWorkerBundle) == false ||
      prodigyIsSHA256HexDigest(operation.successorBundle) == false ||
      operation.expectedIncompleteWorkerBundle.equals(operation.successorBundle) ||
      parseProdigyPersistentBootStateJSON(original, boot, failure) == false ||
      boot.bootstrapConfig.nodeRole != ProdigyBootstrapNodeRole::brain ||
      boot.bootstrapConfig.controlSocketPath.empty() ||
      boot.bootstrapConfig.controlSocketPath.equals(operation.providerArguments[11]) == false)
  {
    if (failure) failure->assign("bootstrap supersession does not target the retained Brain boot identity"_ctv);
    return false;
  }
  auto& receipt = boot.bootstrapBundleSupersession;
  receipt.operationID = operation.operationID;
  receipt.clusterUUID = operation.clusterUUID;
  receipt.expectedIncompleteWorkerBundleSHA256 = operation.expectedIncompleteWorkerBundle;
  receipt.successorBundleSHA256 = operation.successorBundle;
  receipt.targetControlSocketPath = boot.bootstrapConfig.controlSocketPath;
  renderProdigyPersistentBootStateJSON(boot, successor);
  return true;
}

static inline bool mothershipVDCReadProcessFile(uint64_t pid, const char *name, String& result)
{
  String path = {};
  path.snprintf<"/proc/{itoa}/{}"_ctv>(pid, String(name));
  return mothershipVDCRead(path, result);
}

static inline bool mothershipVDCReadArguments(uint64_t pid, Vector<String>& arguments)
{
  String text = {};
  if (mothershipVDCReadProcessFile(pid, "cmdline", text) == false || text.empty() || text[text.size() - 1] != 0) return false;
  arguments.clear();
  uint64_t start = 0;
  for (uint64_t i = 0; i < text.size(); ++i)
  {
    if (text[i] != 0) continue;
    arguments.emplace_back();
    arguments.back().assign(text.data() + start, i - start);
    start = i + 1;
  }
  return true;
}

static inline bool mothershipVDCProviderArguments(const Vector<String>& arguments, const String& workspace,
                                                 uint64_t runtimeIdentity, String (&original)[12])
{
  if (arguments.size() != 15 && arguments.size() != 17) return false;
  if (arguments[0].equals("bash"_ctv) == false && arguments[0].equals("/bin/bash"_ctv) == false) return false;
  constexpr char prefix[] = "/proc/self/fd/";
  uint64_t descriptor = 0;
  if (arguments[1].size() <= sizeof(prefix) - 1 ||
      std::memcmp(arguments[1].data(), prefix, sizeof(prefix) - 1) != 0 ||
      mothershipVDCParseUnsigned(reinterpret_cast<const char *>(arguments[1].data()) + sizeof(prefix) - 1,
                                reinterpret_cast<const char *>(arguments[1].data()) + arguments[1].size(), descriptor) == false) return false;
  uint64_t offset = 3;
  if (arguments[2].equals("--serve-adopt"_ctv))
  {
    uint64_t parsed = 0;
    if (arguments.size() != 17 || mothershipVDCParseUnsigned(reinterpret_cast<const char *>(arguments[3].data()), reinterpret_cast<const char *>(arguments[3].data()) + arguments[3].size(), parsed) == false ||
        parsed != runtimeIdentity) return false;
    offset = 5;
  }
  else if (arguments[2].equals("--serve"_ctv) == false || arguments.size() != 15) return false;
  if (arguments[offset].equals(workspace) == false) return false;
  for (uint64_t i = 0; i < 12; ++i) original[i] = arguments[offset + i];
  return true;
}
