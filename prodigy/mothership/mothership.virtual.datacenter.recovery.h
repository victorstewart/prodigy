#pragma once

#include <prodigy/mothership/mothership.virtual.datacenter.h>
#include <sys/file.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>
#include <sched.h>
#include <climits>

// Workers retain the live Brain as their plan owner. A sole Brain requires
// the authenticated checkpoint path plus an exact incomplete-update receipt.
static inline bool mothershipVDCRecoveryTargetIsSupported(uint32_t machineIndex, uint32_t brainCount,
    bool checkpointedSupersession = false, bool testOnlyFollowerReplacement = false)
{
  return machineIndex > brainCount || (checkpointedSupersession && machineIndex == 1 && brainCount == 1) ||
         (testOnlyFollowerReplacement && brainCount == 3 && machineIndex >= 1 && machineIndex <= brainCount);
}

// The provider keeps resource plumbing. Mothership owns the exact process
// identities, approved artifact, durable intent and ordering of recovery.
enum class MothershipVDCRecoveryPhase : uint8_t {
  accepted, frozen, ready, committed, workerStopped, workerKilled,
  rootInstalled, launchRequested, replaced, complete
};

// Command-scoped fault injection for the disposable follower-recovery
// qualification.  It is deliberately outside MothershipVDCBundleRecovery, so
// a recovery journal remains an ordinary durable operation on retry.
enum class MothershipVDCTestRecoveryFaultPhase : uint8_t {
  none, frozen, rootInstalled, workerReplaced
};

static inline bool mothershipVDCTestParseRecoveryFaultPhase(const String& text,
                                                            MothershipVDCTestRecoveryFaultPhase& phase)
{
  phase = MothershipVDCTestRecoveryFaultPhase::none;
  if (text.empty()) return true;
  if (text.equals("frozen"_ctv)) phase = MothershipVDCTestRecoveryFaultPhase::frozen;
  else if (text.equals("rootInstalled"_ctv)) phase = MothershipVDCTestRecoveryFaultPhase::rootInstalled;
  else if (text.equals("workerReplaced"_ctv)) phase = MothershipVDCTestRecoveryFaultPhase::workerReplaced;
  else return false;
  return true;
}

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

// Kernel identities are meaningful only inside the retained worker's recorded
// network namespace. The existing Switchboard owner validates and pins them;
// this record binds the lifecycle transition to those exact resources.
class MothershipVDCRetainedTCX {
public:
  uint32_t ifindex = 0, attachType = 0, programID = 0, linkID = 0;
  uint32_t wormholeFlowMapID = 0, wormholePendingFlowMapID = 0;
  uint8_t programTag[8] = {};
};

template <typename S>
static void serialize(S&& serializer, MothershipVDCRetainedTCX& link)
{
  serializer.value4b(link.ifindex);
  serializer.value4b(link.attachType);
  serializer.value4b(link.programID);
  serializer.value4b(link.linkID);
  serializer.value4b(link.wormholeFlowMapID);
  serializer.value4b(link.wormholePendingFlowMapID);
  for (uint8_t& byte : link.programTag) serializer.value1b(byte);
}

class MothershipVDCBundleRecovery {
public:
  // Version three binds the test-only three-Brain follower preflight to the
  // same retained provider transaction.  It is deliberately not a production
  // rollout or authority-admission record.
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
  bool testOnlyFollowerReplacement = false;
  String selectedMachineUUID, masterMachineUUID, witnessMachineUUID;
  String preflightReportSHA256;
  MothershipVDCProcessIdentity commissionedBrains[3];
  MothershipVDCRetainedTCX retainedTCX[2];
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
  if (operation.version == 3 || operation.version == 4)
  {
    serializer.value1b(operation.testOnlyFollowerReplacement);
    serializer.text1b(operation.selectedMachineUUID, 64);
    serializer.text1b(operation.masterMachineUUID, 64);
    serializer.text1b(operation.witnessMachineUUID, 64);
    serializer.text1b(operation.preflightReportSHA256, 64);
    for (MothershipVDCProcessIdentity& brain : operation.commissionedBrains) serializer.object(brain);
  }
  if (operation.version == 4)
    for (MothershipVDCRetainedTCX& link : operation.retainedTCX) serializer.object(link);
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

static inline bool mothershipVDCWaitForStoppedState(
    const MothershipVDCProcessIdentity& process, bool stopped, unsigned attempts = 200)
{
  for (unsigned attempt = 0; attempt < attempts; ++attempt)
  {
    char state = 0;
    if (mothershipVDCProcessMatches(process, &state) == false) return false;
    const bool isStopped = state == 'T' || state == 't';
    if (isStopped == stopped) return true;
    ::usleep(10000);
  }
  return false;
}

// The capture owner arms this independent child before SIGSTOP.  A clean
// parent sends a disarm byte only after it has sent SIGCONT and observed the
// exact process running.  Parent death, channel loss, or a bounded timeout
// makes the child resume the exact pidfd-bound identity instead.  A timeout is
// deliberately reported as capture failure: it may have resumed mid-copy.
class MothershipVDCProcessResumeGuard {
public:
  MothershipVDCProcessIdentity process = {};
  int watchdogSocket = -1;
  pid_t watchdogPID = -1;
  int watchdogTimeoutMs = 120'000;
  bool armed = false;

  explicit MothershipVDCProcessResumeGuard(
      const MothershipVDCProcessIdentity& identity, int timeoutMs = 120'000)
      : process(identity), watchdogTimeoutMs(timeoutMs) {}

  MothershipVDCProcessResumeGuard(const MothershipVDCProcessResumeGuard&) = delete;
  MothershipVDCProcessResumeGuard& operator=(const MothershipVDCProcessResumeGuard&) = delete;

  static void closeWatchdogDescriptors(int keep)
  {
#ifdef SYS_close_range
    if (keep > 3) (void)::syscall(SYS_close_range, 3u, unsigned(keep - 1), 0u);
    (void)::syscall(SYS_close_range, unsigned(keep + 1), ~0u, 0u);
#else
    long maximum = ::sysconf(_SC_OPEN_MAX);
    if (maximum < 0 || maximum > 65536) maximum = 65536;
    for (int descriptor = 3; descriptor < maximum; ++descriptor)
      if (descriptor != keep) (void)::close(descriptor);
#endif
    (void)::close(STDIN_FILENO);
    (void)::close(STDOUT_FILENO);
    (void)::close(STDERR_FILENO);
  }

  static void runWatchdog(
      int descriptor, MothershipVDCProcessIdentity identity, int timeoutMs)
  {
    (void)::setsid();
    closeWatchdogDescriptors(descriptor);
    struct pollfd event = {};
    event.fd = descriptor;
    event.events = POLLIN | POLLHUP;
    int result = 0;
    do { result = ::poll(&event, 1, timeoutMs); } while (result < 0 && errno == EINTR);
    char command = 0;
    ssize_t received = -1;
    if (result > 0 && (event.revents & POLLIN))
      do { received = ::recv(descriptor, &command, 1, 0); } while (received < 0 && errno == EINTR);
    if (received == 1 && command == 'D')
    {
      (void)::close(descriptor);
      _exit(0);
    }
    const bool resumed = mothershipVDCSignal(identity, SIGCONT) &&
                         mothershipVDCWaitForStoppedState(identity, false);
    (void)::close(descriptor);
    _exit(resumed ? 86 : 87);
  }

  bool arm(String *failure = nullptr)
  {
    if (armed || watchdogSocket >= 0 || watchdogPID > 0 ||
        watchdogTimeoutMs <= 0 || watchdogTimeoutMs > 300'000 ||
        mothershipVDCProcessMatches(process) == false)
    {
      if (failure) failure->assign("cannot arm exact-process capture resume guard"_ctv);
      return false;
    }
    int sockets[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0)
    {
      if (failure) failure->assign("cannot create capture resume watchdog"_ctv);
      return false;
    }
    pid_t child = ::fork();
    if (child == 0)
    {
      (void)::close(sockets[0]);
      runWatchdog(sockets[1], process, watchdogTimeoutMs);
    }
    (void)::close(sockets[1]);
    if (child < 0)
    {
      (void)::close(sockets[0]);
      if (failure) failure->assign("cannot fork capture resume watchdog"_ctv);
      return false;
    }
    watchdogSocket = sockets[0];
    watchdogPID = child;
    armed = true;
    if (failure) failure->clear();
    return true;
  }

  bool freeze(String *failure = nullptr)
  {
    if (!arm(failure)) return false;
    if (!mothershipVDCSignal(process, SIGSTOP) ||
        !mothershipVDCWaitForStoppedState(process, true))
    {
      if (failure) failure->assign("cannot freeze exact Brain for private state capture"_ctv);
      (void)resume(nullptr);
      return false;
    }
    return true;
  }

  bool resume(String *failure = nullptr)
  {
    if (!armed)
    {
      const bool running = mothershipVDCWaitForStoppedState(process, false);
      if (!running && failure) failure->assign("capture process is not observably running"_ctv);
      return running;
    }
    bool running = mothershipVDCSignal(process, SIGCONT) &&
                   mothershipVDCWaitForStoppedState(process, false);
    if (running)
    {
      const char command = 'D';
      running = ::send(watchdogSocket, &command, 1, MSG_NOSIGNAL) == 1;
    }
    (void)::close(watchdogSocket);
    watchdogSocket = -1;
    int status = 0;
    pid_t waited = -1;
    do { waited = ::waitpid(watchdogPID, &status, 0); } while (waited < 0 && errno == EINTR);
    const bool watchdogDisarmed = waited == watchdogPID && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    watchdogPID = -1;
    armed = false;
    // If the watchdog intervened, verify safety but reject this capture: its
    // consistency boundary may have elapsed while the parent was still copying.
    const bool safelyRunning = mothershipVDCWaitForStoppedState(process, false);
    if (!running || !watchdogDisarmed || !safelyRunning)
    {
      if (failure)
      {
        if (!safelyRunning)
          failure->assign("exact Brain could not be verified resumed after capture"_ctv);
        else
          failure->assign("capture resume watchdog intervened before normal completion"_ctv);
      }
      return false;
    }
    if (failure) failure->clear();
    return true;
  }

  ~MothershipVDCProcessResumeGuard()
  {
    if (armed) (void)resume(nullptr);
  }
};

static inline bool mothershipVDCPrivateDirectory(const String& path)
{
  if (path.empty() || path[0] != '/') return false;
  String owned = path;
  struct stat before = {}, opened = {};
  if (::lstat(owned.c_str(), &before) != 0 || !S_ISDIR(before.st_mode) ||
      before.st_uid != ::geteuid() || (before.st_mode & 0777) != 0700) return false;
  int descriptor = ::open(owned.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  const bool valid = descriptor >= 0 && ::fstat(descriptor, &opened) == 0 &&
      opened.st_dev == before.st_dev && opened.st_ino == before.st_ino &&
      S_ISDIR(opened.st_mode) && opened.st_uid == ::geteuid() &&
      (opened.st_mode & 0777) == 0700;
  if (descriptor >= 0) ::close(descriptor);
  return valid;
}

// Copies only directories and regular files into a new private tree.  This is
// the shared private-state primitive used by both the test-VDC recovery and
// the remote Brain diagnostic capture; neither caller opens the live DB.
// Capture only an unambiguous built-in state location in the selected
// process mount. Caller input never chooses a database pathname.
static inline bool mothershipVDCBrainCaptureStatePaths(
    const String& processRoot, String& primary, String& secrets, String *failure = nullptr)
{
  uint32_t matches = 0;
  for (const char *canonical : {"/containers/prodigy.state", defaultProdigyPersistentStateDBPath()})
  {
    String candidate = processRoot;
    candidate.append(String(canonical));
    String candidateSecrets = candidate;
    candidateSecrets.append(".secrets"_ctv);
    struct stat state = {}, secretState = {};
    const bool stateExists = ::lstat(candidate.c_str(), &state) == 0;
    const bool secretsExist = ::lstat(candidateSecrets.c_str(), &secretState) == 0;
    if (!stateExists && !secretsExist) continue;
    if (!stateExists || !secretsExist || !S_ISDIR(state.st_mode) || !S_ISDIR(secretState.st_mode))
    {
      if (failure) failure->assign("canonical Brain state pair is incomplete or unsafe"_ctv);
      return false;
    }
    primary = candidate;
    secrets = candidateSecrets;
    ++matches;
  }
  if (matches != 1)
  {
    if (failure) failure->assign("Brain state path is absent or ambiguous"_ctv);
    return false;
  }
  return true;
}

static inline bool mothershipVDCCopyPrivateStateTree(
    const String& source, const String& destination, String *failure = nullptr)
{
  bool destinationCreated = false;
  auto reject = [&](const char *message) {
    if (destinationCreated)
    {
      std::error_code cleanupError;
      std::filesystem::remove_all(const_cast<String&>(destination).c_str(), cleanupError);
    }
    if (failure) failure->assign(message);
    return false;
  };
  String ownedSource = source, ownedDestination = destination;
  struct stat sourceState = {};
  if (::lstat(ownedSource.c_str(), &sourceState) != 0 || !S_ISDIR(sourceState.st_mode) ||
      S_ISLNK(sourceState.st_mode))
    return reject("private state source or destination is unsafe");
  if (::mkdir(ownedDestination.c_str(), 0700) != 0)
    return reject("private state destination already exists or is unavailable");
  destinationCreated = true;
  std::error_code error = {};
  for (std::filesystem::recursive_directory_iterator it(ownedSource.c_str(), error), end;
       !error && it != end; it.increment(error))
  {
    const auto relative = it->path().lexically_relative(ownedSource.c_str());
    const auto target = std::filesystem::path(ownedDestination.c_str()) / relative;
    const auto status = it->symlink_status(error);
    if (error || std::filesystem::is_symlink(status))
      return reject("private state tree contains a symlink");
    if (std::filesystem::is_directory(status))
    {
      if (::mkdir(target.c_str(), 0700) != 0)
        return reject("private state directory copy failed");
    }
    else if (std::filesystem::is_regular_file(status))
    {
      if (!std::filesystem::copy_file(it->path(), target,
              std::filesystem::copy_options::none, error) || error ||
          ::chmod(target.c_str(), 0600) != 0)
        return reject("private state file copy failed");
    }
    else return reject("private state tree contains an unsupported entry");
  }
  if (error) return reject("private state tree iteration failed");
  if (failure) failure->clear();
  return true;
}

static inline bool mothershipVDCDurableWrite(
    const String& directory, const char *name, const String& text, String *failure);

class MothershipVDCBrainStateCaptureReceipt {
public:
  uint8_t version = 1;
  uint128_t clusterUUID = 0;
  uint128_t machineUUID = 0;
  MothershipVDCProcessIdentity process = {};
  bool resumed = false;
  bool captureComplete = false;
};

template <typename S>
static void serialize(S&& serializer, MothershipVDCBrainStateCaptureReceipt& receipt)
{
  serializer.value1b(receipt.version);
  serializer.value16b(receipt.clusterUUID);
  serializer.value16b(receipt.machineUUID);
  serializer.object(receipt.process);
  serializer.value1b(receipt.resumed);
  serializer.value1b(receipt.captureComplete);
}

static inline bool mothershipVDCBrainStateCaptureReceiptValid(
    const MothershipVDCBrainStateCaptureReceipt& receipt)
{
  return receipt.version == 1 && receipt.clusterUUID != 0 &&
      receipt.machineUUID != 0 && receipt.process.pid > 1 &&
      receipt.process.startTime != 0 && receipt.process.mountNamespace != 0 &&
      receipt.process.networkNamespace != 0 && receipt.process.cgroupNamespace != 0 &&
      (!receipt.captureComplete || receipt.resumed);
}

static inline bool mothershipVDCWriteBrainStateCaptureReceipt(
    const String& directory, const MothershipVDCBrainStateCaptureReceipt& receipt,
    String *failure = nullptr)
{
  if (!mothershipVDCPrivateDirectory(directory) ||
      !mothershipVDCBrainStateCaptureReceiptValid(receipt))
  {
    if (failure) failure->assign("invalid private Brain capture receipt"_ctv);
    return false;
  }
  String bytes = {};
  auto copy = receipt;
  BitseryEngine::serialize(bytes, copy);
  return mothershipVDCDurableWrite(directory, "brain-capture.receipt", bytes, failure);
}

static inline bool mothershipVDCReadBrainStateCaptureReceipt(
    const String& directory, MothershipVDCBrainStateCaptureReceipt& receipt)
{
  receipt = {};
  if (!mothershipVDCPrivateDirectory(directory)) return false;
  String path = {}, bytes = {};
  mothershipVirtualDatacenterPath(directory, "brain-capture.receipt", path);
  return mothershipVDCRead(path, bytes, 256) &&
      BitseryEngine::deserializeSafe(bytes, receipt) &&
      mothershipVDCBrainStateCaptureReceiptValid(receipt);
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
  // Clear optional versioned tails before decoding an older record into a
  // reused object; neither preflight nor retained-link identities may leak in.
  operation = {};
  String path = {}, serialized = {};
  mothershipVirtualDatacenterPath(directory, "operation", path);
  return mothershipVDCRead(path, serialized) && BitseryEngine::deserializeSafe(serialized, operation) &&
         (operation.version == 2 || operation.version == 3 || operation.version == 4) && operation.clusterUUID != 0 && operation.operationID != 0 &&
         operation.runtimeIdentity > 1 && operation.machineIndex > 0 &&
         operation.phase <= MothershipVDCRecoveryPhase::complete;
}

static inline bool mothershipVDCTestFollowerRecoveryMatches(const MothershipVDCBundleRecovery& operation,
                                                            uint128_t clusterUUID, uint32_t machineIndex,
                                                            const String& sourceBundle, const String& successorBundle)
{
  if ((operation.version != 3 && operation.version != 4) || operation.testOnlyFollowerReplacement == false || operation.clusterUUID != clusterUUID ||
      operation.machineIndex != machineIndex || operation.expectedOldBundle.equals(sourceBundle) == false ||
      operation.successorBundle.equals(successorBundle) == false || operation.selectedMachineUUID.empty() ||
      operation.masterMachineUUID.empty() || operation.witnessMachineUUID.empty() || operation.preflightReportSHA256.empty() ||
      operation.selectedMachineUUID.equals(operation.masterMachineUUID) ||
      operation.selectedMachineUUID.equals(operation.witnessMachineUUID) ||
      operation.masterMachineUUID.equals(operation.witnessMachineUUID)) return false;
  return true;
}

// Prepare through the boot-state owner before stopping anything. The caller
// installs these exact bytes only after the selected Brain is stopped.
static inline bool mothershipVDCPrepareSupersessionBoot(const String& original,
    const MothershipVDCBundleRecovery& operation, String& successor, String *failure,
    const String *localCheckpoint = nullptr)
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
  if (localCheckpoint != nullptr)
  {
    receipt.localContainerCheckpoint = *localCheckpoint;
    if (prodigyComputeSHA256Hex(*localCheckpoint, receipt.localContainerCheckpointSHA256, failure) == false) return false;
  }
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
