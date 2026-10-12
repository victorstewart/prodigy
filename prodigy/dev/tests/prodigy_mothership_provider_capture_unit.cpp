#include <services/debug.h>
#include <chrono>
#include <cstring>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define main nametag_mothership_main_disabled
#include <prodigy/mothership/mothership.cpp>
#undef main

static bool writeAll(int fd, const uint8_t *bytes, size_t size)
{
  size_t offset = 0;
  while (offset != size)
  {
    const ssize_t written = ::write(fd, bytes + offset, size - offset);
    if (written > 0) { offset += size_t(written); continue; }
    if (written < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

static bool recordConcurrentFaultInterval(const MothershipTestClusterCrashFault& request, String *failure)
{
  String path = request.cluster.test.workspaceRoot;
  path.append("/interval"_ctv);
  FILE *file = std::fopen(path.c_str(), "w");
  if (file == nullptr)
  {
    if (failure) failure->assign("cannot record concurrent fault interval"_ctv);
    return false;
  }
  const auto nowMs = [] {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
  };
  const long long started = nowMs();
  std::fprintf(file, "%lld ", started);
  std::fflush(file);
  ::usleep(150'000);
  std::fprintf(file, "%lld\n", static_cast<long long>(nowMs()));
  std::fclose(file);
  if (failure) failure->clear();
  return true;
}

static bool recordConcurrentFaultIntervalWithSecondFailure(
    const MothershipTestClusterCrashFault& request,
    String *failure)
{
  if (recordConcurrentFaultInterval(request, failure) == false) return false;
  if (request.cluster.clusterUUID != 2) return true;
  if (failure) failure->assign("injected runner failure"_ctv);
  return false;
}

static bool readInterval(const String& workspace, long long& started, long long& ended)
{
  String path = workspace;
  path.append("/interval"_ctv);
  FILE *file = std::fopen(path.c_str(), "r");
  if (file == nullptr) return false;
  const bool read = std::fscanf(file, "%lld %lld", &started, &ended) == 2;
  std::fclose(file);
  return read;
}

int main()
{
  int failed = 0;
  auto expect = [&](bool condition, const char *name) {
    basics_log("%s: %s\n", condition ? "PASS" : "FAIL", name);
    failed += condition ? 0 : 1;
  };

  int pipeFD[2] = {-1, -1};
  expect(::pipe2(pipeFD, O_CLOEXEC) == 0, "create overflow capture pipe");
  pid_t writer = failed ? -1 : ::fork();
  if (writer == 0)
  {
    (void)::setpgid(0, 0);
    ::close(pipeFD[0]);
    uint8_t bytes[4096]; std::memset(bytes, 'x', sizeof(bytes));
    bool wrote = true;
    for (uint32_t count = 0; count != 17; ++count)
      wrote = writeAll(pipeFD[1], bytes, sizeof(bytes)) && wrote;
    _exit(wrote ? 0 : 1); // 69,632 bytes: exceeds the legacy 64 KiB cap.
  }
  expect(writer > 0, "fork overflow writer");
  if (writer > 0)
  {
    ::close(pipeFD[1]);
    String output = {}, failure = {}; int status = 0;
    const bool captured = mothershipCaptureVirtualDatacenterProviderOutput(
        pipeFD[0], writer, output, &failure, 64 * 1024, 1000, true, status);
    expect(!captured, "real post-wait overflow is rejected");
    expect(output.size() == 64 * 1024 && output.data()[0] == 'x' && output.data()[output.size() - 1] == 'x',
           "real post-wait overflow retains 64 KiB prefix");
    expect(failure.equals("virtual datacenter provider capture failed; retained output prefix is bounded"_ctv),
           "overflow reports retained-prefix capture failure");
  }

  expect(::prctl(PR_SET_CHILD_SUBREAPER, 1) == 0,
         "become a subreaper for deterministic descendant cleanup");
  pipeFD[0] = pipeFD[1] = -1;
  expect(::pipe2(pipeFD, O_CLOEXEC) == 0, "create descendant timeout pipe");
  pid_t groupLeader = failed ? -1 : ::fork();
  if (groupLeader == 0)
  {
    (void)::setpgid(0, 0);
    ::close(pipeFD[0]);
    if (::fork() == 0) { for (;;) ::pause(); }
    _exit(0); // Descendant retains the write end after the direct child exits.
  }
  expect(groupLeader > 0, "fork process-group leader");
  if (groupLeader > 0)
  {
    ::close(pipeFD[1]);
    String output = {}, failure = {}; int status = 0;
    const auto started = std::chrono::steady_clock::now();
    const bool captured = mothershipCaptureVirtualDatacenterProviderOutput(
        pipeFD[0], groupLeader, output, &failure, 64 * 1024, 100, true, status);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    expect(!captured && elapsed < 1000, "timeout bounds a descendant-held output pipe");
    int descendantStatus = 0;
    const pid_t descendant = ::waitpid(-1, &descendantStatus, 0);
    expect(descendant > 0 && WIFSIGNALED(descendantStatus) && WTERMSIG(descendantStatus) == SIGKILL,
           "timeout kills and reaps the descendant process group after direct child exit");
  }

  char concurrentRoot[] = "./mothership-concurrent-fault-unit.XXXXXX";
  char *createdConcurrentRoot = ::mkdtemp(concurrentRoot);
  expect(createdConcurrentRoot != nullptr, "create concurrent fault fixture root");
  if (createdConcurrentRoot != nullptr)
  {
    String firstWorkspace = {};
    String secondWorkspace = {};
    firstWorkspace.snprintf<"{}/first"_ctv>(String(concurrentRoot));
    secondWorkspace.snprintf<"{}/second"_ctv>(String(concurrentRoot));
    expect(::mkdir(firstWorkspace.c_str(), 0700) == 0 && ::mkdir(secondWorkspace.c_str(), 0700) == 0,
           "create distinct concurrent fault workspaces");

    MothershipProdigyCluster firstCluster = {};
    firstCluster.clusterUUID = 1;
    firstCluster.deploymentMode = MothershipClusterDeploymentMode::test;
    firstCluster.test.workspaceRoot = firstWorkspace;
    firstCluster.test.machineCount = 3;
    MothershipProdigyCluster secondCluster = firstCluster;
    secondCluster.clusterUUID = 2;
    secondCluster.test.workspaceRoot = secondWorkspace;
    MothershipTestClusterCrashFault first = {};
    MothershipTestClusterCrashFault second = {};
    String failure = {};
    expect(mothershipBuildConcurrentTestClusterCrashFaults(
               firstCluster, "first"_ctv, "1"_ctv,
               secondCluster, "second"_ctv, "3"_ctv,
               12000, first, second, &failure),
           "validate two distinct bounded test-cluster crash faults");
    expect(first.machineIndex.equals("1"_ctv) && second.machineIndex.equals("3"_ctv) &&
               first.durationMs == 12000 && second.durationMs == 12000,
           "normalize concurrent crash fault targets");

    MothershipProdigyCluster invalid = secondCluster;
    invalid.deploymentMode = MothershipClusterDeploymentMode::remote;
    expect(!mothershipBuildConcurrentTestClusterCrashFaults(
               firstCluster, "first"_ctv, "1"_ctv, invalid, "second"_ctv, "3"_ctv,
               12000, first, second, &failure),
           "reject non-test concurrent crash target");
    invalid = secondCluster;
    invalid.clusterUUID = firstCluster.clusterUUID;
    expect(!mothershipBuildConcurrentTestClusterCrashFaults(
               firstCluster, "first"_ctv, "1"_ctv, invalid, "second"_ctv, "3"_ctv,
               12000, first, second, &failure),
           "reject duplicate concurrent crash cluster UUID");
    invalid = secondCluster;
    invalid.test.workspaceRoot = firstWorkspace;
    expect(!mothershipBuildConcurrentTestClusterCrashFaults(
               firstCluster, "first"_ctv, "1"_ctv, invalid, "second"_ctv, "3"_ctv,
               12000, first, second, &failure),
           "reject duplicate concurrent crash workspace");
    expect(!mothershipBuildConcurrentTestClusterCrashFaults(
               firstCluster, "first"_ctv, "0"_ctv, secondCluster, "second"_ctv, "3"_ctv,
               12000, first, second, &failure) &&
               !mothershipBuildConcurrentTestClusterCrashFaults(
               firstCluster, "first"_ctv, "1"_ctv, secondCluster, "second"_ctv, "4"_ctv,
               12000, first, second, &failure),
           "reject out-of-range concurrent crash machine index");
    expect(!mothershipBuildConcurrentTestClusterCrashFaults(
               firstCluster, "first"_ctv, "1"_ctv, secondCluster, "second"_ctv, "3"_ctv,
               0, first, second, &failure),
           "reject zero concurrent crash duration");

    expect(mothershipBuildConcurrentTestClusterCrashFaults(
               firstCluster, "first"_ctv, "1"_ctv,
               secondCluster, "second"_ctv, "3"_ctv,
               12000, first, second, &failure) &&
               mothershipRunConcurrentTestClusterCrashFaults(
                   first, second, &failure, recordConcurrentFaultInterval),
           "launch and reap both concurrent crash provider workers");
    long long firstStarted = 0, firstEnded = 0, secondStarted = 0, secondEnded = 0;
    expect(readInterval(firstWorkspace, firstStarted, firstEnded) &&
               readInterval(secondWorkspace, secondStarted, secondEnded) &&
               firstStarted < secondEnded && secondStarted < firstEnded,
           "concurrent crash provider worker intervals overlap");

    const bool injectedFailureRejected = !mothershipRunConcurrentTestClusterCrashFaults(
        first, second, &failure, recordConcurrentFaultIntervalWithSecondFailure);
    expect(injectedFailureRejected &&
               failure.equals("test-cluster fault failed for identity=second: injected runner failure"_ctv),
           "reap both workers and attribute one concurrent crash failure");
    errno = 0;
    expect(::waitpid(-1, nullptr, WNOHANG) == -1 && errno == ECHILD,
           "concurrent crash helper leaves no child process");
    std::error_code cleanupError;
    std::filesystem::remove_all(concurrentRoot, cleanupError);
    expect(cleanupError.value() == 0, "remove concurrent fault fixture root");
  }
  return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
