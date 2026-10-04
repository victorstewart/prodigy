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
  return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
