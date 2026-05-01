#include <prodigy/prodigy.h>
#include <services/debug.h>
#include <prodigy/neuron/containers.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <sched.h>
#include <sys/capability.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
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

static int firstAllowedCPU(void)
{
   cpu_set_t allowed {};
   CPU_ZERO(&allowed);
   if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0)
   {
      return -1;
   }

   for (int cpu = 0; cpu < CPU_SETSIZE; cpu++)
   {
      if (CPU_ISSET(cpu, &allowed))
      {
         return cpu;
      }
   }

   return -1;
}

static bool effectiveCapabilityEnabled(cap_value_t capability)
{
   cap_t current = cap_get_proc();
   if (current == nullptr)
   {
      return false;
   }

   cap_flag_value_t flag = CAP_CLEAR;
   bool ok = (cap_get_flag(current, capability, CAP_EFFECTIVE, &flag) == 0);
   cap_free(current);
   return ok && flag == CAP_SET;
}

enum class ProbeKind : uint8_t
{
   schedSetAffinity = 0,
   pthreadSetAffinity,
   ptraceTraceMe,
   unshareFiles,
   pidfdOpenSelf
};

struct HelperThreadContext
{
   int blockFD = -1;
   std::atomic<bool> ready {false};
};

static void *waitOnPipeThread(void *opaque)
{
   auto *context = static_cast<HelperThreadContext *>(opaque);
   context->ready.store(true, std::memory_order_release);

   char byte = 0;
   while (read(context->blockFD, &byte, sizeof(byte)) < 0 && errno == EINTR)
   {
   }

   return nullptr;
}

static int runSeccompProbe(bool installFilter, bool sharedCPUMode, ProbeKind probe)
{
   pid_t pid = fork();
   if (pid < 0)
   {
      return 200;
   }

   if (pid == 0)
   {
      Container container {};
      container.plan.uuid = 0xA11F17EULL;
      container.plan.config.cpuMode = sharedCPUMode ? ApplicationCPUMode::shared : ApplicationCPUMode::isolated;

      int cpu = firstAllowedCPU();
      if (cpu < 0)
      {
         _exit(101);
      }

      cpu_set_t singleton {};
      CPU_ZERO(&singleton);
      CPU_SET(cpu, &singleton);

      if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
      {
         _exit(102);
      }

      if (installFilter && ContainerManager::restrictContainerSyscalls(&container) == false)
      {
         _exit(103);
      }

      switch (probe)
      {
         case ProbeKind::schedSetAffinity:
         {
            cpu_set_t verify {};
            CPU_ZERO(&verify);
            if (sched_getaffinity(0, sizeof(verify), &verify) != 0)
            {
               _exit(104);
            }

            errno = 0;
            int rc = sched_setaffinity(0, sizeof(singleton), &singleton);
            if (installFilter && sharedCPUMode)
            {
               _exit((rc == -1 && errno == EPERM) ? 0 : 120);
            }

            _exit(rc == 0 ? 0 : 121);
         }

         case ProbeKind::pthreadSetAffinity:
         {
            cpu_set_t verify {};
            CPU_ZERO(&verify);
            if (sched_getaffinity(0, sizeof(verify), &verify) != 0)
            {
               _exit(105);
            }

            int rc = pthread_setaffinity_np(pthread_self(), sizeof(singleton), &singleton);
            if (installFilter && sharedCPUMode)
            {
               _exit(rc == EPERM ? 0 : 110);
            }

            _exit(rc == 0 ? 0 : 111);
         }

         case ProbeKind::ptraceTraceMe:
         {
            errno = 0;
            long rc = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
            if (installFilter)
            {
               _exit((rc == -1 && errno == EPERM) ? 0 : 130);
            }

            _exit(rc == 0 ? 0 : 131);
         }

         case ProbeKind::unshareFiles:
         {
            errno = 0;
            int rc = unshare(CLONE_FILES);
            if (installFilter)
            {
               _exit((rc == -1 && errno == EPERM) ? 0 : 140);
            }

            _exit(rc == 0 ? 0 : 141);
         }

         case ProbeKind::pidfdOpenSelf:
         {
            errno = 0;
            int fd = int(syscall(SYS_pidfd_open, getpid(), 0));
            if (installFilter)
            {
               if (fd >= 0)
               {
                  close(fd);
               }
               _exit((fd == -1 && errno == EPERM) ? 0 : 150);
            }

            if (fd < 0)
            {
               _exit(151);
            }

            close(fd);
            _exit(0);
         }
      }

      _exit(199);
   }

   int status = 0;
   if (waitpid(pid, &status, 0) != pid)
   {
      return 201;
   }

   if (!WIFEXITED(status))
   {
      return 202;
   }

   return WEXITSTATUS(status);
}

static int runPrebuiltSeccompProbe(bool sharedCPUMode, ProbeKind probe)
{
   int helperPipe[2] = {-1, -1};
   if (pipe2(helperPipe, O_CLOEXEC) != 0)
   {
      return 200;
   }

   HelperThreadContext helperContext {};
   helperContext.blockFD = helperPipe[0];

   pthread_t helperThread {};
   if (pthread_create(&helperThread, nullptr, waitOnPipeThread, &helperContext) != 0)
   {
      close(helperPipe[0]);
      close(helperPipe[1]);
      return 201;
   }

   while (helperContext.ready.load(std::memory_order_acquire) == false)
   {
      sched_yield();
   }

   Container container {};
   container.plan.uuid = 0xA11F18EULL;
   container.plan.config.cpuMode = sharedCPUMode ? ApplicationCPUMode::shared : ApplicationCPUMode::isolated;

   String failure = {};
   scmp_filter_ctx filter = ContainerManager::debugBuildContainerSyscallFilter(&container, &failure);
   if (filter == nullptr)
   {
      close(helperPipe[1]);
      pthread_join(helperThread, nullptr);
      close(helperPipe[0]);
      close(helperPipe[1]);
      return 202;
   }

   pid_t pid = fork();
   if (pid < 0)
   {
      seccomp_release(filter);
      close(helperPipe[1]);
      pthread_join(helperThread, nullptr);
      close(helperPipe[0]);
      close(helperPipe[1]);
      return 203;
   }

   if (pid == 0)
   {
      close(helperPipe[0]);
      close(helperPipe[1]);

      int cpu = firstAllowedCPU();
      if (cpu < 0)
      {
         _exit(101);
      }

      cpu_set_t singleton {};
      CPU_ZERO(&singleton);
      CPU_SET(cpu, &singleton);

      if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
      {
         _exit(102);
      }

      String childFailure = {};
      if (ContainerManager::debugLoadContainerSyscallFilter(&container, filter, &childFailure) == false)
      {
         _exit(103);
      }

      switch (probe)
      {
         case ProbeKind::schedSetAffinity:
         {
            errno = 0;
            int rc = sched_setaffinity(0, sizeof(singleton), &singleton);
            if (sharedCPUMode)
            {
               _exit((rc == -1 && errno == EPERM) ? 0 : 120);
            }

            _exit(rc == 0 ? 0 : 121);
         }

         case ProbeKind::pthreadSetAffinity:
         {
            int rc = pthread_setaffinity_np(pthread_self(), sizeof(singleton), &singleton);
            if (sharedCPUMode)
            {
               _exit(rc == EPERM ? 0 : 110);
            }

            _exit(rc == 0 ? 0 : 111);
         }

         case ProbeKind::ptraceTraceMe:
         {
            errno = 0;
            long rc = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
            _exit((rc == -1 && errno == EPERM) ? 0 : 130);
         }

         case ProbeKind::unshareFiles:
         {
            errno = 0;
            int rc = unshare(CLONE_FILES);
            _exit((rc == -1 && errno == EPERM) ? 0 : 140);
         }

         case ProbeKind::pidfdOpenSelf:
         {
            errno = 0;
            int fd = int(syscall(SYS_pidfd_open, getpid(), 0));
            if (fd >= 0)
            {
               close(fd);
            }
            _exit((fd == -1 && errno == EPERM) ? 0 : 150);
         }
      }

      _exit(199);
   }

   int status = 0;
   if (waitpid(pid, &status, 0) != pid)
   {
      seccomp_release(filter);
      close(helperPipe[1]);
      pthread_join(helperThread, nullptr);
      close(helperPipe[0]);
      close(helperPipe[1]);
      return 204;
   }

   seccomp_release(filter);
   close(helperPipe[1]);
   pthread_join(helperThread, nullptr);
   close(helperPipe[0]);
   close(helperPipe[1]);

   if (WIFEXITED(status) == false)
   {
      return 205;
   }

   return WEXITSTATUS(status);
}

static int runPostMountExecutionSecurityPolicyProbe(void)
{
   pid_t pid = fork();
   if (pid < 0)
   {
      return 200;
   }

   if (pid == 0)
   {
      Container container {};
      container.plan.uuid = 0xC0FFEEULL;
      String failure = {};

      if (ContainerManager::debugSetContainerNoNewPrivileges(&container, &failure) == false)
      {
         std::fprintf(stderr, "debugSetContainerNoNewPrivileges failed: %s\n", failure.c_str());
         _exit(101);
      }

      if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
      {
         _exit(102);
      }

      if (ContainerManager::debugApplyContainerPostMountExecutionSecurityPolicy(&container, &failure) == false)
      {
         std::fprintf(stderr, "debugApplyContainerPostMountExecutionSecurityPolicy failed: %s\n", failure.c_str());
         _exit(103);
      }

      if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
      {
         _exit(104);
      }

      if (effectiveCapabilityEnabled(CAP_SYS_ADMIN))
      {
         std::fprintf(stderr, "CAP_SYS_ADMIN remained effective after policy\n");
         _exit(105);
      }

      errno = 0;
      long ptraceResult = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
      if (ptraceResult != -1 || errno != EPERM)
      {
         std::fprintf(stderr, "ptrace probe failed result=%ld errno=%d\n", ptraceResult, errno);
         _exit(106);
      }

      errno = 0;
      int pidfd = int(syscall(SYS_pidfd_open, getpid(), 0));
      if (pidfd >= 0)
      {
         std::fprintf(stderr, "pidfd_open unexpectedly succeeded fd=%d\n", pidfd);
         close(pidfd);
         _exit(107);
      }

      if (errno != EPERM)
      {
         std::fprintf(stderr, "pidfd_open failed with unexpected errno=%d\n", errno);
         _exit(108);
      }

      _exit(0);
   }

   int status = 0;
   if (waitpid(pid, &status, 0) != pid)
   {
      return 201;
   }

   if (WIFEXITED(status) == false)
   {
      return 202;
   }

   return WEXITSTATUS(status);
}

static int runChildPrivilegedFDCloseProbe(void)
{
   pid_t pid = fork();
   if (pid < 0)
   {
      return 200;
   }

   if (pid == 0)
   {
      int pidfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
      int cgroupfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
      if (pidfd < 0 || cgroupfd < 0)
      {
         _exit(101);
      }

      Container container {};
      container.plan.uuid = 0xBADFDU;
      container.pidfd = pidfd;
      container.cgroup = cgroupfd;

      String failure = {};
      if (ContainerManager::debugCloseContainerChildPrivilegedFDs(&container, &failure) == false)
      {
         _exit(102);
      }

      if (container.pidfd != -1 || container.cgroup != -1)
      {
         _exit(103);
      }

      errno = 0;
      if (fcntl(pidfd, F_GETFD) != -1 || errno != EBADF)
      {
         _exit(104);
      }

      errno = 0;
      if (fcntl(cgroupfd, F_GETFD) != -1 || errno != EBADF)
      {
         _exit(105);
      }

      _exit(0);
   }

   int status = 0;
   if (waitpid(pid, &status, 0) != pid)
   {
      return 201;
   }

   if (WIFEXITED(status) == false)
   {
      return 202;
   }

   return WEXITSTATUS(status);
}

int main(void)
{
   TestSuite suite;

   suite.expect(prodigyContainerReservedCoreCount(1) == 0, "small_cpuset_reserves_zero_container_cores_one_cpu");
   suite.expect(prodigyContainerReservedCoreCount(2) == 0, "small_cpuset_reserves_zero_container_cores_two_cpus");
   suite.expect(prodigyContainerReservedCoreCount(3) == nReservedCores, "larger_cpuset_keeps_default_reserved_cores");

   suite.expect(runSeccompProbe(false, false, ProbeKind::ptraceTraceMe) == 0, "unfiltered_ptrace_traceme_succeeds");
   suite.expect(runSeccompProbe(true, false, ProbeKind::ptraceTraceMe) == 0, "default_filter_blocks_ptrace_traceme");
   suite.expect(runSeccompProbe(false, false, ProbeKind::unshareFiles) == 0, "unfiltered_unshare_files_succeeds");
   suite.expect(runSeccompProbe(true, false, ProbeKind::unshareFiles) == 0, "default_filter_blocks_unshare_files");
   suite.expect(runSeccompProbe(false, false, ProbeKind::pidfdOpenSelf) == 0, "unfiltered_pidfd_open_succeeds");
   suite.expect(runSeccompProbe(true, false, ProbeKind::pidfdOpenSelf) == 0, "default_filter_blocks_pidfd_open");
   suite.expect(runSeccompProbe(false, true, ProbeKind::schedSetAffinity) == 0, "unfiltered_sched_setaffinity_succeeds");
   suite.expect(runSeccompProbe(false, true, ProbeKind::pthreadSetAffinity) == 0, "unfiltered_pthread_setaffinity_succeeds");
   suite.expect(runSeccompProbe(true, true, ProbeKind::schedSetAffinity) == 0, "shared_cpu_filter_blocks_sched_setaffinity");
   suite.expect(runSeccompProbe(true, true, ProbeKind::pthreadSetAffinity) == 0, "shared_cpu_filter_blocks_pthread_setaffinity");
   suite.expect(runPrebuiltSeccompProbe(false, ProbeKind::ptraceTraceMe) == 0, "prebuilt_filter_blocks_ptrace_after_multithreaded_fork");
   suite.expect(runPrebuiltSeccompProbe(true, ProbeKind::schedSetAffinity) == 0, "prebuilt_shared_cpu_filter_blocks_sched_setaffinity_after_multithreaded_fork");
   suite.expect(runChildPrivilegedFDCloseProbe() == 0, "child_security_hardening_closes_inherited_privileged_fds");
   suite.expect(runPostMountExecutionSecurityPolicyProbe() == 0, "post_mount_security_policy_sets_no_new_privs_drops_caps_and_loads_seccomp");

   return suite.failed == 0 ? 0 : 1;
}
