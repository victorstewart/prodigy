// Helper to spawn a child process with stdout/stderr redirected to log files.

#pragma once

#include <base/includes.h>
#include <prodigy/logging/logging.h>

#include <spawn.h>
#include <sys/wait.h>

namespace Prodigy {
namespace Logs {

// Spawns `path` with `argv` and environment `envp` (pass environ),
// wiring stdout/stderr to the provided ContainerLogPaths.
// Returns 0 on success, and writes child PID to outPid.
static inline int spawn_with_logs(const char *path,
                                  char *const argv[],
                                  char *const envp[],
                                  const ContainerLogPaths &p,
                                  pid_t *outPid)
{
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);

    ensure_dirs(p);
    int rc = setup_posix_spawn_stdio(&fa, p.stdoutPath, p.stderrPath);
    if (rc != 0) {
        posix_spawn_file_actions_destroy(&fa);
        return -1;
    }

    int s = posix_spawn(outPid, path, &fa, nullptr, argv, envp);
    posix_spawn_file_actions_destroy(&fa);
    return s;
}

} // namespace Logs
} // namespace Prodigy

