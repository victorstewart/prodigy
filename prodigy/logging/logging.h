// Logging utilities and conventions for containers
//
// Provides:
// - Path conventions for stdout/stderr and perf logs
// - Helpers to create log directories
// - Helper to redirect a child process' stdout/stderr to files (posix_spawn)
// - Optional helper to redirect current process using freopen (for our own programs)
// - Tail/stream skeletons to follow a log file (for on-demand streaming)

#pragma once

#include <base/includes.h>
#include <services/filesystem.h>

#include <fcntl.h>
#include <spawn.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zstd.h>

namespace Prodigy {
namespace Logs {

// Where logs live
// Preferred (host view of container):
//   /containers/<container-name>/logs/
//     stdout.log
//     stderr.log
//     perf/
//       trace.<ts>.* (tool-specific files)
// Crash bundles under:
//   /containers/<container-name>/logs/crashes/<ts>/
//     stdout.log.zst
//     stderr.log.zst
//     perf/* (if present)

struct ContainerLogPaths {
    String baseDir;      // .../containers/<app-id>/<uuid>
    String stdoutPath;   // baseDir + "/stdout.log"
    String stderrPath;   // baseDir + "/stderr.log"
    String perfDir;      // baseDir + "/perf"
};

// For neuron-side use: resolve by container host name (decimal uuid)
static inline ContainerLogPaths host_paths_for_container(const String &containerName)
{
    ContainerLogPaths p;
    p.baseDir.snprintf<"/containers/{}/logs"_ctv>(containerName);
    p.stdoutPath.snprintf<"{}/stdout.log"_ctv>(p.baseDir);
    p.stderrPath.snprintf<"{}/stderr.log"_ctv>(p.baseDir);
    p.perfDir.snprintf<"{}/perf"_ctv>(p.baseDir);
    return p;
}

static inline String format_uuid_hex(const uint128_t &uuid)
{
    String s;
    s.reserve(32);
    // uuid is 16 bytes in native endianness; write as 32 hex chars, msb->lsb
    uint8_t buf[16];
    memcpy(buf, &const_cast<uint128_t&>(uuid), 16);
    for (int i = 15; i >= 0; --i) s.snprintf_add<"%02x"_ctv>(buf[i]);
    return s;
}

static inline ContainerLogPaths paths_for(uint16_t appID, const uint128_t &uuid)
{
    ContainerLogPaths p;
    String uuidHex = format_uuid_hex(uuid);
    p.baseDir.snprintf<"/var/log/prodigy/containers/{itoa}/{}"_ctv>(appID, uuidHex);
    p.stdoutPath.snprintf<"{}/stdout.log"_ctv>(p.baseDir);
    p.stderrPath.snprintf<"{}/stderr.log"_ctv>(p.baseDir);
    p.perfDir.snprintf<"{}/perf"_ctv>(p.baseDir);
    return p;
}

static inline int ensure_dirs(const ContainerLogPaths &p)
{
    // Best-effort mkdir -p style
    // /var/log
    Filesystem::createDirectoryAt(-1, "/var/log"_ctv, 0755);
    Filesystem::createDirectoryAt(-1, "/var/log/prodigy"_ctv, 0755);
    Filesystem::createDirectoryAt(-1, "/var/log/prodigy/containers"_ctv, 0755);

    // Ensure base and perf dirs exist
    Filesystem::createDirectoryAt(-1, p.baseDir, 0755);
    Filesystem::createDirectoryAt(-1, p.perfDir, 0755);
    return 0;
}

// Redirect a child process' stdio to files using posix_spawn file actions.
// Use O_APPEND so concurrent writers are safe and no seek races occur.
static inline int setup_posix_spawn_stdio(posix_spawn_file_actions_t *fa,
                                          const String &stdoutPath,
                                          const String &stderrPath,
                                          mode_t mode = 0644)
{
    int rc = 0;
    // Open stdout as fd 1
    rc |= posix_spawn_file_actions_addopen(fa, 1, stdoutPath.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, mode);
    // Open stderr as fd 2
    rc |= posix_spawn_file_actions_addopen(fa, 2, stderrPath.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, mode);
    return rc;
}

// For our own programs that can opt-in, redirect process-global stdout/stderr to files.
// Note: only suitable when we control the code; third-party apps should be launched via posix_spawn plumbing above.
static inline bool redirect_self_stdio(const String &stdoutPath, const String &stderrPath)
{
    FILE *so = freopen(stdoutPath.c_str(), "a", stdout);
    FILE *se = freopen(stderrPath.c_str(), "a", stderr);
    if (!so || !se) return false;
    setvbuf(stdout, nullptr, _IOLBF, 0); // line-buffered for terminals; files typically fully buffered but line is a decent default
    setvbuf(stderr, nullptr, _IONBF, 0); // unbuffered stderr
    return true;
}

// Minimal tail follower for on-demand streaming.
// This is a simple skeleton suitable for integration into an event loop.
class TailFollower {
public:
    using Sink = void(*)(const uint8_t *data, size_t len, void *opaque);

    TailFollower() = default;

    // Start following the given path. If the file exists, starts from current EOF
    // and emits only new appended data. If truncated/rotated, resets offset.
    // Returns fd of epoll instance to poll on, or -1 on error.
    int start(const String &path, Sink sink, void *opaque)
    {
        logPath = path;
        onChunk = sink;
        user = opaque;

        // Open the file for reading
        logfd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (logfd < 0) return -1;

        // Start at EOF
        off = lseek(logfd, 0, SEEK_END);

        // inotify watch
        inofd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (inofd < 0) return -1;
        wd = inotify_add_watch(inofd, path.c_str(), IN_MODIFY | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF | IN_IGNORED);
        if (wd < 0) return -1;

        // epoll
        epfd = epoll_create1(EPOLL_CLOEXEC);
        if (epfd < 0) return -1;
        epoll_event ev{}; ev.events = EPOLLIN | EPOLLET; ev.data.u32 = 1;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, inofd, &ev) < 0) return -1;
        return epfd;
    }

    // Call when epoll indicates readability on inotify fd.
    // Reads events and emits any new appended bytes since last read.
    void on_epoll()
    {
        // Drain inotify
        uint8_t buf[4096];
        ssize_t n = ::read(inofd, buf, sizeof(buf));
        (void)n; // events are not individually inspected here; we re-check file state

        // Attempt to read any new bytes from file
        emit_new_bytes();
    }

    void stop()
    {
        if (wd >= 0) { inotify_rm_watch(inofd, wd); wd = -1; }
        if (inofd >= 0) { ::close(inofd); inofd = -1; }
        if (logfd >= 0) { ::close(logfd); logfd = -1; }
        if (epfd >= 0) { ::close(epfd); epfd = -1; }
        off = 0;
    }

private:
    void emit_new_bytes()
    {
        if (logfd < 0 || !onChunk) return;
        for (;;) {
            uint8_t buf[8192];
            ssize_t r = ::pread(logfd, buf, sizeof(buf), off);
            if (r > 0) {
                off += r;
                onChunk(buf, size_t(r), user);
                continue;
            }
            if (r == 0) break; // EOF
            if (r < 0 && (errno == EINTR)) continue;
            break;
        }
        // Detect truncation
        struct stat st{};
        if (fstat(logfd, &st) == 0 && off > st.st_size) {
            off = st.st_size;
        }
    }

    String logPath;
    int logfd{-1};
    int inofd{-1};
    int wd{-1};
    int epfd{-1};
    off_t off{0};
    Sink onChunk{nullptr};
    void *user{nullptr};
};

// Crash bundle output location under a timestamped directory.
static inline String crash_bundle_dir(const ContainerLogPaths &p, int64_t crashTimeMs)
{
    String d;
    d.snprintf<"{}/crashes/{}"_ctv>(p.baseDir, String::epochMsToDateTime(crashTimeMs));
    return d;
}

// Compress a source file to destPath using zstd.
// Returns 0 on success, negative on error.
static inline int zstd_compress_file(const String &srcPath, const String &destPath, int level = 3)
{
    int in = ::open(srcPath.c_str(), O_RDONLY);
    if (in < 0) return -1;
    int out = ::open(destPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { ::close(in); return -2; }

    ZSTD_CCtx *cctx = ZSTD_createCCtx();
    if (!cctx) { ::close(in); ::close(out); return -3; }
    if (ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level))) { ZSTD_freeCCtx(cctx); ::close(in); ::close(out); return -4; }

    const size_t outCap = ZSTD_CStreamOutSize();
    const size_t inCap  = ZSTD_CStreamInSize();
    std::unique_ptr<uint8_t[]> inBuf(new uint8_t[inCap]);
    std::unique_ptr<uint8_t[]> outBuf(new uint8_t[outCap]);

    ZSTD_inBuffer zin{ inBuf.get(), 0, 0 };
    ZSTD_outBuffer zout{ outBuf.get(), outCap, 0 };

    for (;;) {
        ssize_t r = ::read(in, inBuf.get(), inCap);
        if (r < 0) { ZSTD_freeCCtx(cctx); ::close(in); ::close(out); return -5; }
        zin.src = inBuf.get();
        zin.size = size_t(r);
        zin.pos = 0;

        int last = (r == 0);
        ZSTD_EndDirective mode = last ? ZSTD_e_end : ZSTD_e_continue;
        size_t remaining;
        do {
            zout.dst = outBuf.get();
            zout.size = outCap;
            zout.pos = 0;
            remaining = ZSTD_compressStream2(cctx, &zout, &zin, mode);
            if (ZSTD_isError(remaining)) { ZSTD_freeCCtx(cctx); ::close(in); ::close(out); return -6; }
            if (zout.pos) {
                ssize_t wr = ::write(out, outBuf.get(), zout.pos);
                if (wr < 0) { ZSTD_freeCCtx(cctx); ::close(in); ::close(out); return -7; }
            }
        } while (remaining != 0 && (last ? (zin.pos == zin.size) : true));
        if (last) break;
    }

    ZSTD_freeCCtx(cctx);
    ::close(in);
    ::close(out);
    return 0;
}

// Prepare a crash bundle (stdout/stderr compressed) and return the output directory used.
// Returns empty String on failure.
static inline String make_crash_bundle(const ContainerLogPaths &p, int64_t crashTimeMs)
{
    ensure_dirs(p);
    String outDir = crash_bundle_dir(p, crashTimeMs);
    Filesystem::createDirectoryAt(-1, outDir, 0755);

    String soGz, seGz;
    soGz.snprintf<"{}/stdout.log.zst"_ctv>(outDir);
    seGz.snprintf<"{}/stderr.log.zst"_ctv>(outDir);

    if (zstd_compress_file(p.stdoutPath, soGz) != 0) return String();
    if (zstd_compress_file(p.stderrPath, seGz) != 0) return String();
    return outDir;
}

} // namespace Logs
} // namespace Prodigy
