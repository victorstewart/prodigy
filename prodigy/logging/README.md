Logging conventions for containers

Directory layout

- Base: `/var/log/nametag/containers/<app-id>/<container-uuid>/`
- Files:
  - `stdout.log`: redirected stdout of the container
  - `stderr.log`: redirected stderr of the container
  - `perf/`: directory for performance traces collected by profilers or eBPF tools
  - `crashes/<timestamp>/`: crash bundles (compressed copies of the above at time of crash)

Identifiers

- `<app-id>`: 16-bit application ID (decimal)
- `<container-uuid>`: 128-bit container UUID, 32 lowercase hex chars

Writing strategy

- Redirect the child process’ fd 1 and 2 to files opened with `O_APPEND|O_CREAT`.
- Prefer doing this in the launcher (neuron) using `posix_spawn_file_actions_addopen` to avoid pipe overhead.
- For programs we own, optional fallback is `freopen("...", "a", stdout/stderr)` at startup; set `stderr` unbuffered and `stdout` line-buffered.
- On termination signals in our own programs, call `fflush(nullptr)` in a minimal async-signal-safe handler (or arrange a graceful shutdown) to reduce data loss risk. For third‑party apps we rely on kernel page cache + `O_APPEND` semantics.

Streaming logs to Master/Mothership

- For a running container, stream logs by tailing `stdout.log` (and optionally `stderr.log`).
- Request API supports a lookback window in minutes with sentinels:
  - `lookbackMinutes = -1`: only now forward (start at current EOF).
  - `lookbackMinutes = -2`: from oldest (start of file).
  - `lookbackMinutes >= 0`: start at first entry whose timestamp ≥ now − lookback.
- Rotation is handled: follower detects inode changes and reopens the current `*.log` file.
- Framing includes: `<container-uuid>`, `stream` (stdout|stderr), `sequence`, `payload`.

Crash handling

- When the container exits abnormally (non‑zero or signal), the neuron must:
  - Stop scheduling new work for it immediately.
  - Create a crash bundle directory: `/var/log/nametag/containers/<app-id>/<uuid>/crashes/<timestamp>/`.
  - Compress `stdout.log` and `stderr.log` to `stdout.log.gz`, `stderr.log.gz` under the crash dir.
  - Optionally include recent perf traces from `perf/`.
  - Upload the bundle to the master (HTTP/2 PUT or mesh message) and include a reference on the ApplicationDeployment object.

Retention & rotation

- Daily rotation with 2-day retention per stream:
  - Active day writes to `stdout.log`/`stderr.log`.
  - At UTC day change, `*.log` is renamed to `stdout.YYYYMMDD.log` / `stderr.YYYYMMDD.log` and a new `*.log` is opened.
  - Only the latest rotated day is kept; older rotated files are deleted (i.e., keep current day + previous day).
- Crash bundles and perf files older than 24h are purged by the neuron GC.

Security

- Log directories default to `0755` and files `0644`. If logs contain sensitive data, tighten to `0750`/`0640` and group‑assign to the operator role.
- Validate and sanitize any on‑demand read ranges requested by the Mothership.

Integration points

- On container launch (neuron): compute `ContainerLogPaths`, `ensure_dirs()`, and set up stdio mapping via `setup_posix_spawn_stdio(...)`.
- On container crash: call `make_crash_bundle(...)` then upload; record artifact URI on the deployment report.
- On Mothership request: use `TailFollower` to stream new bytes and send the preexisting tail segment the client requests.

Header utility

- See `prodigy/logging/logging.h` for path helpers, stdio redirection, and a tail follower skeleton.
