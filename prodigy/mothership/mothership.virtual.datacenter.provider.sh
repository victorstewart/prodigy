#!/usr/bin/env bash
set -Eeuo pipefail

enter_machine()
{
   [[ "$#" -eq 13 || "$#" -eq 14 ]]
   local machine_cgroup="$1"
   shift
   if [[ "$#" -eq 13 ]]
   then
      local retained_cgroup_fd="$1"
      shift
      [[ "${retained_cgroup_fd}" =~ ^[0-9]+$ && -r "/proc/self/fd/${retained_cgroup_fd}" && -w "${machine_cgroup}/prodigy-runtime/cgroup.procs" ]] || exit 2
      printf "%s\n" "$$" > "${machine_cgroup}/prodigy-runtime/cgroup.procs"
      exec nsenter --cgroup="/proc/self/fd/${retained_cgroup_fd}" -- unshare --mount --propagation private -- bash "$0" --run-machine "$@"
   fi
   printf "%s\n" "$$" > "${machine_cgroup}/cgroup.procs"
   exec unshare --cgroup --mount --propagation private -- bash "$0" --run-machine "$@"
}
run_machine()
{
   [[ "$#" -eq 12 ]]
   local workspace="$1"
   local machine_root="$2"
   local containers_root="$3"
   local storage_root="$4"
   local storage_device_count="$5"
   local child_ns="$6"
   local boot_path="$7"
   local transport_tls_path="$8"
   local host_netns_inode="$9"
   local brain_count="${10}"
   local fake_ingress="${11}"
   local machine_bpffs="${12}"

   [[ "${machine_bpffs}" == /mnt/prodigy-vdc-*/machine-bpffs/machine* && -d "${machine_bpffs}" && ! -L "${machine_bpffs}" ]]
   mountpoint -q "${machine_bpffs}"
   [[ "$(findmnt -n -o FSTYPE -T "${machine_bpffs}")" == "bpf" ]]

   mkdir -p /mnt/prodigy-vdc-workspace /containers /root /sys/fs/cgroup /sys/fs/bpf /var/log/prodigy "${machine_root}/var/log/prodigy"
   mount --bind "${workspace}" /mnt/prodigy-vdc-workspace
   mount --bind "${machine_root}/var/log/prodigy" /var/log/prodigy
   mount --bind "${machine_root}/root" /root
   mount --bind "${containers_root}" /containers
   mkdir -p "${workspace}" /containers/store
   mount --bind /mnt/prodigy-vdc-workspace "${workspace}"

   local storage_mounts=""
   local device=""
   for device in $(seq 1 "${storage_device_count}")
   do
      local target="/mnt/prodigy-storage/${device}"
      mkdir -p "${target}"
      mount --bind "${storage_root}/${device}" "${target}"
      [[ -z "${storage_mounts}" ]] || storage_mounts+=":"
      storage_mounts+="${target}"
   done

   local boot_json
   boot_json="$(<"${boot_path}")"
   local environment=(
      "PRODIGY_DEV_MODE=1"
      "PRODIGY_DEV_TEST_OVERCOMMIT_CPUS=1"
      "PRODIGY_HOST_NETNS_INO=${host_netns_inode}"
      "PRODIGY_BOOTSTRAP_BRAIN_COUNT=${brain_count}"
      "PRODIGY_CRASH_REPORT_PATH=/root/prodigy-crashreport.txt"
      "PRODIGY_STATE_DB=/containers/prodigy.state"
      "PRODIGY_VDC_MACHINE_BPFFS=${machine_bpffs}"
   )
   if [[ "${PRODIGY_DEV_CANCEL_TEST_DIR:-}" == "/mnt/prodigy-vdc-workspace/cancel-deployment-test" ]]
   then
      environment+=("PRODIGY_DEV_CANCEL_TEST_DIR=/mnt/prodigy-vdc-workspace/cancel-deployment-test")
   fi
   [[ -z "${storage_mounts}" ]] || environment+=("PRODIGY_DEV_CONTAINER_STORAGE_MOUNTS=${storage_mounts}")
   if [[ -n "${fake_ingress}" ]]
   then
      environment+=(
         "PRODIGY_DEV_FAKE_IPV4_MODE=1"
         "PRODIGY_HOST_INGRESS_EBPF=${fake_ingress}"
         "PRODIGY_HOST_EGRESS_EBPF=/root/prodigy/host.egress.router.ebpf.o"
      )
   fi
   exec ip netns exec "${child_ns}" env "${environment[@]}" bash -c '
      set -euo pipefail
      mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
      umount /sys/fs/cgroup >/dev/null 2>&1 || true
      mount -t cgroup2 -o nsdelegate cgroup2 /sys/fs/cgroup
      mkdir -p /sys/fs/cgroup/prodigy-runtime
      printf "%s\n" "$$" > /sys/fs/cgroup/prodigy-runtime/cgroup.procs
      umount /sys/fs/bpf >/dev/null 2>&1 || true
      [[ -d "${PRODIGY_VDC_MACHINE_BPFFS}" && ! -L "${PRODIGY_VDC_MACHINE_BPFFS}" ]]
      mountpoint -q "${PRODIGY_VDC_MACHINE_BPFFS}"
      [[ "$(findmnt -n -o FSTYPE -T "${PRODIGY_VDC_MACHINE_BPFFS}")" == "bpf" ]]
      mount --bind "${PRODIGY_VDC_MACHINE_BPFFS}" /sys/fs/bpf
      exec "$@"
   ' _ /root/prodigy/prodigy --isolated --netdev=bond0 "--boot-json=${boot_json}" "--transport-tls-json-path=${transport_tls_path}"
}

bounded_machine_log()
{
   [[ "$#" -eq 4 ]]
   local log_path="$1"
   local segments="$2"
   local segment_bytes="$3"
   local first_bytes="$4"
   [[ "${log_path}" == /*/* && "${segments}" =~ ^[1-9][0-9]*$ && "${segments}" -le 8 &&
      "${segment_bytes}" =~ ^[1-9][0-9]*$ && "${segment_bytes}" -le 1073741824 &&
      "${first_bytes}" =~ ^[1-9][0-9]*$ && "${first_bytes}" -le "${segment_bytes}" ]]
   [[ -d "${log_path%/*}" && ! -L "${log_path}" ]]
   exec python3 -c '
import os
import sys

path = sys.argv[1]
segments = int(sys.argv[2])
segment_bytes = int(sys.argv[3])
first_bytes = int(sys.argv[4])
first_path = path + ".first"

def rotate():
    oldest = f"{path}.{segments}"
    try:
        os.unlink(oldest)
    except FileNotFoundError:
        pass
    for index in range(segments - 1, 0, -1):
        source = f"{path}.{index}"
        try:
            os.replace(source, f"{path}.{index + 1}")
        except FileNotFoundError:
            pass
    try:
        os.replace(path, f"{path}.1")
    except FileNotFoundError:
        pass

first_size = os.path.getsize(first_path) if os.path.exists(first_path) else 0
current_size = os.path.getsize(path) if os.path.exists(path) else 0
output = open(path, "ab", buffering=0)
first = open(first_path, "ab", buffering=0) if first_size < first_bytes else None
try:
    while True:
        chunk = os.read(sys.stdin.fileno(), 1024 * 1024)
        if not chunk:
            break
        if first is not None:
            prefix = chunk[:max(0, first_bytes - first_size)]
            first.write(prefix)
            first_size += len(prefix)
            if first_size >= first_bytes:
                first.close()
                first = None
        offset = 0
        while offset < len(chunk):
            if current_size >= segment_bytes:
                output.close()
                rotate()
                output = open(path, "ab", buffering=0)
                current_size = 0
            part = chunk[offset:offset + segment_bytes - current_size]
            output.write(part)
            current_size += len(part)
            offset += len(part)
finally:
    output.close()
    if first is not None:
        first.close()
' "${log_path}" "${segments}" "${segment_bytes}" "${first_bytes}"
}

valid_workspace()
{
   local canonical
   canonical="$(realpath -m -- "$1")" || return 1
   [[ "${canonical}" == "$1" && "$1" == /*/* && "$1" != */ ]]
}

valid_control_socket_path()
{
   [[ "$1" =~ ^/tmp/prodigy-vdc-0x[0-9a-fA-F]{1,32}(-d([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))?/mothership\.sock$ ]]
}

network_fragment_from_control_socket_path()
{
   local control_socket_path="$1"
   if [[ "${control_socket_path}" =~ -d([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/mothership\.sock$ ]]
   then
      printf '%s\n' "${BASH_REMATCH[1]}"
   else
      printf '1\n'
   fi
}

resolve_cgroup_scope()
{
   local hierarchy=""
   local controllers=""
   local relative=""
   while IFS=: read -r hierarchy controllers relative
   do
      [[ "${hierarchy}" != "0" || -n "${controllers}" ]] || break
   done < /proc/self/cgroup
   [[ "${hierarchy}" == "0" && -z "${controllers}" && "${relative}" == /* ]]
   if [[ "${relative}" =~ ^(.*)/prodigy-vdc-control$ || "${relative}" =~ ^(.*)/prodigy-vdc-[0-9]+(/.*)?$ ]]
   then
      relative="${BASH_REMATCH[1]}"
      [[ -n "${relative}" ]] || relative="/"
   fi
   cgroup_scope="/sys/fs/cgroup${relative%/}"
   [[ -d "${cgroup_scope}" && -w "${cgroup_scope}/cgroup.procs" && -w "${cgroup_scope}/cgroup.subtree_control" ]]
   cgroup_control="${cgroup_scope}/prodigy-vdc-control"
   cgroup_lock="/run/prodigy-vdc-cgroup-$(stat -Lc %i "${cgroup_scope}").lock"
}

move_cgroup_processes()
{
   local source="$1"
   local destination="$2"
   local -a processes=()
   local process=""
   for _ in {1..10}
   do
      mapfile -t processes < "${source}/cgroup.procs"
      [[ "${#processes[@]}" -gt 0 ]] || return 0
      for process in "${processes[@]}"
      do
         printf '%s\n' "${process}" > "${destination}/cgroup.procs" 2>/dev/null || [[ ! -d "/proc/${process}" ]]
      done
   done
   [[ ! -s "${source}/cgroup.procs" ]]
}

prepare_cgroup_scope()
{
   resolve_cgroup_scope
   (
      exec {cgroup_lock_fd}>"${cgroup_lock}"
      flock "${cgroup_lock_fd}"

      local child=""
      while IFS= read -r child
      do
         [[ "${child}" == "${cgroup_control}" || "${child##*/}" =~ ^prodigy-vdc-[0-9]+$ ]] || {
            echo "virtual datacenter requires a dedicated Mothership cgroup" >&2
            return 1
         }
      done < <(find "${cgroup_scope}" -mindepth 1 -maxdepth 1 -type d -print)

      if [[ ! -d "${cgroup_control}" ]]
      then
         [[ ! -s "${cgroup_scope}/cgroup.subtree_control" ]] || {
            echo "virtual datacenter requires an undelegated Mothership cgroup" >&2
            return 1
         }
         mkdir "${cgroup_control}"
      fi
      move_cgroup_processes "${cgroup_scope}" "${cgroup_control}"

      local available=" $(<"${cgroup_scope}/cgroup.controllers") "
      local enabled=" $(<"${cgroup_scope}/cgroup.subtree_control") "
      local controller=""
      for controller in cpuset cpu memory pids
      do
         [[ "${available}" == *" ${controller} "* ]] || {
            echo "virtual datacenter requires cgroup controller ${controller}" >&2
            return 1
         }
         if [[ "${enabled}" != *" ${controller} "* ]]
         then
            printf '+%s\n' "${controller}" > "${cgroup_scope}/cgroup.subtree_control"
         fi
      done
      flock -u "${cgroup_lock_fd}"
   )
}

valid_retained_cgroup_root()
{
   local retained_cgroup_root="$1"
   local runtime_identity="$2"
   local canonical=""
   [[ "${runtime_identity}" =~ ^[0-9]+$ ]] || return 1
   canonical="$(realpath -m -- "${retained_cgroup_root}")" || return 1
   [[ "${canonical}" == "${retained_cgroup_root}" ]] || return 1
   [[ "${retained_cgroup_root}" == "/sys/fs/cgroup/prodigy-vdc-${runtime_identity}" ||
      "${retained_cgroup_root}" == /sys/fs/cgroup/*/prodigy-vdc-"${runtime_identity}" ]]
}

restore_cgroup_scope_if_idle()
{
   if [[ -n "${1:-}" ]]
   then
      cgroup_scope="$1"
      [[ ( "${cgroup_scope}" == /sys/fs/cgroup || "${cgroup_scope}" == /sys/fs/cgroup/* ) && -d "${cgroup_scope}" ]] || return 1
      cgroup_control="${cgroup_scope}/prodigy-vdc-control"
      cgroup_lock="/run/prodigy-vdc-cgroup-$(stat -Lc %i "${cgroup_scope}").lock"
   else
      resolve_cgroup_scope || return 0
   fi
   (
      exec {cgroup_restore_lock_fd}>"${cgroup_lock}"
      flock "${cgroup_restore_lock_fd}"

      local child=""
      local active=0
      for child in "${cgroup_scope}"/prodigy-vdc-[0-9]*
      do
         [[ ! -d "${child}" ]] || active=1
      done
      if [[ "${active}" -eq 0 && -d "${cgroup_control}" ]]
      then
         local enabled=" $(<"${cgroup_scope}/cgroup.subtree_control") "
         local controller=""
         for controller in cpuset cpu memory pids
         do
            if [[ "${enabled}" == *" ${controller} "* ]]
            then
               printf -- '-%s\n' "${controller}" > "${cgroup_scope}/cgroup.subtree_control" 2>/dev/null || true
            fi
         done
         move_cgroup_processes "${cgroup_control}" "${cgroup_scope}" || true
         rmdir "${cgroup_control}" 2>/dev/null || true
      fi
      flock -u "${cgroup_restore_lock_fd}"
   )
}

provider_process()
{
   local candidate="$1"
   local workspace="$2"
   [[ "${candidate}" =~ ^[0-9]+$ && "${candidate}" -gt 1 && -r "/proc/${candidate}/cmdline" ]] || return 1
   local -a arguments=()
   mapfile -d '' -t arguments < "/proc/${candidate}/cmdline" || return 1
   [[ "${arguments[0]:-}" == bash || "${arguments[0]:-}" == /bin/bash ]] || return 1
   [[ "${arguments[1]:-}" =~ ^/proc/self/fd/[0-9]+$ ]] || return 1
   case "${arguments[2]:-}" in
      --serve) [[ "${#arguments[@]}" -eq 15 && "${arguments[3]}" == "${workspace}" ]] ;;
      --serve-adopt) [[ "${#arguments[@]}" -eq 17 && "${arguments[3]}" =~ ^[0-9]+$ && "${arguments[5]}" == "${workspace}" && "${arguments[4]}" == "${workspace}/virtual-datacenter.recovery/"* ]] ;;
      *) return 1 ;;
   esac
}

runtime_identity_for_workspace()
{
   local workspace="$1" actual_pid="$2" identity_path="${workspace}/virtual-datacenter.identity" identity=""
   if [[ -r "${identity_path}" ]]
   then
      identity="$(<"${identity_path}")"
      [[ "${identity}" =~ ^[0-9]+$ && "${identity}" -gt 1 ]] || return 1
      printf "%s\n" "${identity}"
   else
      printf "%s\n" "${actual_pid}"
   fi
}

sleep_milliseconds()
{
   local milliseconds="$1"
   local seconds=""
   printf -v seconds '%d.%03d' "$((milliseconds / 1000))" "$((milliseconds % 1000))"
   sleep "${seconds}"
}

validate_machine_indices()
{
   local indices="$1"
   local machine_count="$2"
   local index=""
   local -a parsed=()
   IFS=, read -r -a parsed <<< "${indices}"
   [[ "${#parsed[@]}" -gt 0 ]]
   for index in "${parsed[@]}"
   do
      [[ "${index}" =~ ^[0-9]+$ && "${index}" -ge 1 && "${index}" -le "${machine_count}" ]]
   done
}

# A fault can outlive provider adoption. Resolve the published owner at each
# link transition and bind it to the original retained namespace identity.
fault_link_set()
{
   [[ "$#" -eq 4 ]] || return 2
   local workspace="$1"
   local expected_runtime_identity="$2"
   local link_name="$3"
   local link_state="$4"
   valid_workspace "${workspace}" || return 2
   [[ "${expected_runtime_identity}" =~ ^[0-9]+$ && "${expected_runtime_identity}" -gt 1 ]] || return 2
   [[ "${link_name}" =~ ^vp[1-9][0-9]*$ && ( "${link_state}" == down || "${link_state}" == up ) ]] || return 2
   local pid_path="${workspace}/virtual-datacenter.pid"
   local current_provider_pid=""
   [[ -r "${pid_path}" ]] || return 1
   current_provider_pid="$(<"${pid_path}")"
   provider_process "${current_provider_pid}" "${workspace}" || return 1
   local current_runtime_identity=""
   current_runtime_identity="$(runtime_identity_for_workspace "${workspace}" "${current_provider_pid}")" || return 1
   [[ "${current_runtime_identity}" == "${expected_runtime_identity}" ]] || return 1
   nsenter -t "${current_provider_pid}" -m -- ip netns exec "pvd-p-${expected_runtime_identity}" ip link set "${link_name}" "${link_state}" || return 1
   printf 'fault-link runtime=%s link=%s state=%s atMs=%s\n' "${expected_runtime_identity}" "${link_name}" "${link_state}" "$(date +%s%3N)" >> "${workspace}/fault-events.log"
}

fault_datacenter()
{
   [[ "$#" -eq 7 && "${EUID}" -eq 0 ]] || return 2
   local workspace="$1"
   local mode="$2"
   local indices="$3"
   local duration_ms="$4"
   local cycles="$5"
   local down_ms="$6"
   local up_ms="$7"
   valid_workspace "${workspace}" || return 2
   [[ "${mode}" == "link" || "${mode}" == "crash" || "${mode}" == "flap" ]] || return 2
   for value in "${duration_ms}" "${cycles}" "${down_ms}" "${up_ms}"
   do
      [[ "${value}" =~ ^[0-9]+$ && "${value}" -le 3600000 ]] || return 2
   done

   local pid_path="${workspace}/virtual-datacenter.pid"
   local runtime_path="${workspace}/virtual-datacenter.runtime"
   local provider_pid=""
   [[ -r "${pid_path}" && -r "${runtime_path}" ]] || return 1
   provider_pid="$(<"${pid_path}")"
   provider_process "${provider_pid}" "${workspace}" || return 1
   command -v ip >/dev/null
   command -v nsenter >/dev/null
   local runtime_identity=""
   runtime_identity="$(runtime_identity_for_workspace "${workspace}" "${provider_pid}")" || return 1
   local -a machine_pids=()
   mapfile -t machine_pids < "${runtime_path}"
   validate_machine_indices "${indices}" "${#machine_pids[@]}" || return 2

   local index=""
   local cycle=""
   local -a parsed=()
   IFS=, read -r -a parsed <<< "${indices}"
   if [[ "${mode}" == "link" || "${mode}" == "flap" ]]
   then
      local repetitions=1
      local link_down_ms="${duration_ms}"
      local link_up_ms=0
      if [[ "${mode}" == "flap" ]]
      then
         repetitions="${cycles}"
         link_down_ms="${down_ms}"
         link_up_ms="${up_ms}"
         [[ "${repetitions}" -gt 0 ]] || return 2
      fi
      for cycle in $(seq 1 "${repetitions}")
      do
         for index in "${parsed[@]}"
         do
            fault_link_set "${workspace}" "${runtime_identity}" "vp${index}" down || return 1
         done
         if [[ "${mode}" == "link" && "${duration_ms}" -eq 0 ]]
         then
            return 0
         fi
         sleep_milliseconds "${link_down_ms}"
         for index in "${parsed[@]}"
         do
            fault_link_set "${workspace}" "${runtime_identity}" "vp${index}" up || return 1
         done
         [[ "${cycle}" -eq "${repetitions}" ]] || sleep_milliseconds "${link_up_ms}"
      done
      return 0
   fi

   local marker="" fault_pid=""
   for index in "${parsed[@]}"
   do
      marker="${workspace}/fault-machine-${index}"
      fault_pid="${machine_pids[$((index - 1))]}"
      [[ "${fault_pid}" =~ ^[0-9]+$ ]] || return 1
      # Bind a timed whole-machine fault to the exact runtime it killed. The
      # atomic marker becomes the reset ticket only after the requested delay.
      printf '%s\n' "${fault_pid}" > "${marker}.$$.tmp"
      mv -f "${marker}.$$.tmp" "${marker}"
      kill -KILL -- "-${fault_pid}" >/dev/null 2>&1 || true
      kill -KILL "${fault_pid}" >/dev/null 2>&1 || true
      printf 'fault-crash runtime=%s machine=%s atMs=%s\n' "${runtime_identity}" "${index}" "$(date +%s%3N)" >> "${workspace}/fault-events.log"
   done
   [[ "${duration_ms}" -ne 0 ]] || return 0
   sleep_milliseconds "${duration_ms}"
   for index in "${parsed[@]}"
   do
      # Preserve the explicit whole-machine-fault authorization until the
      # supervisor resets the dead machine cgroup and starts its replacement.
      mv -f "${workspace}/fault-machine-${index}" "${workspace}/fault-machine-reset-${index}"
   done

   local ready=0
   for _ in $(seq 1 300)
   do
      ready=1
      mapfile -t current_pids < "${runtime_path}"
      for index in "${parsed[@]}"
      do
         if [[ "${current_pids[$((index - 1))]:-}" == "${machine_pids[$((index - 1))]}" ]] || ! kill -0 "${current_pids[$((index - 1))]:-0}" >/dev/null 2>&1
         then
            ready=0
         fi
      done
      [[ "${ready}" -eq 0 ]] || return 0
      sleep 0.1
   done
   return 1
}


probe_namespace_for_source()
{
   [[ "$#" -eq 2 ]] || return 2
   local workspace="$1" source_index="$2" provider_pid="" runtime_identity="" namespace=""
   valid_workspace "${workspace}" || return 2
   provider_pid="$(<"${workspace}/virtual-datacenter.pid")"
   provider_process "${provider_pid}" "${workspace}" || return 1
   runtime_identity="$(runtime_identity_for_workspace "${workspace}" "${provider_pid}")" || return 1
   namespace="pvd-p-${runtime_identity}"
   if [[ "${source_index}" != 0 ]]
   then
      local -a machine_pids=()
      mapfile -t machine_pids < "${workspace}/virtual-datacenter.runtime"
      [[ "${source_index}" =~ ^[0-9]+$ && "${source_index}" -ge 1 && "${source_index}" -le "${#machine_pids[@]}" ]] || return 2
      namespace="pvd-m${source_index}-${runtime_identity}"
   fi
   printf '%s\n' "${provider_pid}" "${namespace}"
}

probe_traffic_datacenter()
{
   [[ "$#" -eq 10 && "${EUID}" -eq 0 ]] || return 2
   local workspace="$1" address="$2" port="$3" payload="$4" expected="$5" request_timeout_ms="$6" source_index="$7" clients="$8" requests_per_client="$9" interval_ms="${10}"
   [[ "${address}" =~ ^[0-9A-Fa-f:.]+$ && "${port}" =~ ^[0-9]+$ && "${port}" -ge 1 && "${port}" -le 65535 &&
      "${request_timeout_ms}" =~ ^[0-9]+$ && "${request_timeout_ms}" -ge 1 && "${request_timeout_ms}" -le 5000 &&
      "${clients}" == 4 && "${requests_per_client}" =~ ^[1-9][0-9]*$ && "${requests_per_client}" -le 15000 &&
      "${interval_ms}" =~ ^[0-9]+$ && "${interval_ms}" -le 1000 ]] || return 2
   local planned_work_ms=""
   if (( interval_ms == 0 ))
   then planned_work_ms=$(( requests_per_client * request_timeout_ms ))
   else planned_work_ms=$(( (requests_per_client - 1) * interval_ms + request_timeout_ms ))
   fi
   local client_bound_ms=$(( planned_work_ms + 100 )) # fixed common worker origin
   (( clients * requests_per_client <= 60000 && client_bound_ms <= 1201000 )) || return 2
   [[ "${#payload}" -le 4096 && "${#expected}" -le 4096 ]] || return 2
   command -v ip >/dev/null && command -v nsenter >/dev/null && command -v timeout >/dev/null && command -v python3 >/dev/null || return 1
   local probe_namespace_output=""
   probe_namespace_output="$(probe_namespace_for_source "${workspace}" "${source_index}")" || return $?
   local -a probe_namespace=()
   mapfile -t probe_namespace <<< "${probe_namespace_output}"
   [[ "${#probe_namespace[@]}" -eq 2 ]] || return 1
   local provider_pid="${probe_namespace[0]}" namespace="${probe_namespace[1]}"
   local outer_timeout_ms=$(( client_bound_ms + 10000 )) timeout_seconds=""
   printf -v timeout_seconds '%d.%03d' "$((outer_timeout_ms / 1000))" "$((outer_timeout_ms % 1000))"
   nsenter -t "${provider_pid}" -m -- ip netns exec "${namespace}" timeout --foreground "${timeout_seconds}" python3 - \
      "${address}" "${port}" "${payload}" "${expected}" "${request_timeout_ms}" "${clients}" "${requests_per_client}" "${interval_ms}" <<'PROBE_TRAFFIC'
import json, socket, sys, threading, time
address, port, payload, expected, timeout_ms, clients, per_client, interval_ms = sys.argv[1:]
port=int(port); timeout_ns=int(timeout_ms)*1_000_000; clients=int(clients); per_client=int(per_client); interval_ms=int(interval_ms); interval_ns=interval_ms*1_000_000
origin=time.monotonic_ns()+100_000_000
results=[]; output_lock=threading.Lock()
def close(sock):
    if sock is not None:
        try: sock.close()
        except OSError: pass
    return None
def worker(client):
    sock=None; connection=0; buffer=b''
    for sequence in range(per_client):
        scheduled=origin + sequence*interval_ns
        remaining=scheduled-time.monotonic_ns()
        if remaining > 0: time.sleep(remaining/1e9)
        start=time.monotonic_ns(); deadline=(scheduled+timeout_ns) if interval_ns else (start+timeout_ns); success=False; outcome='connect'
        try:
            if sock is None:
                remaining=(deadline-time.monotonic_ns())/1e9
                if remaining <= 0: raise socket.timeout()
                sock=socket.create_connection((address,port), remaining); connection+=1; buffer=b''
            while True:
                remaining=(deadline-time.monotonic_ns())/1e9
                if remaining <= 0: raise socket.timeout()
                sock.settimeout(remaining)
                sock.sendall((payload+'\n').encode())
                break
            while b'\n' not in buffer:
                if len(buffer) >= 4096:
                    outcome='response'; raise ValueError()
                remaining=(deadline-time.monotonic_ns())/1e9
                if remaining <= 0: raise socket.timeout()
                sock.settimeout(remaining)
                chunk=sock.recv(min(4096-len(buffer),4096))
                if not chunk: raise EOFError()
                buffer+=chunk
            line,buffer=buffer.split(b'\n',1)
            if line.decode(errors='replace') == expected: success=True; outcome='pong'
            else: outcome='unexpected'; sock=close(sock); buffer=b''
        except socket.timeout:
            outcome='timeout'; sock=close(sock); buffer=b''
        except EOFError:
            outcome='eof'; sock=close(sock); buffer=b''
        except ValueError:
            sock=close(sock); buffer=b''
        except OSError:
            outcome='connect' if sock is None else 'write'; sock=close(sock); buffer=b''
        end=time.monotonic_ns()
        item={'type':'request','client':client,'sequence':sequence,'scheduledNs':scheduled,'startNs':start,'endNs':end,
              'latencyNs':end-start,'success':success,'outcome':outcome,'connection':connection}
        with output_lock:
            results.append(item)
            print(json.dumps(item,separators=(',',':')), flush=True)
    close(sock)
threads=[threading.Thread(target=worker,args=(client,)) for client in range(clients)]
for thread in threads: thread.start()
for thread in threads: thread.join()
successes=sum(item['success'] for item in results)
print(json.dumps({'type':'summary','summary':True,'clients':clients,'requestsPerClient':per_client,'attempts':len(results),
                  'successes':successes,'failures':len(results)-successes,'intervalMs':interval_ms},separators=(',',':')), flush=True)
sys.exit(0 if len(results)==clients*per_client and successes==len(results) else 1)
PROBE_TRAFFIC
}


probe_datacenter()
{
   [[ "$#" -eq 7 && "${EUID}" -eq 0 ]] || return 2
   local workspace="$1"
   local address="$2"
   local port="$3"
   local payload="$4"
   local expected="$5"
   local timeout_ms="$6"
   local source_index="$7"
   valid_workspace "${workspace}" || return 2
   [[ "${address}" =~ ^[0-9A-Fa-f:.]+$ && "${port}" =~ ^[0-9]+$ && "${port}" -ge 1 && "${port}" -le 65535 ]] || return 2
   [[ "${#payload}" -le 4096 && "${#expected}" -le 4096 && "${timeout_ms}" =~ ^[0-9]+$ && "${timeout_ms}" -ge 1 && "${timeout_ms}" -le 60000 ]] || return 2

   local provider_pid=""
   provider_pid="$(<"${workspace}/virtual-datacenter.pid")"
   provider_process "${provider_pid}" "${workspace}" || return 1
   command -v ip >/dev/null
   command -v nsenter >/dev/null
   command -v timeout >/dev/null
   local runtime_identity=""
   runtime_identity="$(runtime_identity_for_workspace "${workspace}" "${provider_pid}")" || return 1
   local namespace="pvd-p-${runtime_identity}"
   if [[ "${source_index}" != "0" ]]
   then
      local -a machine_pids=()
      mapfile -t machine_pids < "${workspace}/virtual-datacenter.runtime"
      [[ "${source_index}" =~ ^[0-9]+$ && "${source_index}" -ge 1 && "${source_index}" -le "${#machine_pids[@]}" ]] || return 2
      namespace="pvd-m${source_index}-${runtime_identity}"
   fi
   local timeout_seconds=""
   printf -v timeout_seconds '%d.%03d' "$((timeout_ms / 1000))" "$((timeout_ms % 1000))"
   nsenter -t "${provider_pid}" -m -- ip netns exec "${namespace}" timeout "${timeout_seconds}" bash -c '
      exec 3<>"/dev/tcp/$1/$2"
      printf "%s\n" "$3" >&3
      [[ -n "$4" ]] || exit 0
      response=""
      IFS= read -r response <&3
      if [[ "$4" == contains:* ]]
      then
         required="${4#contains:}"
         IFS="|" read -r -a tokens <<< "${required}"
         for token in "${tokens[@]}"
         do
            [[ -n "${token}" && "${response}" == *"${token}"* ]] || exit 1
         done
      else
         [[ "${response}" == "$4" ]]
      fi
   ' _ "${address}" "${port}" "${payload}" "${expected}"
}

# Pair endpoints live in their own supervisor's mount namespace. The two VDC
# parent namespace handles are bound there; neither VDC owns the shared router.
pair_parse()
{
   [[ "$#" -ge 14 && "${EUID}" == 0 ]] || return 2
   pair_args=("${@:1:14}")
   pair_dir="$1"; pair_id="$2"; pair_source_uuid="$3"; pair_target_uuid="$4"
   pair_source_workspace="$5"; pair_source_runtime="$6"; pair_source_index="$7"; pair_source_ip="$8"
   pair_target_workspace="$9"; pair_target_runtime="${10}"; pair_target_index="${11}"; pair_target_ip="${12}"
   pair_vip="${13}"; pair_port="${14}"
   for identity in "$pair_id" "$pair_source_uuid" "$pair_target_uuid"; do
      [[ "$identity" =~ ^0x[0-9a-f]{2,32}$ && $(( ${#identity} % 2 )) == 0 && "${identity:2:2}" != 00 ]] || return 2
   done
   [[ "$pair_dir" == "/mnt/prodigy-vdc-pairs/$pair_id" && ! -L "$pair_dir" &&
      "$pair_source_uuid" != "$pair_target_uuid" && "$pair_source_runtime" != "$pair_target_runtime" &&
      "$pair_source_workspace" != "$pair_target_workspace" ]] || return 2
   valid_workspace "$pair_source_workspace" && valid_workspace "$pair_target_workspace" || return 2
   python3 - "$pair_source_runtime" "$pair_target_runtime" "$pair_source_index" "$pair_target_index" \
      "$pair_source_ip" "$pair_target_ip" "$pair_vip" "$pair_port" <<'PAIR_VALIDATE'
import ipaddress,sys
sr,tr,si,ti,source,target,vip,port=sys.argv[1:]
assert all(str(int(x))==x for x in (sr,tr,si,ti,port))
assert int(sr)>1 and int(tr)>1 and 1<=int(si)<=128 and 1<=int(ti)<=128 and 1<=int(port)<=65535
assert ipaddress.IPv4Address(source) in ipaddress.IPv4Network('10.0.0.0/8')
assert ipaddress.IPv4Address(target) in ipaddress.IPv4Network('10.0.0.0/8')
assert ipaddress.IPv4Address(vip) in ipaddress.IPv4Network('198.18.0.0/15')
PAIR_VALIDATE
}

pair_descriptor() { printf '%s\n' "${pair_args[@]}"; }

pair_write()
{
   local path="$1" value="$2" temporary="$1.$BASHPID.tmp"
   (umask 077; printf '%s\n' "$value" > "$temporary")
   sync -f "$temporary"
   mv -f -- "$temporary" "$path"
   sync -f "${path%/*}"
}

# Prospective guest-reset fences are strictly test-provider cleanup receipts.  A
# different kernel boot ID proves the old guest's kernel resources vanished; it
# never authorizes deletion against a new guest.
pair_descriptor_sha256()
{
   command -v sha256sum >/dev/null || return 1
   pair_descriptor | sha256sum | awk '{print $1}'
}

pair_guest_reset_identity_valid()
{
   local boot="$1" guest="$2"
   [[ "$boot" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
      "$boot" != 00000000-0000-0000-0000-000000000000 &&
      "$guest" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]
}

pair_guest_reset_identity()
{
   local boot guest
   [[ "${PRODIGY_DEV_TEST_BOUNDARY:-}" == apple-container && -r /proc/sys/kernel/random/boot_id ]] || return 1
   boot="$(</proc/sys/kernel/random/boot_id)"
   guest="${PRODIGY_DEV_APPLE_CONTAINER_ID:-}"
   pair_guest_reset_identity_valid "$boot" "$guest" || return 1
   printf '%s\t%s\n' "$boot" "$guest"
}

pair_workspace_lifecycle_lock_path()
{
   local digest
   digest="$(printf '%s' "$1" | sha256sum | awk '{print $1}')" || return 1
   [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
   printf '/run/prodigy-vdc-workspace-%s.lock\n' "$digest"
}

pair_lock_workspace()
{
   local workspace="$1" variable="$2" path fd
   path="$(pair_workspace_lifecycle_lock_path "$workspace")" || return 1
   exec {fd}>"$path" || return 1
   flock -n "$fd" || { eval "exec ${fd}>&-"; return 1; }
   printf -v "$variable" '%s' "$fd"
}

pair_unlock_workspace()
{
   local fd="$1"
   [[ "$fd" =~ ^[0-9]+$ ]] || return 1
   flock -u "$fd" || return 1
   eval "exec ${fd}>&-"
}

pair_workspace_fence_path()
{
   printf '%s/virtual-datacenter.pair-guest-reset\n' "$1"
}

pair_regular_root_receipt()
{
   local path="$1" uid mode
   [[ -f "$path" && ! -L "$path" ]] || return 1
   uid="$(stat -Lc %u "$path")"; mode="$(stat -Lc %a "$path")"
   [[ "$uid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
   (( (8#$mode & 022) == 0 ))
}

pair_receipt_exact()
{
   local path="$1" expected="$2"
   pair_regular_root_receipt "$path" || return 1
   python3 - "$path" "$expected" <<'PAIR_RECEIPT_EXACT'
import pathlib,sys
assert pathlib.Path(sys.argv[1]).read_bytes() == (sys.argv[2] + '\n').encode()
PAIR_RECEIPT_EXACT
}

pair_workspace_persisted_identity()
{
   local workspace="$1" runtime="$2" index="$3" address="$4"
   pair_regular_root_receipt "$workspace/virtual-datacenter.identity" &&
      pair_regular_root_receipt "$workspace/test-cluster-manifest.json" &&
      [[ "$(<"$workspace/virtual-datacenter.identity")" == "$runtime" ]] || return 1
   python3 - "$workspace/test-cluster-manifest.json" "$runtime" "$index" "$address" <<'PAIR_RESET_MANIFEST'
import json,sys
path,runtime,index,address=sys.argv[1:]
m=json.load(open(path, encoding='utf-8'))
assert m['parentNamespace']=='pvd-p-'+runtime
node=next(n for n in m['nodes'] if n['index']==int(index))
assert node['ipv4']==address and node['namespace']=='pvd-m'+index+'-'+runtime
PAIR_RESET_MANIFEST
}

pair_workspace_provider_dead()
{
   local workspace="$1" provider_pid=""
   [[ -r "$workspace/virtual-datacenter.pid" && ! -L "$workspace/virtual-datacenter.pid" ]] || return 1
   provider_pid="$(<"$workspace/virtual-datacenter.pid")"
   [[ "$provider_pid" =~ ^[0-9]+$ && "$provider_pid" -gt 1 ]] || return 1
   ! provider_process "$provider_pid" "$workspace"
}

pair_fence_text()
{
   local boot="$1" guest="$2" digest
   digest="$(pair_descriptor_sha256)" || return 1
   [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
   printf 'version=1\noperationID=%s\ndescriptorSHA256=%s\nbootID=%s\nguestID=%s\nsourceWorkspace=%s\nsourceRuntime=%s\ntargetWorkspace=%s\ntargetRuntime=%s\n' \
      "$pair_id" "$digest" "$boot" "$guest" "$pair_source_workspace" "$pair_source_runtime" "$pair_target_workspace" "$pair_target_runtime"
}

pair_fence_exact()
{
   local boot="$1" guest="$2" expected path
   expected="$(pair_fence_text "$boot" "$guest")" || return 1
   for path in "$pair_dir/guest-reset.fence" \
               "$(pair_workspace_fence_path "$pair_source_workspace")" \
               "$(pair_workspace_fence_path "$pair_target_workspace")"; do
      pair_receipt_exact "$path" "$expected" || return 1
   done
}

pair_fence_removed_exact()
{
   local boot="$1" guest="$2" expected workspace path
   expected="$(pair_fence_text "$boot" "$guest")" || return 1
   pair_receipt_exact "$pair_dir/guest-reset.fence" "$expected" || return 1
   for workspace in "$pair_source_workspace" "$pair_target_workspace"; do
      path="$(pair_workspace_fence_path "$workspace")"
      if [[ -e "$path" || -L "$path" ]]; then
         pair_receipt_exact "$path" "$expected" || return 1
      else
         # After phase=removed, one peer workspace may already have been
         # deleted by its receipt-gated stop.  An extant workspace may not
         # silently lose or replace its fence.
         [[ ! -e "$workspace" && ! -L "$workspace" ]] || return 1
      fi
   done
}

pair_workspace_reset_flagged()
{
   local path
   path="$(pair_workspace_fence_path "$1")"
   # Presence itself is a one-way startup/cleanup block.  Validation belongs
   # to arm/remove/stop and a malformed marker must never look absent.
   [[ -e "$path" || -L "$path" ]]
}

pair_arm_guest_reset()
{
   local identity boot guest expected source_fd="" target_fd="" first second
   [[ -f "$pair_dir/descriptor" && ! -L "$pair_dir/descriptor" && "$(pair_descriptor)" == "$(<"$pair_dir/descriptor")" ]] || return 1
   [[ -f "$pair_dir/phase" && ! -L "$pair_dir/phase" ]] || return 1
   [[ "$(<"$pair_dir/phase")" == prepared || "$(<"$pair_dir/phase")" == reset-required ]] || return 1
   identity="$(pair_guest_reset_identity)" || return 1
   IFS=$'\t' read -r boot guest <<<"$identity"
   [[ -n "$boot" && -n "$guest" ]] || return 1
   if [[ "$pair_source_workspace" < "$pair_target_workspace" ]]; then first="$pair_source_workspace"; second="$pair_target_workspace"; else first="$pair_target_workspace"; second="$pair_source_workspace"; fi
   pair_lock_workspace "$first" source_fd || return 1
   pair_lock_workspace "$second" target_fd || { pair_unlock_workspace "$source_fd"; return 1; }
   pair_owner_dead || { pair_unlock_workspace "$target_fd"; pair_unlock_workspace "$source_fd"; return 1; }
   pair_workspace_provider_dead "$pair_source_workspace" && pair_workspace_provider_dead "$pair_target_workspace" &&
      pair_workspace_persisted_identity "$pair_source_workspace" "$pair_source_runtime" "$pair_source_index" "$pair_source_ip" &&
      pair_workspace_persisted_identity "$pair_target_workspace" "$pair_target_runtime" "$pair_target_index" "$pair_target_ip" || {
      pair_unlock_workspace "$target_fd"; pair_unlock_workspace "$source_fd"; return 1; }
   expected="$(pair_fence_text "$boot" "$guest")" || { pair_unlock_workspace "$target_fd"; pair_unlock_workspace "$source_fd"; return 1; }
   # A partial same-boot arm is completed idempotently. Any different content,
   # including a boot change before commit, remains non-authoritative.
   for path in "$pair_dir/guest-reset.fence" \
               "$(pair_workspace_fence_path "$pair_source_workspace")" \
               "$(pair_workspace_fence_path "$pair_target_workspace")"; do
      if [[ -e "$path" || -L "$path" ]]; then
         if ! pair_receipt_exact "$path" "$expected"; then
            pair_unlock_workspace "$target_fd"; pair_unlock_workspace "$source_fd"; return 1
         fi
      else
         pair_write "$path" "$expected"
      fi
   done
   pair_fence_exact "$boot" "$guest" || { pair_unlock_workspace "$target_fd"; pair_unlock_workspace "$source_fd"; return 1; }
   pair_write "$pair_dir/phase" reset-required
   pair_fence_exact "$boot" "$guest" && [[ "$(<"$pair_dir/phase")" == reset-required ]] || {
      pair_unlock_workspace "$target_fd"; pair_unlock_workspace "$source_fd"; return 1; }
   pair_unlock_workspace "$target_fd"; pair_unlock_workspace "$source_fd"
   printf 'PAIR_GUEST_RESET operationID=%s descriptorSHA256=%s bootID=%s guestID=%s\n' \
      "$pair_id" "$(pair_descriptor_sha256)" "$boot" "$guest"
}

pair_guest_reset_absence_proven()
{
   local identity boot guest fenced_boot fenced_guest expected
   [[ -f "$pair_dir/phase" && "$(<"$pair_dir/phase")" == reset-required ]] || return 1
   pair_owner_dead || return 1
   identity="$(pair_guest_reset_identity)" || return 1
   IFS=$'\t' read -r boot guest <<<"$identity"
   [[ -n "$boot" && -n "$guest" ]] || return 1
   [[ -r "$pair_dir/guest-reset.fence" && ! -L "$pair_dir/guest-reset.fence" ]] || return 1
   fenced_boot="$(sed -n 's/^bootID=//p' "$pair_dir/guest-reset.fence")"
   fenced_guest="$(sed -n 's/^guestID=//p' "$pair_dir/guest-reset.fence")"
   [[ "$fenced_boot" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
      "$fenced_boot" != 00000000-0000-0000-0000-000000000000 &&
      "$fenced_guest" == "$guest" && "$boot" != "$fenced_boot" ]] || return 1
   pair_fence_exact "$fenced_boot" "$guest" || return 1
   pair_workspace_provider_dead "$pair_source_workspace" && pair_workspace_provider_dead "$pair_target_workspace" || return 1
   expected="$(pair_fence_text "$fenced_boot" "$guest")" || return 1
   local absence_text="${expected}"$'\n'"currentBootID=${boot}"
   pair_write "$pair_dir/guest-reset-absence" "$absence_text"
   pair_receipt_exact "$pair_dir/guest-reset-absence" "$absence_text" || return 1
   pair_reset_armed_boot="$fenced_boot"
   pair_reset_completed_boot="$boot"
   pair_reset_guest="$guest"
   pair_reset_descriptor_sha256="$(pair_descriptor_sha256)" || return 1
}

pair_guest_reset_completion_line()
{
   # Either create a receipt immediately after the first changed boot or replay
   # its retained completed boot after later reboots.  A later boot cannot
   # rewrite the operation-bound completion observation.
   local identity current guest armed expected absence_text completed phase
   phase="$(<"$pair_dir/phase")"
   if [[ "$phase" == reset-required ]]; then
      pair_guest_reset_absence_proven || return 1
   elif [[ "$phase" != removed ]]; then
      return 1
   fi
   identity="$(pair_guest_reset_identity)" || return 1
   IFS=$'\t' read -r current guest <<<"$identity"
   armed="$(sed -n 's/^bootID=//p' "$pair_dir/guest-reset.fence")"
   expected="$(pair_fence_text "$armed" "$guest")" || return 1
   if [[ "$phase" == reset-required ]]; then
      pair_fence_exact "$armed" "$guest" || return 1
   else
      pair_fence_removed_exact "$armed" "$guest" || return 1
   fi
   pair_regular_root_receipt "$pair_dir/guest-reset-absence" || return 1
   absence_text="$(<"$pair_dir/guest-reset-absence")"
   completed="$(sed -n 's/^currentBootID=//p' "$pair_dir/guest-reset-absence")"
   [[ "$armed" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
      "$armed" != 00000000-0000-0000-0000-000000000000 &&
      "$completed" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
      "$completed" != 00000000-0000-0000-0000-000000000000 &&
      "$completed" != "$armed" && "$current" != "$armed" &&
      "$absence_text" == "${expected}"$'\n'"currentBootID=${completed}" ]] || return 1
   pair_receipt_exact "$pair_dir/guest-reset-absence" "$absence_text" || return 1
   pair_reset_armed_boot="$armed"
   pair_reset_completed_boot="$completed"
   pair_reset_guest="$guest"
   pair_reset_descriptor_sha256="$(pair_descriptor_sha256)" || return 1
   printf 'PAIR_GUEST_RESET_COMPLETE operationID=%s descriptorSHA256=%s bootID=%s guestID=%s completedBootID=%s\n' \
      "$pair_id" "$pair_reset_descriptor_sha256" "$pair_reset_armed_boot" "$pair_reset_guest" "$pair_reset_completed_boot"
}

workspace_has_mountpoint_beneath()
{
   local workspace="$1" target inventory
   inventory="$(findmnt -rn -o TARGET)" || return 2
   while IFS= read -r target; do
      [[ "$target" == "$workspace" || "$target" == "$workspace/"* ]] && return 0
   done <<<"$inventory"
   return 1
}

workspace_reset_tombstone_cleanup()
{
   local workspace socket manifest
   workspace="$1"; socket="$2"; manifest="$workspace/test-cluster-manifest.json"
   # This is filesystem-only cleanup after a changed-boot receipt.  Python uses
   # dirfds/O_NOFOLLOW and refuses a live or ambiguous Unix socket pathname.
   pair_regular_root_receipt "$manifest" || return 1
   python3 - "$workspace" "$manifest" "$socket" <<'PAIR_RESET_TOMBSTONE'
import errno,json,os,pathlib,stat,sys
workspace,manifest_path,socket_path=sys.argv[1:]
manifest=json.loads(pathlib.Path(manifest_path).read_text(encoding='utf-8'))
assert manifest.get('workspaceRoot') == workspace
assert manifest.get('controlSocketPath') == socket_path
parent,name=os.path.split(socket_path)
assert name == 'mothership.sock' and parent and os.path.dirname(parent)

def safely_vanished(pid, error):
    if error.errno not in (errno.ENOENT, errno.ESRCH): return False
    proc=f'/proc/{pid}'
    try:
        stat_line=pathlib.Path(proc+'/stat').read_text(encoding='ascii').rstrip('\n')
    except OSError:
        return not os.path.exists(proc)
    try:
        state=stat_line.rsplit(') ',1)[1].split()[0]
    except (IndexError, ValueError):
        return False
    return state in ('Z','X','x') and not os.path.exists(proc+'/ns/net')

def no_live_socket():
    # Each active process namespace must be readable and structurally valid;
    # only a confirmed vanished/zombie process may disappear during scanning.
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit(): continue
        path=f'/proc/{entry.name}/net/unix'
        try:
            with open(path, encoding='ascii', errors='strict') as f:
                header=f.readline()
                if not header.startswith('Num       RefCount Protocol Flags    Type St Inode'):
                    raise RuntimeError('malformed /proc net/unix header')
                for line in f:
                    fields=line.rstrip('\n').split()
                    if len(fields) >= 8 and fields[-1] == socket_path:
                        return False
        except OSError as error:
            if safely_vanished(entry.name, error): continue
            raise
    return True

def root_private_directory(st):
    return stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o700

def root_socket(st):
    return stat.S_ISSOCK(st.st_mode) and st.st_uid == 0 and not (stat.S_IMODE(st.st_mode) & 0o022)

try:
    grand=os.path.dirname(parent); dirname=os.path.basename(parent)
    grandfd=os.open(grand, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
except FileNotFoundError:
    raise SystemExit(0) # parent directory already absent: idempotent retry.
try:
    try:
        dirfd=os.open(dirname, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=grandfd)
    except FileNotFoundError:
        raise SystemExit(0)
    try:
        before_dir=os.fstat(dirfd)
        assert root_private_directory(before_dir)
        entries=os.listdir(dirfd)
        if name in entries:
            assert entries == [name]
            before_socket=os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            assert root_socket(before_socket)
        else:
            assert entries == []
            before_socket=None
        assert no_live_socket()
        # Recheck both identities after the last live-socket observation.
        assert os.fstat(dirfd).st_dev == before_dir.st_dev and os.fstat(dirfd).st_ino == before_dir.st_ino
        if before_socket is not None:
            now=os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            assert now.st_dev == before_socket.st_dev and now.st_ino == before_socket.st_ino and root_socket(now)
            assert no_live_socket()
            os.unlink(name, dir_fd=dirfd)
        assert os.listdir(dirfd) == []
        parent_now=os.stat(dirname, dir_fd=grandfd, follow_symlinks=False)
        assert parent_now.st_dev == before_dir.st_dev and parent_now.st_ino == before_dir.st_ino and root_private_directory(parent_now)
        os.rmdir(dirname, dir_fd=grandfd)
    finally:
        os.close(dirfd)
finally:
    os.close(grandfd)
PAIR_RESET_TOMBSTONE
}

workspace_reset_only_cleanup()
{
   local workspace="$1" socket="$2" mount_status
   workspace_guest_reset_stop_safe "$workspace" || return 1
   # A reset receipt proves old kernel objects absent. This branch never names
   # retained PID/cgroup/netlink/mount targets; it may remove only a verified
   # stale filesystem socket tombstone through workspace_reset_tombstone_cleanup.
   if workspace_has_mountpoint_beneath "$workspace"; then
      return 1
   else
      mount_status=$?
      [[ "$mount_status" == 1 ]] || return 1
   fi
   workspace_reset_tombstone_cleanup "$workspace" "$socket" || return 1
   [[ -d "$workspace" && ! -L "$workspace" ]] || return 1
   rm -rf -- "$workspace"
}


workspace_guest_reset_stop_safe()
{
   local workspace="$1" path operation pair_path fence_boot guest current absence identity current_guest fence_text absence_text completed
   local -a descriptor_args=()
   path="$(pair_workspace_fence_path "$workspace")"
   pair_regular_root_receipt "$path" || return 1
   operation="$(sed -n 's/^operationID=//p' "$path")"
   fence_boot="$(sed -n 's/^bootID=//p' "$path")"
   guest="$(sed -n 's/^guestID=//p' "$path")"
   [[ "$operation" =~ ^0x[0-9a-f]{2,32}$ && "$fence_boot" =~ ^[0-9a-f-]{36}$ ]] || return 1
   pair_path="/mnt/prodigy-vdc-pairs/${operation}"
   [[ -d "$pair_path" && ! -L "$pair_path" && -r "$pair_path/phase" && "$(<"$pair_path/phase")" == removed &&
      -f "$pair_path/descriptor" && ! -L "$pair_path/descriptor" ]] || return 1
   mapfile -t descriptor_args < "$pair_path/descriptor"
   [[ "${#descriptor_args[@]}" == 14 ]] || return 1
   pair_parse "${descriptor_args[@]}" || return 1
   [[ "$pair_dir" == "$pair_path" && "$(pair_descriptor)" == "$(<"$pair_path/descriptor")" ]] || return 1
   [[ "$workspace" == "$pair_source_workspace" || "$workspace" == "$pair_target_workspace" ]] || return 1
   identity="$(pair_guest_reset_identity)" || return 1
   IFS=$'\t' read -r current current_guest <<<"$identity"
   [[ "$current_guest" == "$guest" && "$current" != "$fence_boot" ]] || return 1
   pair_fence_removed_exact "$fence_boot" "$guest" || return 1
   # The current workspace marker must be the exact bound copy selected by
   # this parsed descriptor; only an absent already-deleted peer is permitted.
   # descriptor, never merely a receipt with the same operation text.
   fence_text="$(pair_fence_text "$fence_boot" "$guest")" || return 1
   pair_receipt_exact "$path" "$fence_text" || return 1
   absence="$pair_path/guest-reset-absence"
   pair_regular_root_receipt "$absence" || return 1
   absence_text="$(<"$absence")"
   completed="$(sed -n 's/^currentBootID=//p' "$absence")"
   [[ "$completed" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
      "$completed" != 00000000-0000-0000-0000-000000000000 && "$completed" != "$fence_boot" &&
      "$absence_text" == "${fence_text}"$'\n'"currentBootID=${completed}" ]] || return 1
   pair_receipt_exact "$absence" "$absence_text"
}

pair_owner_live()
{
   [[ -f "$pair_dir/owner" && ! -L "$pair_dir/owner" ]] || return 1
   read -r pair_pid pair_start pair_mount < "$pair_dir/owner"
   [[ "$pair_pid" =~ ^[1-9][0-9]*$ && "$pair_pid" -gt 1 && -r "/proc/$pair_pid/stat" ]] || return 1
   local current
   current="$(awk '{sub(/^.*\) /, ""); print $20}' "/proc/$pair_pid/stat")"
   [[ "$current" == "$pair_start" && "$(stat -Lc %i "/proc/$pair_pid/ns/mnt")" == "$pair_mount" ]]
}

pair_owner_dead()
{
   local owner_pid owner_start owner_mount extra current
   [[ -e "$pair_dir/owner" ]] || return 0
   pair_regular_root_receipt "$pair_dir/owner" || return 1
   read -r owner_pid owner_start owner_mount extra < "$pair_dir/owner"
   [[ -z "$extra" && "$owner_pid" =~ ^[1-9][0-9]*$ && "$owner_pid" -gt 1 &&
      "$owner_start" =~ ^[0-9]+$ && "$owner_mount" =~ ^[0-9]+$ ]] || return 1
   [[ -r "/proc/$owner_pid/stat" && -e "/proc/$owner_pid/ns/mnt" ]] || return 0
   current="$(awk '{sub(/^.*\) /, ""); print $20}' "/proc/$owner_pid/stat")" || return 1
   [[ "$current" != "$owner_start" || "$(stat -Lc %i "/proc/$owner_pid/ns/mnt")" != "$owner_mount" ]]
}

pair_parent_identity()
{
   local workspace="$1" runtime="$2" index="$3" address="$4" provider_pid
   provider_pid="$(<"$workspace/virtual-datacenter.pid")"
   provider_process "$provider_pid" "$workspace" || return 1
   [[ "$(runtime_identity_for_workspace "$workspace" "$provider_pid")" == "$runtime" ]] || return 1
   python3 - "$workspace/test-cluster-manifest.json" "$runtime" "$index" "$address" <<'PAIR_PARENT' || return 1
import json,sys
path,runtime,index,address=sys.argv[1:]
m=json.load(open(path)); node=next(n for n in m['nodes'] if n['index']==int(index))
assert m['parentNamespace']=='pvd-p-'+runtime and node['ipv4']==address
assert node['namespace']=='pvd-m'+index+'-'+runtime
assert all(n['public6'].startswith('2001:db8:100:') for n in m['nodes'])
PAIR_PARENT
   printf '%s\n' "$provider_pid"
}

pair_rules()
{
   local mark="$1" current
   [[ "$mark" == 1 || "$mark" == 2 ]] || return 2
   # The map is the only selector. Replacing its element is one kernel
   # transaction; an already marked SYN retry retains its original owner.
   if ip netns exec pair-router nft list table inet prodigy_pair >/dev/null 2>&1; then
      current="$(pair_selected)"
      [[ "$current" != 2 || "$mark" == 2 ]] || return 1
      # nft batches both commands in one transaction; there is no exposed
      # interval with an empty map. Element replacement has no `replace` verb.
      printf 'delete element inet prodigy_pair owner { 0 }\nadd element inet prodigy_pair owner { 0 : %s }\n' "$mark" |
         ip netns exec pair-router nft -f -
      return
   fi
   ip netns exec pair-router nft -f - <<EOF_PAIR_NFT
table inet prodigy_pair {
 map owner { type mark : mark; elements = { 0 : $mark }; }
 chain prerouting {
  type filter hook prerouting priority mangle; policy accept;
  iifname "client0" ip daddr $pair_vip tcp dport $pair_port ct mark 0 ct state new ct mark set ct mark map @owner
  meta mark set ct mark
 }
 chain forward {
  type filter hook forward priority filter; policy drop;
  iifname "client0" oifname "source0" ip daddr $pair_vip tcp dport $pair_port ct mark 1 accept
  iifname "client0" oifname "target0" ip daddr $pair_vip tcp dport $pair_port ct mark 2 accept
  iifname "source0" oifname "client0" ip saddr $pair_vip tcp sport $pair_port ct mark 1 ct state established,related accept
  iifname "target0" oifname "client0" ip saddr $pair_vip tcp sport $pair_port ct mark 2 ct state established,related accept
 }
}
EOF_PAIR_NFT
}

pair_selected()
{
   ip netns exec pair-router nft -j list map inet prodigy_pair owner | python3 -c '
import json,sys
maps=[x["map"] for x in json.load(sys.stdin)["nftables"] if "map" in x]
assert len(maps)==1
entry=maps[0]["elem"]
def mark(value):
 assert isinstance(value,(int,str)) and not isinstance(value,bool)
 return int(value,0) if isinstance(value,str) else value
assert len(entry)==1 and len(entry[0])==2 and mark(entry[0][0])==0 and mark(entry[0][1]) in (1,2)
print(mark(entry[0][1]))'
}

pair_query()
{
   local selected counts
   selected="$(pair_selected)" || return 1
   # Conntrack's proc view is scoped to this namespace. Parsing failures and
   # unavailable accounting are errors, never evidence of zero source flows.
   counts="$(ip netns exec pair-router python3 - "$pair_vip" "$pair_port" <<'PAIR_COUNT'
import sys
vip,port=sys.argv[1:]; counts={1:0,2:0}
with open('/proc/net/nf_conntrack') as f:
 for line in f:
  fields=line.split(); original={}; mark=None
  for field in fields:
   if '=' not in field: continue
   key,value=field.split('=',1)
   if key=='mark': mark=int(value,0)
   elif key not in original: original[key]=value
  if original.get('src')=='172.30.240.2' and original.get('dst')==vip and original.get('dport')==port:
   assert 'tcp' in fields and mark in counts
   counts[mark]+=1
print(counts[1],counts[2])
PAIR_COUNT
)"
   local source target
   read -r source target <<< "$counts"
   printf 'PAIR_BOUNDARY operationID=%s sourceClusterUUID=%s targetClusterUUID=%s sourceRuntimeIdentity=%s targetRuntimeIdentity=%s sourceMachineIndex=%s targetMachineIndex=%s selected=%s drainCapability=1 sourceFlows=%s targetFlows=%s\n' \
      "$pair_id" "$pair_source_uuid" "$pair_target_uuid" "$pair_source_runtime" "$pair_target_runtime" \
      "$pair_source_index" "$pair_target_index" "$selected" "$source" "$target"
   [[ "${1:-query}" != drain || ( "$selected" == 2 && "$source" == 0 ) ]]
}

pair_link_identity()
{
   ip -n "$1" -j link show "$2" | python3 -c '
import json,sys
links=json.load(sys.stdin); assert len(links)==1
link=links[0]
assert link["ifindex"]>0 and link["link_index"]>0 and link["address"]
print(json.dumps([link["ifindex"],link["link_index"],link["address"]],separators=(",",":")))'
}

pair_link_owned()
{
   local side="$1" link="$2"
   if [[ -f "$pair_dir/$side-link" ]]; then
      [[ "$(pair_link_identity "pair-$side" "$link")" == "$(<"$pair_dir/$side-link")" ]]
      return
   fi
   # The peer MAC is journaled before creation. A crash between the move and
   # identity receipt cannot strand an unidentifiable link. This fallback is
   # valid only before any parent route effects were authorized.
   [[ -f "$pair_dir/$side-link-intent" && ! -f "$pair_dir/$side-route-intent" &&
      -z "$(ip -n "pair-$side" route show exact "$pair_vip/32")" &&
      -z "$(ip -n "pair-$side" route show exact 172.30.240.0/30)" ]] || return 1
   ip -n "pair-$side" -d -j link show "$link" | python3 -c '
import json,sys
links=json.load(sys.stdin); assert len(links)==1
assert links[0]["linkinfo"]["info_kind"]=="veth" and links[0]["address"]==sys.argv[1]
' "$(<"$pair_dir/$side-link-intent")"
}

# Return 0 only if a successful namespace inventory contains this exact link,
# 1 only if that successful inventory omits it, and 2 for any command or JSON
# error. A nonzero `ip link show <name>` alone is not evidence of teardown.
pair_link_presence()
{
   local namespace="$1" link="$2" inventory
   inventory="$(ip -n "$namespace" -j link show)" || return 2
   python3 -c '
import json,sys
try:
 links=json.loads(sys.stdin.read())
 assert isinstance(links,list)
 names=[]
 for item in links:
  assert isinstance(item,dict) and isinstance(item.get("ifname"),str) and item["ifname"]
  names.append(item["ifname"])
 assert len(names)==len(set(names))
except Exception:
 raise SystemExit(2)
raise SystemExit(0 if sys.argv[1] in names else 1)
' "$link" <<<"$inventory"
}

# A router namespace can be torn down asynchronously after its owner is
# SIGKILLed.  Its veth peer may therefore disappear between the first lookup
# and the identity read below.  Absence is safe; any link which still exists
# must prove the journaled identity before this owner deletes it.
pair_remove_owned_link()
{
   local side="$1" link="$2" presence
   if pair_link_presence "pair-$side" "$link"; then
      :
   else
      presence=$?
      [[ "$presence" == 1 ]] && return 0
      return 1
   fi
   if pair_link_owned "$side" "$link"; then
      if ip -n "pair-$side" link del "$link"; then return 0; fi
      # Do not turn a concurrent kernel peer teardown into a leaked boundary.
      if pair_link_presence "pair-$side" "$link"; then return 1; else
         presence=$?
         [[ "$presence" == 1 ]] && return 0
         return 1
      fi
   fi
   # A failed identity read is acceptable only when a *successful* inventory
   # immediately proves the link vanished. A lookup error remains fail-closed.
   if pair_link_presence "pair-$side" "$link"; then return 1; else
      presence=$?
      [[ "$presence" == 1 ]] && return 0
      return 1
   fi
}

pair_require_no_clients()
{
   # A probe may outlive the supervisor. Do not claim cleanup while a process
   # still owns either endpoint namespace. Inodes are recorded before exposure.
   python3 - "$pair_dir" <<'PAIR_NO_CLIENTS'
import errno,pathlib,sys
root=pathlib.Path(sys.argv[1]); inodes=set()
for name in ('router-network','client-network'):
 p=root/name
 if p.exists(): inodes.add(int(p.read_text().strip()))
for p in pathlib.Path('/proc').glob('[0-9]*/ns/net'):
 try: inode=p.stat().st_ino
 except OSError as e:
  if e.errno in (errno.ENOENT,errno.ESRCH): continue
  raise
 if inode in inodes: raise SystemExit('pair boundary still has an active client or router process')
PAIR_NO_CLIENTS
}

pair_cleanup_inside()
{
   pair_require_no_clients || return 1
   local status=0 side route_ip route_dev expected
   for side in source target; do
      route_ip="$pair_source_ip"; route_dev=pairSource0
      [[ "$side" == source ]] || { route_ip="$pair_target_ip"; route_dev=pairTarget0; }
      if [[ -e "/run/netns/pair-$side" ]]; then
         # Routes were added, never replaced; only this exact nexthop belongs
         # to the endpoint. Foreign changes are retained and reported.
         expected="$(ip -n "pair-$side" -o route show exact "$pair_vip/32")"
         if [[ -f "$pair_dir/$side-route-intent" && -n "$expected" ]]; then
            [[ "$expected" == "$pair_vip via $route_ip dev vdcbr0"* ]] || { status=1; continue; }
            ip -n "pair-$side" route del "$pair_vip/32" via "$route_ip" dev vdcbr0 || status=1
         fi
         if [[ -f "$pair_dir/$side-route-intent" && -f "$pair_dir/$side-forwarding" ]]; then
            ip netns exec "pair-$side" sysctl -q -w "net.ipv4.ip_forward=$(<"$pair_dir/$side-forwarding")" || status=1
         fi
      fi
   done
   # Deleting our router namespace drops its peer links and their connected
   # return routes; the retained parent namespace bindings then release.
   for name in pair-client pair-router; do
      if [[ -e "/run/netns/$name" ]]; then ip netns del "$name" || status=1; fi
   done
   for side in source target; do
      if [[ -e "/run/netns/pair-$side" ]]; then
         route_dev=pairSource0
         [[ "$side" == source ]] || route_dev=pairTarget0
         if ! pair_remove_owned_link "$side" "$route_dev"; then
            echo "pair boundary refuses changed $side peer link" >&2
            status=1
         fi
         umount "/run/netns/pair-$side" || status=1
      fi
   done
   [[ "$status" == 0 ]] && pair_write "$pair_dir/phase" removed
   return "$status"
}

pair_recover_remove()
{
   pair_parse "$@"
   [[ "$(pair_descriptor)" == "$(<"$pair_dir/descriptor")" ]]
   # A reset-required pair can only be closed after a new guest boot proves
   # its old kernel resources absent.  Do not bind or mutate stale namespaces.
   if [[ "$(<"$pair_dir/phase")" == reset-required ]]; then
      pair_guest_reset_completion_line >/dev/null || return 1
      pair_write "$pair_dir/phase" removed
      pair_guest_reset_completion_line
      return
   fi
   # Never race a still-live owner, including one which is still preparing.
   if pair_owner_live; then return 1; fi
   pair_require_no_clients
   mount --make-rprivate /
   mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs /run/netns
   local side workspace runtime index address provider_pid
   for side in source target; do
      # No journaled parent binding means no effects were issued in that parent.
      [[ -f "$pair_dir/$side-namespace" ]] || continue
      workspace="$pair_source_workspace"; runtime="$pair_source_runtime"; index="$pair_source_index"; address="$pair_source_ip"
      [[ "$side" == source ]] || { workspace="$pair_target_workspace"; runtime="$pair_target_runtime"; index="$pair_target_index"; address="$pair_target_ip"; }
      provider_pid="$(pair_parent_identity "$workspace" "$runtime" "$index" "$address")"
      touch "/run/netns/pair-$side"
      mount --bind "/proc/$provider_pid/root/run/netns/pvd-p-$runtime" "/run/netns/pair-$side"
      [[ "$(stat -Lc %i "/run/netns/pair-$side")" == "$(<"$pair_dir/$side-namespace")" ]]
   done
   pair_cleanup_inside
}

pair_serve()
{
   pair_parse "$@"
   [[ "$(pair_descriptor)" == "$(<"$pair_dir/descriptor")" ]]
   mount --make-rprivate /
   pair_write "$pair_dir/owner" "$$ $(awk '{sub(/^.*\) /, ""); print $20}' /proc/$$/stat) $(stat -Lc %i /proc/$$/ns/mnt)"
   # Private netns handles cannot disappear when the invoking CLI exits.
   mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs /run/netns
   trap 'pair_cleanup_inside || true' EXIT
   trap 'exit 0' TERM INT HUP
   local side workspace runtime index address provider_pid namespace_source
   for side in source target; do
      workspace="$pair_source_workspace"; runtime="$pair_source_runtime"; index="$pair_source_index"; address="$pair_source_ip"
      [[ "$side" == source ]] || { workspace="$pair_target_workspace"; runtime="$pair_target_runtime"; index="$pair_target_index"; address="$pair_target_ip"; }
      provider_pid="$(pair_parent_identity "$workspace" "$runtime" "$index" "$address")"
      namespace_source="/proc/$provider_pid/root/run/netns/pvd-p-$runtime"
      [[ -e "$namespace_source" ]]
      touch "/run/netns/pair-$side"
      mount --bind "$namespace_source" "/run/netns/pair-$side"
      pair_write "$pair_dir/$side-namespace" "$(stat -Lc %i "/run/netns/pair-$side")"
      # Refuse preexisting routes/interfaces before changing the parent.
      [[ -z "$(ip -n "pair-$side" route show exact "$pair_vip/32")" ]]
      [[ -z "$(ip -n "pair-$side" route show exact 172.30.240.0/30)" ]]
      local parent_link=pairSource0
      [[ "$side" == source ]] || parent_link=pairTarget0
      if ip -n "pair-$side" link show "$parent_link" >/dev/null 2>&1; then return 1; fi
      pair_write "$pair_dir/$side-forwarding" "$(ip netns exec "pair-$side" sysctl -n net.ipv4.ip_forward)"
      pair_write "$pair_dir/$side-link-intent" "$(python3 - "$pair_id" "$side" <<'PAIR_MAC'
import hashlib,sys
mac=b'\x02'+hashlib.sha256((sys.argv[1]+':'+sys.argv[2]).encode()).digest()[:5]
print(':'.join(f'{b:02x}' for b in mac))
PAIR_MAC
)"
   done
   ip netns add pair-router
   ip netns add pair-client
   pair_write "$pair_dir/router-network" "$(stat -Lc %i /run/netns/pair-router)"
   pair_write "$pair_dir/client-network" "$(stat -Lc %i /run/netns/pair-client)"
   ip -n pair-router link add client0 type veth peer name client-peer
   ip -n pair-router link set client-peer netns pair-client
   ip -n pair-client link set client-peer name client0
   ip -n pair-router link add source0 type veth peer name pairSource0 address "$(<"$pair_dir/source-link-intent")"
   ip -n pair-router link set pairSource0 netns pair-source
   pair_write "$pair_dir/source-link" "$(pair_link_identity pair-source pairSource0)"
   ip -n pair-router link add target0 type veth peer name pairTarget0 address "$(<"$pair_dir/target-link-intent")"
   ip -n pair-router link set pairTarget0 netns pair-target
   pair_write "$pair_dir/target-link" "$(pair_link_identity pair-target pairTarget0)"
   ip -n pair-client addr add 172.30.240.2/30 dev client0
   ip -n pair-client link set client0 up
   ip -n pair-client route add "$pair_vip/32" via 172.30.240.1 dev client0
   ip -n pair-router addr add 172.30.240.1/30 dev client0
   ip -n pair-router addr add 169.254.240.1/30 dev source0
   ip -n pair-router addr add 169.254.240.5/30 dev target0
   for link in client0 source0 target0; do ip -n pair-router link set "$link" up; done
   ip netns exec pair-router sysctl -q -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
   ip -n pair-router route add "$pair_vip/32" via 169.254.240.2 dev source0 table 101
   ip -n pair-router route add "$pair_vip/32" via 169.254.240.6 dev target0 table 102
   ip -n pair-router rule add priority 10001 to "$pair_vip/32" fwmark 1 lookup 101
   ip -n pair-router rule add priority 10002 to "$pair_vip/32" fwmark 2 lookup 102
   ip -n pair-source addr add 169.254.240.2/30 dev pairSource0
   ip -n pair-target addr add 169.254.240.6/30 dev pairTarget0
   for side in source target; do
      local link=pairSource0 gateway=169.254.240.1 selected_ip="$pair_source_ip"
      [[ "$side" == source ]] || { link=pairTarget0; gateway=169.254.240.5; selected_ip="$pair_target_ip"; }
      ip -n "pair-$side" link set "$link" up
      ip -n "pair-$side" route add 172.30.240.0/30 via "$gateway" dev "$link"
      pair_write "$pair_dir/$side-route-intent" "$pair_vip $selected_ip"
      ip -n "pair-$side" route add "$pair_vip/32" via "$selected_ip" dev vdcbr0
      ip netns exec "pair-$side" sysctl -q -w net.ipv4.ip_forward=1
   done
   pair_rules 1
   pair_write "$pair_dir/phase" prepared
   while [[ ! -e "$pair_dir/stop" ]]; do sleep 0.2; done
}

pair_action()
{
   local action="$1"; shift
   pair_parse "$@"
   # Admission is durable before provider creation. An absent operation
   # directory proves that no provider effect for this identity was issued.
   if [[ "$action" == remove && ! -e "$pair_dir" ]]; then return; fi
   [[ -r "$pair_dir/descriptor" && "$(pair_descriptor)" == "$(<"$pair_dir/descriptor")" ]]
   if [[ "$action" == armGuestReset ]]; then
      pair_arm_guest_reset
      return
   fi
   if [[ "$action" == remove && -f "$pair_dir/phase" && "$(<"$pair_dir/phase")" == removed ]]; then
      if [[ -e "$pair_dir/guest-reset-absence" || -L "$pair_dir/guest-reset-absence" ]]; then
         pair_guest_reset_completion_line
      else
         return 0
      fi
      return
   fi
   if [[ "$(<"$pair_dir/phase")" == reset-required ]]; then
      # No query, selection, probe, or crash can turn a reset fence into a
      # live pair.  A changed boot closes without entering a namespace or
      # touching any retained link/cgroup/socket identity.
      [[ "$action" == remove ]] || return 1
      pair_guest_reset_completion_line >/dev/null || return 1
      pair_write "$pair_dir/phase" removed
      pair_guest_reset_completion_line
      return
   fi
   if ! pair_owner_live; then
      [[ "$action" == remove ]] || return 1
      exec unshare --mount --propagation private -- bash "$0" --pair-recover-remove "$@"
   fi
   if [[ "$action" == remove ]]; then
      pair_require_no_clients
      pair_write "$pair_dir/stop" requested
      for _ in $(seq 1 100); do
         [[ "$(<"$pair_dir/phase")" != removed ]] || return 0
         sleep 0.1
      done
      return 1
   fi
   [[ "$(<"$pair_dir/phase")" == prepared ]]
   if [[ "$action" == crashOwner ]]; then
      python3 - "$pair_pid" "$pair_start" "$pair_mount" <<'PAIR_CRASH'
import os,pathlib,signal,sys
pid,start,mount=map(int,sys.argv[1:])
fd=os.pidfd_open(pid)
try:
 assert int(pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[19])==start
 assert pathlib.Path(f'/proc/{pid}/ns/mnt').stat().st_ino==mount
 signal.pidfd_send_signal(fd,signal.SIGKILL)
finally: os.close(fd)
PAIR_CRASH
      for _ in $(seq 1 100); do
         if ! pair_owner_live; then return 0; fi
         sleep 0.1
      done
      return 1
   fi
   exec nsenter -t "$pair_pid" -m -- bash "$0" --pair-inside "$action" "$@"
}

pair_inside()
{
   local action="$1"; shift
   pair_parse "$@"
   pair_owner_live
   [[ "$(stat -Lc %i /proc/self/ns/mnt)" == "$pair_mount" && "$(pair_descriptor)" == "$(<"$pair_dir/descriptor")" ]]
   case "$action" in
      query|drain) pair_query "$action" ;;
      selectTarget) pair_rules 2; pair_query ;;
      probe)
         [[ "$#" == 17 ]]
         ip netns exec pair-client timeout 60 python3 - "$pair_vip" "$pair_port" "${15}" "${16}" "${17}" <<'PAIR_PROBE'
import json,socket,sys,time
vip,port,expected,count,interval=sys.argv[1:]; count=int(count); interval=int(interval)
assert 1<=count<=1024 and 0<=interval<=60000 and (count-1)*interval<=50000
start=time.monotonic_ns()
with socket.create_connection((vip,int(port)),timeout=3) as s:
 s.settimeout(3); stream=s.makefile('rb')
 for seq in range(count):
  sent=time.monotonic_ns(); s.sendall(('identity:'+str(seq)+'\n').encode())
  reply=stream.readline(4097).decode().rstrip('\n')
  ok=reply.startswith('deploymentID='+expected+' containerUUID=') and reply.endswith(' request='+str(seq))
  print('PAIR_BOUNDARY_REQUEST '+json.dumps(dict(sequence=seq,reply=reply,ok=ok,sentNs=sent,receivedNs=time.monotonic_ns())),flush=True)
  assert ok
  if seq+1<count: time.sleep(interval/1000)
print('PAIR_BOUNDARY_CONNECTION '+json.dumps(dict(startNs=start,endNs=time.monotonic_ns(),requests=count)),flush=True)
PAIR_PROBE
         ;;
      *) return 2 ;;
   esac
}


# Pair-control transit is deliberately separate from the existing pair
# application boundary above.  Typed Mothership code selects and authorizes the
# two immutable rosters; this provider only binds those saved arguments to the
# two currently-live VDC parent namespaces.
pair_control_parse()
{
   [[ "$#" -eq 12 && "${EUID}" -eq 0 ]] || return 2
   pair_control_args=("$@")
   pair_control_id="$1"; pair_control_first_uuid="$2"; pair_control_second_uuid="$3"
   pair_control_first_workspace="$4"; pair_control_second_workspace="$5"
   pair_control_first_runtime="$6"; pair_control_second_runtime="$7"
   pair_control_first_subnet="$8"; pair_control_second_subnet="$9"
   pair_control_first_endpoints="${10}"; pair_control_second_endpoints="${11}"; pair_control_port="${12}"
   local identity
   for identity in "$pair_control_id" "$pair_control_first_uuid" "$pair_control_second_uuid"; do
      [[ "$identity" =~ ^0x[0-9a-f]{2,32}$ && $(( ${#identity} % 2 )) == 0 && "${identity:2:2}" != 00 ]] || return 2
   done
   [[ "$pair_control_first_uuid" != "$pair_control_second_uuid" &&
      "$pair_control_first_workspace" != "$pair_control_second_workspace" &&
      "$pair_control_first_runtime" != "$pair_control_second_runtime" ]] || return 2
   valid_workspace "$pair_control_first_workspace" && valid_workspace "$pair_control_second_workspace" || return 2
   if ! python3 - "$pair_control_first_runtime" "$pair_control_second_runtime" \
      "$pair_control_first_subnet" "$pair_control_second_subnet" \
      "$pair_control_first_endpoints" "$pair_control_second_endpoints" "$pair_control_port" <<'PAIR_CONTROL_PARSE'
import ipaddress,sys
first_runtime,second_runtime,first_subnet,second_subnet,first_csv,second_csv,port=sys.argv[1:]
assert all(str(int(x))==x and 1<int(x)<=2**64-1 for x in (first_runtime,second_runtime))
assert str(int(port))==port and int(port)==315
first_network=ipaddress.IPv6Network(first_subnet,strict=True)
second_network=ipaddress.IPv6Network(second_subnet,strict=True)
assert first_network.prefixlen==64 and second_network.prefixlen==64 and first_network!=second_network
assert first_network.with_prefixlen==first_subnet and second_network.with_prefixlen==second_subnet
def roster(value,network):
    items=value.split(',')
    assert 1<=len(items)<=16 and all(items)
    addresses=[ipaddress.IPv6Address(x) for x in items]
    assert [x.compressed for x in addresses]==items
    assert all(x in network and x!=network.network_address for x in addresses)
    assert len(set(addresses))==len(addresses) and addresses==sorted(addresses)
roster(first_csv,first_network); roster(second_csv,second_network)
PAIR_CONTROL_PARSE
   then
      return 2
   fi
   pair_control_dir="/mnt/prodigy-vdc-pair-control/$pair_control_id"
   [[ ! -L "$pair_control_dir" ]] || return 2
}

pair_control_descriptor() { printf '%s\n' "${pair_control_args[@]}"; }

pair_control_digest()
{
   command -v sha256sum >/dev/null || return 1
   pair_control_descriptor | sha256sum | awk '{print $1}'
}

pair_control_tag()
{
   local digest
   digest="$(pair_control_digest)" || return 1
   [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
   printf '%s\n' "${digest:0:10}"
}


pair_control_link_mac()
{
   local side="$1"
   python3 - "$(pair_control_digest)" "$side" <<'PAIR_CONTROL_MAC'
import hashlib,sys
mac=b'\x02'+hashlib.sha256((sys.argv[1]+':'+sys.argv[2]).encode()).digest()[:5]
print(':'.join(f'{byte:02x}' for byte in mac))
PAIR_CONTROL_MAC
}


# The manifest remains the provider's signed-by-ownership description of its
# own VDC.  The pair UUID is intentionally not inferred here: it is an
# authority-level relationship checked by the typed caller before it invokes us.
pair_control_parent_identity()
{
   local workspace="$1" runtime="$2" subnet="$3" endpoints="$4" provider_pid
   pair_regular_root_receipt "$workspace/virtual-datacenter.pid" &&
      pair_regular_root_receipt "$workspace/virtual-datacenter.identity" &&
      pair_regular_root_receipt "$workspace/test-cluster-manifest.json" || return 1
   provider_pid="$(<"$workspace/virtual-datacenter.pid")"
   provider_process "$provider_pid" "$workspace" || return 1
   [[ "$(runtime_identity_for_workspace "$workspace" "$provider_pid")" == "$runtime" ]] || return 1
   if ! python3 - "$workspace/test-cluster-manifest.json" "$workspace" "$runtime" "$subnet" "$endpoints" <<'PAIR_CONTROL_PARENT'
import ipaddress,json,sys
path,workspace,runtime,subnet,csv=sys.argv[1:]
m=json.load(open(path,encoding='utf-8'))
assert m['workspaceRoot']==workspace
assert m['parentNamespace']=='pvd-p-'+runtime
assert m['privateIPv6Subnet']==subnet
network=ipaddress.IPv6Network(subnet,strict=True)
manifest=[]
for node in m['nodes']:
    address=ipaddress.IPv6Address(node['private6'])
    assert address in network and address.compressed==node['private6']
    manifest.append(address)
assert len(manifest)==len(set(manifest))
requested=[ipaddress.IPv6Address(value) for value in csv.split(',')]
assert all(address in manifest for address in requested)
PAIR_CONTROL_PARENT
   then
      return 1
   fi
   printf '%s\n' "$provider_pid"
}

pair_control_lock_both()
{
   local first second
   if [[ "$pair_control_first_workspace" < "$pair_control_second_workspace" ]]; then
      first="$pair_control_first_workspace"; second="$pair_control_second_workspace"
   else
      first="$pair_control_second_workspace"; second="$pair_control_first_workspace"
   fi
   pair_lock_workspace "$first" pair_control_first_lock || return 1
   pair_lock_workspace "$second" pair_control_second_lock || {
      pair_unlock_workspace "$pair_control_first_lock"; return 1; }
}

pair_control_unlock_both()
{
   pair_unlock_workspace "$pair_control_second_lock" || return 1
   pair_unlock_workspace "$pair_control_first_lock"
}

pair_control_owner_live()
{
   local pair_dir="$pair_control_dir" pair_pid pair_start pair_mount
   pair_owner_live || return 1
   pair_control_pid="$pair_pid"; pair_control_start="$pair_start"; pair_control_mount="$pair_mount"
}

pair_control_owner_dead()
{
   local pair_dir="$pair_control_dir"
   pair_owner_dead
}

pair_control_link_owned()
{
   local side="$1" link="$2" receipt intent
   receipt="$pair_control_dir/$side-link"; intent="$pair_control_dir/$side-link-intent"
   if [[ -f "$receipt" && ! -L "$receipt" ]]; then
      [[ "$(pair_link_identity "pc-$side" "$link")" == "$(<"$receipt")" ]]
      return
   fi
   # An owner can die after the veth move but before recording its ifindex.
   # The prewritten, descriptor-bound peer MAC identifies only this incomplete
   # link, and only before a route made it externally reachable.
   [[ -f "$intent" && ! -L "$intent" && ! -f "$pair_control_dir/$side-route" ]] || return 1
   ip -n "pc-$side" -d -j link show "$link" | python3 -c '
import json,sys
links=json.load(sys.stdin); assert len(links)==1
link=links[0]
assert link["linkinfo"]["info_kind"]=="veth" and link["address"]==sys.argv[1]
' "$(<"$intent")"
}

pair_control_remove_owned_link()
{
   local side="$1" link="$2" present
   if pair_link_presence "pc-$side" "$link"; then :; else
      present=$?; [[ "$present" == 1 ]] && return 0; return 1
   fi
   pair_control_link_owned "$side" "$link" || return 1
   ip -n "pc-$side" link del "$link" || {
      if pair_link_presence "pc-$side" "$link"; then return 1; else
         present=$?; [[ "$present" == 1 ]] && return 0; return 1
      fi
   }
}

pair_control_addresses()
{
   local digest
   digest="$(pair_control_digest)" || return 1
   python3 - "$digest" "$pair_control_first_subnet" "$pair_control_second_subnet" <<'PAIR_CONTROL_ADDRESSES'
import ipaddress,sys
digest,first,second=sys.argv[1:]
assert len(digest)==64
# The operation digest supplies stable, high host bits in each existing VDC
# prefix.  The manifest validator rejects collisions with every current node.
def endpoint(prefix,offset):
    network=ipaddress.IPv6Network(prefix,strict=True)
    host=(int(digest[offset:offset+16],16) | (1<<63))
    host &= (1<<64)-1
    assert host not in (0,1)
    return ipaddress.IPv6Address(int(network.network_address)|host)
first_address=endpoint(first,0); second_address=endpoint(second,16)
assert first_address not in ipaddress.IPv6Network(second) and second_address not in ipaddress.IPv6Network(first)
print(f'{first_address}/64 {first_address} {second_address}/64 {second_address}')
PAIR_CONTROL_ADDRESSES
}

pair_control_cleanup_inside()
{
   local status=0 side other_subnet gateway link expected route
   for side in first second; do
      [[ -e "/run/netns/pc-$side" ]] || continue
      if [[ "$side" == first ]]; then other_subnet="$pair_control_second_subnet"; gateway="${pair_control_first_router:-}"; link="${pair_control_first_link:-}"; else other_subnet="$pair_control_first_subnet"; gateway="${pair_control_second_router:-}"; link="${pair_control_second_link:-}"; fi
      if [[ -e "$pair_control_dir/$side-route-intent" || -e "$pair_control_dir/$side-route" ]]; then
         [[ -f "$pair_control_dir/$side-route-intent" && ! -L "$pair_control_dir/$side-route-intent" && -n "$gateway" ]] || { status=1; continue; }
         expected="$(<"$pair_control_dir/$side-route-intent")"
         [[ "$expected" == "$other_subnet via $gateway dev vdcbr0" ]] || { status=1; continue; }
         if [[ -e "$pair_control_dir/$side-route" ]]; then
            [[ -f "$pair_control_dir/$side-route" && ! -L "$pair_control_dir/$side-route" && "$(<"$pair_control_dir/$side-route")" == "$expected" ]] || { status=1; continue; }
         fi
         route="$(ip -n "pc-$side" -o -6 route show exact "$other_subnet")" || { status=1; continue; }
         # A crash may occur after intent persistence and before route add.
         # Empty output is a completed no-op; any other route must exactly
         # match this operation's immutable intent before deletion.
         if [[ -n "$route" ]]; then
            [[ "$route" == "$expected" || "$route" == "$expected "* ]] || { status=1; continue; }
            ip -n "pc-$side" -6 route del "$other_subnet" via "$gateway" dev vdcbr0 || status=1
         fi
      fi
   done
   # The router is owned only by this supervisor's private mount namespace.
   if [[ -n "${pair_control_router_ns:-}" && -e "/run/netns/$pair_control_router_ns" ]]; then
      [[ -f "$pair_control_dir/router-namespace" && "$(stat -Lc %i "/run/netns/$pair_control_router_ns")" == "$(<"$pair_control_dir/router-namespace")" ]] || status=1
      [[ "$status" != 0 ]] || ip netns del "$pair_control_router_ns" || status=1
   fi
   for side in first second; do
      [[ -e "/run/netns/pc-$side" ]] || continue
      link="${pair_control_first_link:-}"; [[ "$side" == first ]] || link="${pair_control_second_link:-}"
      [[ -n "$link" ]] && pair_control_remove_owned_link "$side" "$link" || status=1
      umount "/run/netns/pc-$side" || status=1
   done
   [[ "$status" == 0 ]] && pair_write "$pair_control_dir/phase" removed
   return "$status"
}

pair_control_bind_parents()
{
   local side workspace runtime subnet endpoints provider_pid source inode
   for side in first second; do
      workspace="$pair_control_first_workspace"; runtime="$pair_control_first_runtime"; subnet="$pair_control_first_subnet"; endpoints="$pair_control_first_endpoints"
      [[ "$side" == first ]] || { workspace="$pair_control_second_workspace"; runtime="$pair_control_second_runtime"; subnet="$pair_control_second_subnet"; endpoints="$pair_control_second_endpoints"; }
      provider_pid="$(pair_control_parent_identity "$workspace" "$runtime" "$subnet" "$endpoints")" || return 1
      source="/proc/$provider_pid/root/run/netns/pvd-p-$runtime"
      [[ -e "$source" ]] || return 1
      touch "/run/netns/pc-$side"
      mount --bind "$source" "/run/netns/pc-$side" || return 1
      inode="$(stat -Lc %i "/run/netns/pc-$side")" || return 1
      if [[ -e "$pair_control_dir/$side-namespace" ]]; then
         [[ "$(<"$pair_control_dir/$side-namespace")" == "$inode" ]] || return 1
      else
         pair_write "$pair_control_dir/$side-namespace" "$inode"
      fi
   done
}

# A supervisor's retained bind mount is useful for in-owner cleanup, but it is
# not proof that the VDC currently selected by the descriptor is still live.
# Query therefore rebinds identity to the live provider and checks the exact
# saved namespace inode before reporting a usable carrier.
pair_control_current_parent_bound()
{
   local side="$1" workspace runtime subnet endpoints provider_pid source saved current
   workspace="$pair_control_first_workspace"; runtime="$pair_control_first_runtime"; subnet="$pair_control_first_subnet"; endpoints="$pair_control_first_endpoints"
   [[ "$side" == first ]] || { workspace="$pair_control_second_workspace"; runtime="$pair_control_second_runtime"; subnet="$pair_control_second_subnet"; endpoints="$pair_control_second_endpoints"; }
   provider_pid="$(pair_control_parent_identity "$workspace" "$runtime" "$subnet" "$endpoints")" || return 1
   source="/proc/$provider_pid/root/run/netns/pvd-p-$runtime"
   [[ -e "$source" && -f "$pair_control_dir/$side-namespace" && ! -L "$pair_control_dir/$side-namespace" ]] || return 1
   saved="$(<"$pair_control_dir/$side-namespace")"
   current="$(stat -Lc %i "$source")" || return 1
   [[ "$saved" == "$current" && "$(stat -Lc %i "/run/netns/pc-$side")" == "$saved" ]]
}

pair_control_bridge_mac()
{
   ip -n "pc-$1" -d -j link show vdcbr0 | python3 -c '
import json,re,sys
rows=json.load(sys.stdin)
assert len(rows)==1 and rows[0]["linkinfo"]["info_kind"]=="bridge"
mac=rows[0]["address"]
assert re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}",mac) and int(mac[:2],16)&1==0
print(mac)
'
}

pair_control_firewall_digest()
{
   # Counter changes are expected once the carrier is live; hash only the
   # policy and rule shape, not packet/byte counters.
   ip netns exec "$pair_control_router_ns" ip6tables-save |
      sed -E '/^#/d; s/\[[0-9]+:[0-9]+\]/[0:0]/g' | sha256sum | awk '{print $1}'
}

pair_control_firewall()
{
   local left right digest
   # The router namespace is new, but flush explicitly so the journaled digest
   # describes exactly the forwarding policy installed below.
   ip netns exec "$pair_control_router_ns" ip6tables -F
   ip netns exec "$pair_control_router_ns" ip6tables -P FORWARD DROP
   IFS=, read -r -a pair_control_first_endpoint_array <<< "$pair_control_first_endpoints"
   IFS=, read -r -a pair_control_second_endpoint_array <<< "$pair_control_second_endpoints"
   for left in "${pair_control_first_endpoint_array[@]}"; do for right in "${pair_control_second_endpoint_array[@]}"; do
      ip netns exec "$pair_control_router_ns" ip6tables -A FORWARD -i first0 -o second0 -s "$left" -d "$right" -p tcp --dport "$pair_control_port" -j ACCEPT
      ip netns exec "$pair_control_router_ns" ip6tables -A FORWARD -i second0 -o first0 -s "$right" -d "$left" -p tcp --dport "$pair_control_port" -j ACCEPT
   done; done
   ip netns exec "$pair_control_router_ns" ip6tables -A FORWARD -i first0 -o second0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
   ip netns exec "$pair_control_router_ns" ip6tables -A FORWARD -i second0 -o first0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
   # NDP is link-local to each VDC bridge and router interface. It never
   # traverses this router's FORWARD hook, so there is no broad ICMPv6 rule.
   digest="$(pair_control_firewall_digest)" || return 1
   [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
   pair_write "$pair_control_dir/firewall-digest" "$digest"
}

pair_control_serve()
{
   pair_control_parse "$@" || return
   [[ "$(pair_control_descriptor)" == "$(<"$pair_control_dir/descriptor")" ]] || return 1
   mount --make-rprivate /
   pair_write "$pair_control_dir/owner" "$$ $(awk '{sub(/^.*\) /, ""); print $20}' /proc/$$/stat) $(stat -Lc %i /proc/$$/ns/mnt)"
   mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs /run/netns
   pair_control_router_ns=""; pair_control_first_link=""; pair_control_second_link=""
   pair_control_first_router=""; pair_control_second_router=""
   trap 'pair_control_cleanup_inside || true' EXIT
   trap 'exit 0' TERM INT HUP
   pair_control_bind_parents || return 1
   local first_bridge_mac second_bridge_mac
   first_bridge_mac="$(pair_control_bridge_mac first)" || return 1
   second_bridge_mac="$(pair_control_bridge_mac second)" || return 1
   pair_write "$pair_control_dir/first-bridge-mac" "$first_bridge_mac"
   pair_write "$pair_control_dir/second-bridge-mac" "$second_bridge_mac"
   local tag addresses first_mac second_mac first_link_identity second_link_identity router_namespace_inode first_route_intent second_route_intent
   tag="$(pair_control_tag)" || return 1
   pair_control_router_ns="pc-r-$tag"
   pair_control_first_link="pc${tag}a"; pair_control_second_link="pc${tag}b"
   addresses="$(pair_control_addresses)" || return 1
   read -r pair_control_first_router_cidr pair_control_first_router pair_control_second_router_cidr pair_control_second_router <<< "$addresses" || return 1
   # No pair may reuse a node's private IPv6 identity.  This checks the live
   # manifest as well as the deterministic descriptor-derived router address.
   if ! python3 - "$pair_control_first_workspace/test-cluster-manifest.json" "$pair_control_second_workspace/test-cluster-manifest.json" "$pair_control_first_router" "$pair_control_second_router" <<'PAIR_CONTROL_ROUTER_UNIQUE'
import json,sys
first,second,first_router,second_router=sys.argv[1:]
all_addresses={n['private6'] for path in (first,second) for n in json.load(open(path))['nodes']}
assert first_router not in all_addresses and second_router not in all_addresses
PAIR_CONTROL_ROUTER_UNIQUE
   then
      return 1
   fi
   [[ -z "$(ip -n pc-first -o -6 route show exact "$pair_control_second_subnet")" && -z "$(ip -n pc-second -o -6 route show exact "$pair_control_first_subnet")" ]] || return 1
   ip netns add "$pair_control_router_ns"
   router_namespace_inode="$(stat -Lc %i "/run/netns/$pair_control_router_ns")" || return 1
   pair_write "$pair_control_dir/router-namespace" "$router_namespace_inode"
   first_mac="$(pair_control_link_mac first)" || return 1
   second_mac="$(pair_control_link_mac second)" || return 1
   pair_write "$pair_control_dir/first-link-intent" "$first_mac"
   pair_write "$pair_control_dir/second-link-intent" "$second_mac"
   ip -n "$pair_control_router_ns" link add first0 type veth peer name "$pair_control_first_link" address "$first_mac"
   ip -n "$pair_control_router_ns" link set "$pair_control_first_link" netns pc-first
   ip -n "$pair_control_router_ns" link add second0 type veth peer name "$pair_control_second_link" address "$second_mac"
   ip -n "$pair_control_router_ns" link set "$pair_control_second_link" netns pc-second
   ip -n pc-first link set "$pair_control_first_link" master vdcbr0
   ip -n pc-second link set "$pair_control_second_link" master vdcbr0
   first_link_identity="$(pair_link_identity pc-first "$pair_control_first_link")" || return 1
   second_link_identity="$(pair_link_identity pc-second "$pair_control_second_link")" || return 1
   pair_write "$pair_control_dir/first-link" "$first_link_identity"
   pair_write "$pair_control_dir/second-link" "$second_link_identity"
   ip -n "$pair_control_router_ns" -6 addr add "$pair_control_first_router_cidr" dev first0
   ip -n "$pair_control_router_ns" -6 addr add "$pair_control_second_router_cidr" dev second0
   # Install and journal the restrictive policy before either forwarding or a
   # cross-VDC route becomes live.
   pair_control_firewall || return 1
   ip -n "$pair_control_router_ns" link set first0 up
   ip -n "$pair_control_router_ns" link set second0 up
   ip -n pc-first link set "$pair_control_first_link" up
   ip -n pc-second link set "$pair_control_second_link" up
   # VDC parents are created with IPv6 forwarding already enabled.  It is
   # shared parent state, never toggled or restored by an individual pair.
   [[ "$(ip netns exec pc-first sysctl -n net.ipv6.conf.all.forwarding)" == 1 && "$(ip netns exec pc-second sysctl -n net.ipv6.conf.all.forwarding)" == 1 ]] || return 1
   ip netns exec "$pair_control_router_ns" sysctl -q -w net.ipv6.conf.all.forwarding=1
   first_route_intent="$pair_control_second_subnet via $pair_control_first_router dev vdcbr0"
   pair_write "$pair_control_dir/first-route-intent" "$first_route_intent"
   ip -n pc-first -6 route add "$pair_control_second_subnet" via "$pair_control_first_router" dev vdcbr0
   pair_write "$pair_control_dir/first-route" "$first_route_intent"
   second_route_intent="$pair_control_first_subnet via $pair_control_second_router dev vdcbr0"
   pair_write "$pair_control_dir/second-route-intent" "$second_route_intent"
   ip -n pc-second -6 route add "$pair_control_first_subnet" via "$pair_control_second_router" dev vdcbr0
   pair_write "$pair_control_dir/second-route" "$second_route_intent"
   pair_write "$pair_control_dir/phase" prepared
   while [[ ! -e "$pair_control_dir/stop" ]]; do sleep 0.2; done
}

pair_control_recover_remove()
{
   pair_control_parse "$@" || return
   [[ "$(pair_control_descriptor)" == "$(<"$pair_control_dir/descriptor")" ]] || return 1
   pair_control_owner_dead || return 1
   mount --make-rprivate /
   mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs /run/netns
   # Bind only a parent whose durable namespace identity still matches the
   # journal. A restarted/reused VDC is never a cleanup target.
   pair_control_bind_parents || return 1
   local tag
   tag="$(pair_control_tag)" || return 1
   pair_control_router_ns="pc-r-$tag"; pair_control_first_link="pc${tag}a"; pair_control_second_link="pc${tag}b"
   local addresses
   addresses="$(pair_control_addresses)" || return 1
   read -r _ pair_control_first_router _ pair_control_second_router <<< "$addresses" || return 1
   pair_control_cleanup_inside
}

pair_control_query_inside()
{
   [[ -f "$pair_control_dir/phase" && ! -L "$pair_control_dir/phase" && "$(<"$pair_control_dir/phase")" == prepared && ! -e "$pair_control_dir/stop" ]] || { echo "pair-control query rejected: phase" >&2; return 1; }
   [[ -f "$pair_control_dir/router-namespace" && ! -L "$pair_control_dir/router-namespace" &&
      -e "/run/netns/$pair_control_router_ns" &&
      "$(stat -Lc %i "/run/netns/$pair_control_router_ns")" == "$(<"$pair_control_dir/router-namespace")" ]] || { echo "pair-control query rejected: router-namespace" >&2; return 1; }
   pair_control_current_parent_bound first || { echo "pair-control query rejected: first-current-parent" >&2; return 1; }
   pair_control_current_parent_bound second || { echo "pair-control query rejected: second-current-parent" >&2; return 1; }
   local side bridge_mac
   for side in first second; do
      bridge_mac="$(pair_control_bridge_mac "$side")" || return 1
      [[ -f "$pair_control_dir/$side-bridge-mac" && ! -L "$pair_control_dir/$side-bridge-mac" &&
         "$bridge_mac" == "$(<"$pair_control_dir/$side-bridge-mac")" ]] || {
         echo "pair-control query rejected: $side-bridge-mac" >&2; return 1; }
   done
   pair_control_link_owned first "$pair_control_first_link" || { echo "pair-control query rejected: first-link" >&2; return 1; }
   pair_control_link_owned second "$pair_control_second_link" || { echo "pair-control query rejected: second-link" >&2; return 1; }
   [[ -f "$pair_control_dir/first-route-intent" && ! -L "$pair_control_dir/first-route-intent" &&
      -f "$pair_control_dir/first-route" && ! -L "$pair_control_dir/first-route" &&
      "$(<"$pair_control_dir/first-route-intent")" == "$pair_control_second_subnet via $pair_control_first_router dev vdcbr0" &&
      "$(<"$pair_control_dir/first-route")" == "$(<"$pair_control_dir/first-route-intent")" ]] || { echo "pair-control query rejected: first-route-journal" >&2; return 1; }
   [[ -f "$pair_control_dir/second-route-intent" && ! -L "$pair_control_dir/second-route-intent" &&
      -f "$pair_control_dir/second-route" && ! -L "$pair_control_dir/second-route" &&
      "$(<"$pair_control_dir/second-route-intent")" == "$pair_control_first_subnet via $pair_control_second_router dev vdcbr0" &&
      "$(<"$pair_control_dir/second-route")" == "$(<"$pair_control_dir/second-route-intent")" ]] || { echo "pair-control query rejected: second-route-journal" >&2; return 1; }
   [[ "$(ip -n pc-first -o -6 route show exact "$pair_control_second_subnet")" == "$(<"$pair_control_dir/first-route-intent")"* ]] || { echo "pair-control query rejected: first-route" >&2; return 1; }
   [[ "$(ip -n pc-second -o -6 route show exact "$pair_control_first_subnet")" == "$(<"$pair_control_dir/second-route-intent")"* ]] || { echo "pair-control query rejected: second-route" >&2; return 1; }
   [[ -f "$pair_control_dir/firewall-digest" && ! -L "$pair_control_dir/firewall-digest" &&
      "$(<"$pair_control_dir/firewall-digest")" =~ ^[0-9a-f]{64}$ &&
      "$(pair_control_firewall_digest)" == "$(<"$pair_control_dir/firewall-digest")" ]] || { echo "pair-control query rejected: firewall" >&2; return 1; }
   printf 'PAIR_CONTROL operationID=%s firstClusterUUID=%s secondClusterUUID=%s firstRuntimeIdentity=%s secondRuntimeIdentity=%s firstPrivate6Subnet=%s secondPrivate6Subnet=%s port=%s phase=prepared\n' \
      "$pair_control_id" "$pair_control_first_uuid" "$pair_control_second_uuid" "$pair_control_first_runtime" "$pair_control_second_runtime" "$pair_control_first_subnet" "$pair_control_second_subnet" "$pair_control_port"
}

pair_control_action()
{
   local action="$1"; shift
   [[ "$action" == query || "$action" == remove ]] || return 2
   pair_control_parse "$@" || return
   if [[ "$action" == remove && ! -e "$pair_control_dir" ]]; then return 0; fi
   [[ -r "$pair_control_dir/descriptor" && ! -L "$pair_control_dir/descriptor" && "$(pair_control_descriptor)" == "$(<"$pair_control_dir/descriptor")" &&
      -f "$pair_control_dir/phase" && ! -L "$pair_control_dir/phase" ]] || return 1
   pair_control_lock_both || return 1
   if [[ "$(<"$pair_control_dir/phase")" == removed ]]; then pair_control_unlock_both; [[ "$action" == remove ]]; return; fi
   if ! pair_control_owner_live; then
      pair_control_unlock_both
      [[ "$action" == remove ]] || return 1
      exec unshare --mount --propagation private -- bash "$0" --pair-control-recover-remove "$@"
   fi
   if [[ "$action" == remove ]]; then
      pair_write "$pair_control_dir/stop" requested
      pair_control_unlock_both
      for _ in $(seq 1 100); do [[ "$(<"$pair_control_dir/phase")" == removed ]] && return 0; sleep 0.1; done
      return 1
   fi
   pair_control_unlock_both
   exec nsenter -t "$pair_control_pid" -m -- bash "$0" --pair-control-inside "$@"
}

pair_control_inside()
{
   pair_control_parse "$@" || return
   pair_control_owner_live || { echo "pair-control query rejected: live-owner" >&2; return 1; }
   [[ "$(stat -Lc %i /proc/self/ns/mnt)" == "$pair_control_mount" && "$(pair_control_descriptor)" == "$(<"$pair_control_dir/descriptor")" ]] || { echo "pair-control query rejected: owner-mount-or-descriptor" >&2; return 1; }
   local tag
   tag="$(pair_control_tag)" || return 1
   pair_control_router_ns="pc-r-$tag"; pair_control_first_link="pc${tag}a"; pair_control_second_link="pc${tag}b"
   local addresses
   addresses="$(pair_control_addresses)" || return 1
   read -r _ pair_control_first_router _ pair_control_second_router <<< "$addresses" || return 1
   pair_control_query_inside
}

pair_control_launch()
{
   pair_control_parse "$@" || return
   command -v ip >/dev/null && command -v ip6tables >/dev/null && command -v ip6tables-save >/dev/null && command -v sha256sum >/dev/null && command -v sed >/dev/null || return 1
   mkdir -p -m 0700 /mnt/prodigy-vdc-pair-control
   [[ ! -L /mnt/prodigy-vdc-pair-control ]] || return 1
   pair_control_lock_both || return 1
   if [[ -d "$pair_control_dir" ]]; then
      [[ -r "$pair_control_dir/descriptor" && ! -L "$pair_control_dir/descriptor" && "$(pair_control_descriptor)" == "$(<"$pair_control_dir/descriptor")" && "$(<"$pair_control_dir/phase")" == prepared ]] || { pair_control_unlock_both; return 1; }
      pair_control_owner_live || { pair_control_unlock_both; return 1; }
      pair_control_unlock_both
      nsenter -t "$pair_control_pid" -m -- bash "$0" --pair-control-inside "$@"
      return
   fi
   mkdir -m 0700 "$pair_control_dir" || { pair_control_unlock_both; return 1; }
   pair_write "$pair_control_dir/descriptor" "$(pair_control_descriptor)"
   pair_write "$pair_control_dir/phase" preparing
   # Validate both bound parent identities before the detached supervisor can
   # create an interface in either namespace.
   pair_control_parent_identity "$pair_control_first_workspace" "$pair_control_first_runtime" "$pair_control_first_subnet" "$pair_control_first_endpoints" >/dev/null &&
      pair_control_parent_identity "$pair_control_second_workspace" "$pair_control_second_runtime" "$pair_control_second_subnet" "$pair_control_second_endpoints" >/dev/null || {
      pair_write "$pair_control_dir/phase" removed; pair_control_unlock_both; return 1; }
   pair_control_unlock_both
   setsid nohup unshare --mount --propagation private -- bash "$0" --pair-control-serve "$@" >"$pair_control_dir/provider.log" 2>&1 </dev/null &
   for _ in $(seq 1 100); do
      if [[ "$(<"$pair_control_dir/phase")" == prepared ]]; then pair_control_owner_live && return 0; fi
      [[ "$(<"$pair_control_dir/phase")" == removed ]] && break
      sleep 0.1
   done
   cat "$pair_control_dir/provider.log" >&2
   return 1
}

pair_launch()
{
   pair_parse "$@"
   [[ "$#" == 14 ]]
   pair_workspace_reset_flagged "$pair_source_workspace" && return 1
   pair_workspace_reset_flagged "$pair_target_workspace" && return 1
   mkdir -p -m 0700 /mnt/prodigy-vdc-pairs
   [[ ! -L /mnt/prodigy-vdc-pairs ]]
   if [[ -d "$pair_dir" ]]; then
      [[ -r "$pair_dir/descriptor" && "$(pair_descriptor)" == "$(<"$pair_dir/descriptor")" ]]
      pair_owner_live
      [[ "$(<"$pair_dir/phase")" == prepared ]]
      return
   fi
   mkdir -m 0700 "$pair_dir"
   pair_write "$pair_dir/descriptor" "$(pair_descriptor)"
   pair_write "$pair_dir/phase" preparing
   setsid nohup unshare --mount --propagation private -- bash "$0" --pair-serve "$@" >"$pair_dir/provider.log" 2>&1 </dev/null &
   for _ in $(seq 1 100); do
      if [[ "$(<"$pair_dir/phase")" == prepared ]]; then pair_owner_live; return; fi
      if [[ "$(<"$pair_dir/phase")" == removed ]]; then cat "$pair_dir/provider.log" >&2; return 1; fi
      sleep 0.1
   done
   cat "$pair_dir/provider.log" >&2
   return 1
}

stop_datacenter_locked()
{
   [[ "$#" -eq 2 && "${EUID}" -eq 0 ]] || return 2
   local workspace="$1"
   local control_socket_path="$2"
   command -v find >/dev/null
   command -v findmnt >/dev/null
   command -v flock >/dev/null
   command -v ip >/dev/null
   command -v realpath >/dev/null
   command -v seq >/dev/null
   command -v tr >/dev/null
   valid_workspace "${workspace}" && valid_control_socket_path "${control_socket_path}" || return 2
   if pair_workspace_reset_flagged "${workspace}"; then
      workspace_reset_only_cleanup "${workspace}" "${control_socket_path}"
      return
   fi
   local pid_path="${workspace}/virtual-datacenter.pid"
   local provider_pid="" runtime_identity="" retained_cgroup_root="" retained_scope=""
   [[ ! -r "${pid_path}" ]] || provider_pid="$(<"${pid_path}")"
   if [[ "${provider_pid}" =~ ^[0-9]+$ && "${provider_pid}" -gt 1 ]]
   then
      runtime_identity="$(runtime_identity_for_workspace "${workspace}" "${provider_pid}")" || return 1
      if provider_process "${provider_pid}" "${workspace}"
      then
         local provider_cgroup="$(cut -d: -f3 "/proc/${provider_pid}/cgroup")"
         [[ "${provider_cgroup}" == */prodigy-vdc-${runtime_identity}/provider ]] || return 1
         retained_cgroup_root="/sys/fs/cgroup${provider_cgroup%/provider}"
      elif [[ -r "${workspace}/virtual-datacenter.cgroup" ]]
      then
         retained_cgroup_root="$(<"${workspace}/virtual-datacenter.cgroup")"
      else
         echo "cannot resolve retained provider cgroup owner" >&2
         return 1
      fi
      valid_retained_cgroup_root "${retained_cgroup_root}" "${runtime_identity}" || return 1
      retained_scope="${retained_cgroup_root%/prodigy-vdc-${runtime_identity}}"
   fi
   if provider_process "${provider_pid}" "${workspace}"
   then
      kill -TERM -- "-${provider_pid}"
      for _ in $(seq 1 150)
      do
         provider_process "${provider_pid}" "${workspace}" || break
         sleep 0.2
      done
      provider_process "${provider_pid}" "${workspace}" && kill -KILL -- "-${provider_pid}"
   fi
   if [[ "${provider_pid}" =~ ^[0-9]+$ && "${provider_pid}" -gt 1 ]]
   then
      local cgroup_root="${retained_cgroup_root}"
      [[ ! -w "${cgroup_root}/cgroup.kill" ]] || printf '1\n' > "${cgroup_root}/cgroup.kill"
      for _ in $(seq 1 50)
      do
         find "${cgroup_root}" -depth -type d -exec rmdir {} \; >/dev/null 2>&1 || true
         [[ -d "${cgroup_root}" ]] || break
         sleep 0.02
      done
      [[ ! -d "${cgroup_root}" ]]
      ip link del "vdh${runtime_identity: -8}" >/dev/null 2>&1 || true
   fi
   [[ -z "${retained_scope}" ]] || restore_cgroup_scope_if_idle "${retained_scope}"
   rm -f -- "${control_socket_path}"
   rmdir -- "${control_socket_path%/*}" 2>/dev/null || true
   rm -rf -- "${workspace}"
}


stop_datacenter()
{
   [[ "$#" -eq 2 && "${EUID}" -eq 0 ]] || return 2
   local workspace="$1" lifecycle_fd="" status
   valid_workspace "${workspace}" || return 2
   pair_lock_workspace "${workspace}" lifecycle_fd || return 1
   stop_datacenter_locked "$@"; status=$?
   pair_unlock_workspace "$lifecycle_fd" || return 1
   return "$status"
}

launch_datacenter()
{
   [[ "$#" -eq 12 && "${EUID}" -eq 0 ]] || return 2
   local workspace="$1"
   local control_socket_path="${12}"
   valid_workspace "${workspace}" && valid_control_socket_path "${control_socket_path}" || return 2
   command -v nohup >/dev/null
   command -v realpath >/dev/null
   command -v setsid >/dev/null
   command -v tr >/dev/null
   # Hold the pre-fork slice under the same workspace flock.  Release before
   # spawning --serve so no lock descriptor crosses an exec boundary; --serve
   # reacquires it after its mount-namespace reexec before runtime effects.
   local lifecycle_fd=""
   pair_lock_workspace "${workspace}" lifecycle_fd || return 1
   if pair_workspace_reset_flagged "${workspace}"; then
      pair_unlock_workspace "$lifecycle_fd"
      return 1
   fi
   stop_datacenter_locked "${workspace}" "${control_socket_path}" || { pair_unlock_workspace "$lifecycle_fd"; return 1; }
   mkdir -p "${workspace%/*}" "${workspace}" || { pair_unlock_workspace "$lifecycle_fd"; return 1; }
   pair_unlock_workspace "$lifecycle_fd" || return 1
   setsid nohup bash "$0" --serve "$@" > "${workspace}/virtual-datacenter.log" 2>&1 < /dev/null &
}

adopted_mode=0
adopted_runtime_identity=""
adopted_operation_dir=""
case "${1:-}" in
   --pair-launch) shift; pair_launch "$@"; exit ;;
   --pair-serve) shift; pair_serve "$@"; exit ;;
   --pair-recover-remove) shift; pair_recover_remove "$@"; exit ;;
   --pair-action) shift; pair_action "$@"; exit ;;
   --pair-inside) shift; pair_inside "$@"; exit ;;
   --pair-control-launch) shift; pair_control_launch "$@"; exit ;;
   --pair-control-serve) shift; pair_control_serve "$@"; exit ;;
   --pair-control-recover-remove) shift; pair_control_recover_remove "$@"; exit ;;
   --pair-control-action) shift; pair_control_action "$@"; exit ;;
   --pair-control-inside) shift; pair_control_inside "$@"; exit ;;
   --bounded-log)
      shift
      bounded_machine_log "$@"
      ;;
   --enter-machine)
      shift
      enter_machine "$@"
      ;;
   --run-machine)
      shift
      run_machine "$@"
      ;;
   --launch)
      shift
      launch_datacenter "$@"
      exit
      ;;
   --stop)
      shift
      stop_datacenter "$@"
      exit
      ;;
   --fault)
      shift
      fault_datacenter "$@"
      exit
      ;;
   --probe)
      shift
      probe_datacenter "$@"
      exit
      ;;
   --probe-traffic)
      shift
      probe_traffic_datacenter "$@"
      exit
      ;;
   --serve-adopt)
      [[ "$#" -eq 15 ]] || { echo "serve-adopt requires runtime identity, operation directory, and original provider arguments" >&2; exit 2; }
      adopted_mode=1
      adopted_runtime_identity="$2"
      adopted_operation_dir="$3"
      shift 3
      ;;
   --serve)
      shift
      ;;
   *)
      echo "virtual datacenter provider requires --launch or --stop" >&2
      exit 2
      ;;
esac

if [[ "${adopted_mode}" -eq 0 && "${PRODIGY_VDC_MOUNT_NAMESPACE_READY:-0}" != "1" ]]
then
   export PRODIGY_VDC_MOUNT_NAMESPACE_READY=1
   exec unshare --mount --propagation private -- bash "$0" --serve "$@"
fi

if [[ "$#" -ne 12 || "${EUID}" -ne 0 ]]
then
   echo "virtual datacenter provider requires workspace, machine count, brain count, MTU, fake-boundary flag, host netns inode, machine resources, storage devices, and control socket as root" >&2
   exit 2
fi

workspace="$1"
machine_count="$2"
brain_count="$3"
inter_container_mtu="$4"
fake_boundary="$5"
host_netns_inode="$6"
machine_logical_cores="$7"
machine_memory_mb="$8"
machine_storage_mb="$9"
storage_device_count="${10}"
storage_device_mb="${11}"
control_socket_path="${12}"
datacenter_fragment="$(network_fragment_from_control_socket_path "${control_socket_path}")"
private_network_domain="$((datacenter_fragment - 1))"
private4_prefix="10.0.${private_network_domain}"
private4_subnet="${private4_prefix}.0/24"
private6_prefix="fd00:10"
if [[ "${private_network_domain}" -gt 0 ]]
then
   private6_prefix+=":$(printf '%x' "${private_network_domain}")"
fi
private6_subnet="${private6_prefix}::/64"

if ! valid_workspace "${workspace}" ||
   ! [[ "${machine_count}" =~ ^[0-9]+$ ]] || [[ "${machine_count}" -lt 1 || "${machine_count}" -gt 128 ]] ||
   ! [[ "${brain_count}" =~ ^[0-9]+$ ]] || [[ "${brain_count}" -lt 1 || "${brain_count}" -gt "${machine_count}" ]] ||
   ! [[ "${inter_container_mtu}" =~ ^[0-9]+$ ]] || [[ "${inter_container_mtu}" -lt 1280 || "${inter_container_mtu}" -gt 65495 ]] ||
   [[ "${fake_boundary}" != "0" && "${fake_boundary}" != "1" ]] ||
   ! [[ "${host_netns_inode}" =~ ^[0-9]+$ ]] || [[ "${host_netns_inode}" -eq 0 ]] ||
   ! [[ "${machine_logical_cores}" =~ ^[0-9]+$ ]] || [[ "${machine_logical_cores}" -lt 1 || "${machine_logical_cores}" -gt 65535 ]] ||
   ! [[ "${machine_memory_mb}" =~ ^[0-9]+$ ]] || [[ "${machine_memory_mb}" -lt 1 || "${machine_memory_mb}" -gt 16777216 ]] ||
   ! [[ "${machine_storage_mb}" =~ ^[0-9]+$ ]] || [[ "${machine_storage_mb}" -lt 1 || "${machine_storage_mb}" -gt 1048576 ]] ||
   ! [[ "${storage_device_count}" =~ ^[0-9]+$ ]] || [[ "${storage_device_count}" -gt 16 ]] ||
   ! [[ "${storage_device_mb}" =~ ^[0-9]+$ ]] || [[ "${storage_device_mb}" -lt 1 || "${storage_device_mb}" -gt 1048576 ]] ||
   ! valid_control_socket_path "${control_socket_path}"
then
   echo "invalid virtual datacenter provider arguments" >&2
   exit 2
fi

required=(btrfs find findmnt flock install ip mkfs.btrfs mount mountpoint mv python3 realpath rm rmdir seq setsid stat tr truncate umount unshare xargs)
[[ "${storage_device_count}" -eq 0 ]] || required+=(mkfs.ext4)
if [[ "${fake_boundary}" == "1" ]]
then
   required+=(bpftool ip6tables iptables sysctl tc)
fi
for command in "${required[@]}"
do
   command -v "${command}" >/dev/null || {
      echo "virtual datacenter provider requires ${command}" >&2
      exit 2
   }
done

if [[ "$(stat -Lc %i /proc/self/ns/net)" != "${host_netns_inode}" ]]
then
   echo "virtual datacenter provider did not start in the declared host network namespace" >&2
   exit 2
fi

# This is deliberately after the initial mount-namespace reexec.  It closes the
# launch/arm race until the provider has published its durable identity/runtime.
workspace_startup_lock_fd=""
pair_lock_workspace "${workspace}" workspace_startup_lock_fd || exit 1
if pair_workspace_reset_flagged "${workspace}"
then
   pair_unlock_workspace "${workspace_startup_lock_fd}"
   exit 1
fi

pid="$$"
runtime_identity="${pid}"
if [[ "${adopted_mode}" -eq 1 ]]
then
   [[ "${adopted_runtime_identity}" =~ ^[0-9]+$ && "${adopted_runtime_identity}" -gt 1 && -d "${adopted_operation_dir}" ]] || {
      echo "invalid adopted provider identity" >&2; exit 2;
   }
   runtime_identity="${adopted_runtime_identity}"
fi
underlay_mtu=$((inter_container_mtu + 40))
public_ingress_mtu=1500
parent_ns="pvd-p-${runtime_identity}"
filesystem_root="/mnt/prodigy-vdc-${runtime_identity}"
filesystem_image="${workspace}/virtual-datacenter.btrfs"
machine_bpffs_root="${filesystem_root}/machine-bpffs"
cgroup_scope=""
cgroup_control=""
cgroup_lock=""
cgroup_root=""
provisioned_path="${workspace}/virtual-datacenter.provisioned"
members_provisioned_path="${workspace}/virtual-datacenter.members-provisioned"
seed_runtime_path="${workspace}/virtual-datacenter.seed-runtime"
ready_path="${workspace}/virtual-datacenter.ready"
runtime_path="${workspace}/virtual-datacenter.runtime"
pid_path="${workspace}/virtual-datacenter.pid"
failure_path="${workspace}/virtual-datacenter.failure"
manifest_path="${workspace}/test-cluster-manifest.json"
boundary_lock="/run/prodigy-virtual-datacenter.boundary.lock"
boundary_bpffs="${workspace}/boundary-bpffs"
host_edge="vdh${runtime_identity: -8}"
parent_edge="vdp${runtime_identity: -8}"
child_names=()
machine_pids=()
machine_exit_held=()
storage_mounts=()
host_ipv4_forward=""
host_ipv6_forward=""
cleaned=0
adoption_committed=0
recovering_machine=0
recovery_operation_id=""
recovery_launch_started=0
recovery_failed=0
identity_path="${workspace}/virtual-datacenter.identity"

atomic_write()
{
   local path="$1"
   local temporary="${path}.${pid}.tmp"
   shift
   printf '%b' "$*" > "${temporary}"
   mv -f "${temporary}" "${path}"
}

machine_bpffs_path()
{
   local index="$1"
   [[ "${index}" =~ ^[1-9][0-9]*$ && "${index}" -le "${machine_count}" ]]
   printf '%s/machine%s\n' "${machine_bpffs_root}" "${index}"
}

valid_machine_bpffs()
{
   local index="$1"
   local path=""
   path="$(machine_bpffs_path "${index}")" || return 1
   [[ "${path}" == "${machine_bpffs_root}/machine${index}" && -d "${path}" && ! -L "${path}" ]] || return 1
   mountpoint -q "${path}" || return 1
   [[ "$(findmnt -n -o FSTYPE -T "${path}")" == "bpf" ]]
}

cleanup()
{
   local status="$?"
   if [[ "${cleaned}" -eq 1 ]]
   then
      return
   fi
   cleaned=1
   trap - ERR EXIT HUP INT TERM
   # Before C++ commits the matching operation receipt, this process has only
   # observed retained resources. Leaving must return sole ownership to the
   # frozen original supervisor without touching its roots, cgroups, or links.
   if [[ "${adopted_mode}" -eq 1 && "${adoption_committed}" -eq 0 ]]
   then
      exit "${status}"
   fi
   set +e

   for machine_pid in "${machine_pids[@]}"
   do
      kill -TERM -- "-${machine_pid}" >/dev/null 2>&1 || true
      kill -TERM "${machine_pid}" >/dev/null 2>&1 || true
   done
   sleep 0.2
   for machine_pid in "${machine_pids[@]}"
   do
      kill -KILL -- "-${machine_pid}" >/dev/null 2>&1 || true
      kill -KILL "${machine_pid}" >/dev/null 2>&1 || true
      wait "${machine_pid}" >/dev/null 2>&1 || true
   done

   if [[ "${fake_boundary}" == 1 ]]
   then
      iptables -D FORWARD -i "${host_edge}" ! -o "${host_edge}" -j ACCEPT >/dev/null 2>&1 || true
      iptables -D FORWARD ! -i "${host_edge}" -o "${host_edge}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || true
      iptables -t nat -D POSTROUTING ! -s 172.31.0.0/30 -d 198.18.0.0/16 -o "${host_edge}" -j SNAT --to-source 172.31.0.1 >/dev/null 2>&1 || true
      iptables -t nat -D POSTROUTING -s 172.31.0.2/32 ! -o "${host_edge}" -j MASQUERADE >/dev/null 2>&1 || true
      ip route del 198.18.0.0/16 via 172.31.0.2 dev "${host_edge}" >/dev/null 2>&1 || true
      ip route del "${private4_subnet}" via 172.31.0.2 dev "${host_edge}" >/dev/null 2>&1 || true
      ip6tables -D FORWARD -i "${host_edge}" ! -o "${host_edge}" -j ACCEPT >/dev/null 2>&1 || true
      ip6tables -D FORWARD ! -i "${host_edge}" -o "${host_edge}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || true
      ip6tables -t nat -D POSTROUTING -s 2602:fac0:0:12ab:34cd::/88 -j MASQUERADE >/dev/null 2>&1 || true
      ip6tables -t nat -D POSTROUTING -s fd00:31::2/128 -j MASQUERADE >/dev/null 2>&1 || true
      [[ -z "${host_ipv4_forward}" ]] || sysctl -q -w "net.ipv4.ip_forward=${host_ipv4_forward}" >/dev/null 2>&1 || true
      [[ -z "${host_ipv6_forward}" ]] || sysctl -q -w "net.ipv6.conf.all.forwarding=${host_ipv6_forward}" >/dev/null 2>&1 || true
      ip link del "${host_edge}" >/dev/null 2>&1 || true
      mountpoint -q "${boundary_bpffs}" && umount "${boundary_bpffs}" >/dev/null 2>&1 || true
      rm -rf "${boundary_bpffs}" "${boundary_lock}" >/dev/null 2>&1 || true
   fi

   for child_ns in "${child_names[@]}"
   do
      ip netns pids "${child_ns}" 2>/dev/null | xargs -r kill -KILL >/dev/null 2>&1 || true
      ip netns del "${child_ns}" >/dev/null 2>&1 || true
   done
   ip netns pids "${parent_ns}" 2>/dev/null | xargs -r kill -KILL >/dev/null 2>&1 || true
   ip netns del "${parent_ns}" >/dev/null 2>&1 || true

   for storage_mount in "${storage_mounts[@]}"
   do
      mountpoint -q "${storage_mount}" && umount "${storage_mount}" >/dev/null 2>&1 || true
   done
   for index in $(seq "${machine_count}" -1 1)
   do
      machine_bpffs="$(machine_bpffs_path "${index}")" || continue
      mountpoint -q "${machine_bpffs}" && umount "${machine_bpffs}" >/dev/null 2>&1 || true
   done
   mountpoint -q "${filesystem_root}" && umount "${filesystem_root}" >/dev/null 2>&1 || true
   rm -rf "${filesystem_root}" >/dev/null 2>&1 || true
   rm -f "${filesystem_image}" "${workspace}"/machine*.storage*.ext4 >/dev/null 2>&1 || true

   [[ -z "${cgroup_control}" || ! -w "${cgroup_control}/cgroup.procs" ]] || printf '%s\n' "${pid}" > "${cgroup_control}/cgroup.procs" 2>/dev/null || true
   [[ ! -e "${cgroup_root}/cgroup.kill" ]] || printf '1\n' > "${cgroup_root}/cgroup.kill" 2>/dev/null || true
   find "${cgroup_root}" -depth -type d -exec rmdir {} \; >/dev/null 2>&1 || true
   restore_cgroup_scope_if_idle
   rm -f "${ready_path}" "${seed_runtime_path}" "${runtime_path}" >/dev/null 2>&1 || true
   rm -f -- "${control_socket_path}" >/dev/null 2>&1 || true
   rmdir -- "${control_socket_path%/*}" >/dev/null 2>&1 || true
   exit "${status}"
}

failed()
{
   local status="$1"
   local line="$2"
   atomic_write "${failure_path}" "provider failed status=${status} line=${line}\n"
   exit "${status}"
}

trap 'failed "$?" "$LINENO"' ERR
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 129' HUP
trap 'exit 143' TERM

if [[ "${adopted_mode}" -eq 0 ]]
then
mkdir -p "${workspace}/boot" "${workspace}/transport-tls" "${filesystem_root}"
install -d -m 0700 "${control_socket_path%/*}"
rm -f "${provisioned_path}" "${members_provisioned_path}" "${seed_runtime_path}" "${ready_path}" "${runtime_path}" "${failure_path}" "${manifest_path}" "${control_socket_path}"
filesystem_size_bytes=$(( (machine_storage_mb * machine_count + 4096) * 1048576 ))
machine_memory_bytes=$(( machine_memory_mb * 1048576 ))
machine_storage_bytes=$(( machine_storage_mb * 1048576 ))
truncate -s "${filesystem_size_bytes}" "${filesystem_image}"
mkfs.btrfs -f "${filesystem_image}" >/dev/null
mount -o loop "${filesystem_image}" "${filesystem_root}"
mkdir -p "${filesystem_root}/machines" "${machine_bpffs_root}"
btrfs quota enable "${filesystem_root}"

prepare_cgroup_scope
cgroup_root="${cgroup_scope}/prodigy-vdc-${runtime_identity}"
mkdir -p "${cgroup_root}/provider"
for controller in cpuset cpu memory pids
do
   printf '+%s\n' "${controller}" > "${cgroup_root}/cgroup.subtree_control"
done
for index in $(seq 1 "${machine_count}")
do
   mkdir -p "${cgroup_root}/machine${index}" "${workspace}/machines/${index}/root"
   btrfs subvolume create "${filesystem_root}/machines/${index}" >/dev/null
   btrfs qgroup limit "${machine_storage_bytes}" "${filesystem_root}/machines/${index}"
   machine_bpffs="$(machine_bpffs_path "${index}")"
   mkdir -m 0700 "${machine_bpffs}"
   mount -t bpf bpf "${machine_bpffs}"
   valid_machine_bpffs "${index}"
   storage_root="${filesystem_root}/storage/${index}"
   mkdir -p "${storage_root}"
   for device in $(seq 1 "${storage_device_count}")
   do
      storage_mount="${storage_root}/${device}"
      storage_image="${workspace}/machine${index}.storage${device}.ext4"
      mkdir "${storage_mount}"
      truncate -s "$((storage_device_mb * 1048576))" "${storage_image}"
      mkfs.ext4 -F "${storage_image}" >/dev/null
      mount -o loop "${storage_image}" "${storage_mount}"
      storage_mounts+=("${storage_mount}")
   done
   printf '%s %s\n' "$((machine_logical_cores * 100000))" 100000 > "${cgroup_root}/machine${index}/cpu.max"
   printf '%s\n' "${machine_memory_bytes}" > "${cgroup_root}/machine${index}/memory.max"
   printf '%s\n' 32768 > "${cgroup_root}/machine${index}/pids.max"
done
printf '%s\n' "${pid}" > "${cgroup_root}/provider/cgroup.procs"

ip netns add "${parent_ns}"
ip netns exec "${parent_ns}" ip link set lo up
if [[ "$(ip netns exec "${parent_ns}" stat -Lc %i /proc/self/ns/net)" == "${host_netns_inode}" ]]
then
   echo "virtual datacenter parent namespace matches host" >&2
   exit 1
fi

ip netns exec "${parent_ns}" ip link add vdcbr0 type bridge
# Pin the generated address before any machine can cache this gateway. Linux
# otherwise chooses a member port's MAC again when a later transit joins.
bridge_mac="$(ip -n "${parent_ns}" -j link show vdcbr0 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["address"])')"
[[ "$bridge_mac" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]
ip -n "${parent_ns}" link set vdcbr0 address "$bridge_mac"
ip netns exec "${parent_ns}" ip link set dev vdcbr0 type bridge mcast_snooping 0
ip netns exec "${parent_ns}" ip link set vdcbr0 mtu "${underlay_mtu}" gso_max_size "${underlay_mtu}" gso_max_segs 1 gro_max_size "${underlay_mtu}" gso_ipv4_max_size "${underlay_mtu}" gro_ipv4_max_size "${underlay_mtu}"
ip netns exec "${parent_ns}" ip addr add "${private4_prefix}.1/24" dev vdcbr0
ip netns exec "${parent_ns}" ip -6 addr add "${private6_prefix}::1/64" nodad dev vdcbr0
if [[ "${fake_boundary}" == "1" ]]
then
   ip netns exec "${parent_ns}" ip -6 addr add 2602:fac0:0:12ab:ffff::1/64 nodad dev vdcbr0
else
   ip netns exec "${parent_ns}" ip -6 addr add 2001:db8:100::1/64 nodad dev vdcbr0
fi
ip netns exec "${parent_ns}" ip link set vdcbr0 up
# The VDC parent is the owned IPv6 router for its children and any authorized
# pair-control transit. Individual pair operations must never toggle this
# shared namespace setting or try to restore it during cleanup.
ip netns exec "${parent_ns}" sysctl -q -w net.ipv6.conf.all.forwarding=1

for index in $(seq 1 "${machine_count}")
do
   child_ns="pvd-m${index}-${pid}"
   parent_if="vp${index}"
   child_if="vc${index}"
   host_octet=$((9 + index))
   child_names+=("${child_ns}")
   ip netns add "${child_ns}"
   ip netns exec "${child_ns}" ip link set lo up
   ip netns exec "${parent_ns}" ip link add "${parent_if}" type veth peer name "${child_if}"
   ip netns exec "${parent_ns}" ip link set "${parent_if}" mtu "${underlay_mtu}" gso_max_size "${underlay_mtu}" gso_max_segs 1 gro_max_size "${underlay_mtu}" gso_ipv4_max_size "${underlay_mtu}" gro_ipv4_max_size "${underlay_mtu}"
   ip netns exec "${parent_ns}" ip link set "${parent_if}" master vdcbr0
   ip netns exec "${parent_ns}" ip link set "${parent_if}" up
   ip netns exec "${parent_ns}" ip link set "${child_if}" netns "${child_ns}"
   ip netns exec "${child_ns}" ip link set "${child_if}" name bond0
   ip netns exec "${child_ns}" ip link set bond0 mtu "${underlay_mtu}" gso_max_size "${underlay_mtu}" gso_max_segs 1 gro_max_size "${underlay_mtu}" gso_ipv4_max_size "${underlay_mtu}" gro_ipv4_max_size "${underlay_mtu}"
   ip netns exec "${child_ns}" ip link set bond0 up
   ip netns exec "${child_ns}" ip addr add "${private4_prefix}.${host_octet}/24" dev bond0
   ip netns exec "${child_ns}" ip -6 addr add "${private6_prefix}::$(printf '%x' "${host_octet}")/64" nodad dev bond0
   if [[ "${fake_boundary}" == "1" ]]
   then
      ip netns exec "${child_ns}" ip -6 addr add "2602:fac0:0:12ab:34cd::$(printf '%x' "${host_octet}")/64" nodad dev bond0
   else
      ip netns exec "${child_ns}" ip -6 addr add "2001:db8:100::$(printf '%x' "${host_octet}")/64" nodad dev bond0
   fi
   ip netns exec "${child_ns}" ip route replace default via "${private4_prefix}.1" dev bond0
   ip netns exec "${child_ns}" ip -6 route replace default via "${private6_prefix}::1" dev bond0
done

atomic_write "${pid_path}" "${pid}\n"
atomic_write "${identity_path}" "${runtime_identity}\n"
atomic_write "${workspace}/virtual-datacenter.cgroup" "${cgroup_root}\n"
atomic_write "${ready_path}" "parentNamespace=${parent_ns} machineCount=${machine_count} nBrains=${brain_count} logicalCores=${machine_logical_cores} memoryMB=${machine_memory_mb} storageMB=${machine_storage_mb} storageDeviceCount=${storage_device_count} storageDeviceMB=${storage_device_mb}\n"
while [[ ! -r "${provisioned_path}" ]]
do
   sleep 0.05
done
[[ -s "${provisioned_path}" ]]

if [[ "${fake_boundary}" == "1" ]]
then
   mkdir "${boundary_lock}"
   boundary_object="${workspace}/machines/1/root/prodigy/fake_ipv4_boundary_nat.ebpf.o"
   [[ -r "${boundary_object}" ]]
   mkdir -p "${boundary_bpffs}"
   mount -t bpf bpf "${boundary_bpffs}"
   mkdir -p "${boundary_bpffs}/programs"
   bpftool prog loadall "${boundary_object}" "${boundary_bpffs}/programs"
   [[ -r "${boundary_bpffs}/programs/fake_nat_eg" && -r "${boundary_bpffs}/programs/fake_nat_in" ]]

   ip link add "${host_edge}" type veth peer name "${parent_edge}"
   ip link set "${parent_edge}" netns "${parent_ns}"
   ip link set "${host_edge}" mtu "${underlay_mtu}" gso_max_size "${underlay_mtu}" gso_max_segs 1 gro_max_size "${underlay_mtu}" gso_ipv4_max_size "${underlay_mtu}" gro_ipv4_max_size "${underlay_mtu}"
   ip netns exec "${parent_ns}" ip link set "${parent_edge}" mtu "${underlay_mtu}" gso_max_size "${underlay_mtu}" gso_max_segs 1 gro_max_size "${underlay_mtu}" gso_ipv4_max_size "${underlay_mtu}" gro_ipv4_max_size "${underlay_mtu}"
   ip addr add 172.31.0.1/30 dev "${host_edge}"
   ip -6 addr add fd00:31::1/126 dev "${host_edge}"
   ip link set "${host_edge}" up
   ip route replace "${private4_subnet}" via 172.31.0.2 dev "${host_edge}"
   # This synthetic 1500-byte public boundary belongs only to deploymentMode=test; production clusters never execute this provider.
   ip route replace 198.18.0.0/16 via 172.31.0.2 dev "${host_edge}" mtu "${public_ingress_mtu}"
   ip netns exec "${parent_ns}" ip link set "${parent_edge}" up
   ip netns exec "${parent_ns}" ip addr add 172.31.0.2/30 dev "${parent_edge}"
   ip netns exec "${parent_ns}" ip -6 addr add fd00:31::2/126 dev "${parent_edge}"
   ip netns exec "${parent_ns}" ip route replace default via 172.31.0.1 dev "${parent_edge}"
   ip netns exec "${parent_ns}" ip -6 route replace default via fd00:31::1 dev "${parent_edge}"
   ip netns exec "${parent_ns}" ip route replace 198.18.0.0/16 via "${private4_prefix}.10" dev vdcbr0 src "${private4_prefix}.1" mtu "${public_ingress_mtu}"
   # Development host-public IPv4 leases encode the selected machine in the
   # low address byte.  Reply-flow state is learned by that machine's egress
   # program and is intentionally not replicated, so return traffic must go
   # back through the same machine rather than through the Brain catch-all.
   # Keep the /16 route for other synthetic routable-prefix traffic, while
   # installing more-specific routes for every machine-owned host-public IP.
   for index in $(seq 1 "${machine_count}")
   do
      host_octet=$((9 + index))
      ip netns exec "${parent_ns}" ip route replace \
         "198.18.0.${host_octet}/32" via "${private4_prefix}.${host_octet}" dev vdcbr0 \
         src "${private4_prefix}.1" mtu "${public_ingress_mtu}"
   done
   ip netns exec "${parent_ns}" ip -6 route replace 2602:fac0:0:12ab:34cd::/88 via "${private6_prefix}::a" dev vdcbr0
   ip netns exec "${parent_ns}" sysctl -q -w net.ipv4.ip_forward=1
   ip netns exec "${parent_ns}" sysctl -q -w net.ipv6.conf.all.forwarding=1
   ip netns exec "${parent_ns}" ip6tables -t nat -A POSTROUTING -s 2602:fac0:0:12ab:34cd::/88 -o "${parent_edge}" -j SNAT --to-source fd00:31::2

   host_ipv4_forward="$(sysctl -n net.ipv4.ip_forward)"
   host_ipv6_forward="$(sysctl -n net.ipv6.conf.all.forwarding)"
   atomic_write "${workspace}/virtual-datacenter.forwarding" "${host_ipv4_forward} ${host_ipv6_forward}\n"
   sysctl -q -w net.ipv4.ip_forward=1
   sysctl -q -w net.ipv6.conf.all.forwarding=1
   iptables -t nat -A POSTROUTING ! -s 172.31.0.0/30 -d 198.18.0.0/16 -o "${host_edge}" -j SNAT --to-source 172.31.0.1
   iptables -t nat -A POSTROUTING -s 172.31.0.2/32 ! -o "${host_edge}" -j MASQUERADE
   iptables -A FORWARD -i "${host_edge}" ! -o "${host_edge}" -j ACCEPT
   iptables -A FORWARD ! -i "${host_edge}" -o "${host_edge}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
   ip6tables -t nat -A POSTROUTING -s 2602:fac0:0:12ab:34cd::/88 -j MASQUERADE
   ip6tables -t nat -A POSTROUTING -s fd00:31::2/128 -j MASQUERADE
   ip6tables -A FORWARD -i "${host_edge}" ! -o "${host_edge}" -j ACCEPT
   ip6tables -A FORWARD ! -i "${host_edge}" -o "${host_edge}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
   ip netns exec "${parent_ns}" tc qdisc replace dev "${parent_edge}" clsact
   ip netns exec "${parent_ns}" tc filter replace dev "${parent_edge}" egress bpf da pinned "${boundary_bpffs}/programs/fake_nat_eg"
   ip netns exec "${parent_ns}" tc filter replace dev "${parent_edge}" ingress bpf da pinned "${boundary_bpffs}/programs/fake_nat_in"
fi
fi

start_machine()
{
   local index="$1"
   local child_ns="${child_names[$((index - 1))]}"
   local machine_root="${workspace}/machines/${index}"
   local containers_root="${filesystem_root}/machines/${index}"
   local storage_root="${filesystem_root}/storage/${index}"
   local machine_cgroup="${cgroup_root}/machine${index}"
   local boot_path="${workspace}/boot/${index}.json"
   local transport_tls_path="${workspace}/transport-tls/${index}.json"
   local log_path="${workspace}/machine${index}.log"
   local fake_ingress=""
   local machine_bpffs="$(machine_bpffs_path "${index}")"
   [[ "${fake_boundary}" != "1" ]] || fake_ingress="/root/prodigy/host.ingress.router.dev.ebpf.o"
   [[ -x "${machine_root}/root/prodigy/prodigy" && -r "${boot_path}" && -r "${transport_tls_path}" ]]
   valid_machine_bpffs "${index}"

   local -a enter_arguments=( "${machine_cgroup}" )
   if [[ "${index}" -eq "${recovering_machine}" && -n "${PRODIGY_VDC_RECOVERY_CGROUP_FD:-}" ]]
   then
      enter_arguments+=( "${PRODIGY_VDC_RECOVERY_CGROUP_FD}" )
   fi
   enter_arguments+=( "${workspace}" "${machine_root}" "${containers_root}" "${storage_root}" "${storage_device_count}" "${child_ns}" "${boot_path}" "${transport_tls_path}" "${host_netns_inode}" "${brain_count}" "${fake_ingress}" "${machine_bpffs}" )
   setsid bash "$0" --enter-machine "${enter_arguments[@]}" \
      > >(bash "$0" --bounded-log "${log_path}" 2 67108864 4194304) 2>&1 &
   machine_pids[$((index - 1))]="$!"
}

reset_machine_cgroup()
{
   local index="$1"
   local machine_cgroup="${cgroup_root}/machine${index}"
   [[ "${index}" =~ ^[0-9]+$ && "${index}" -ge 1 && "${index}" -le "${machine_count}" ]]
   [[ "${machine_cgroup}" == "${cgroup_root}"/machine* && -w "${machine_cgroup}/cgroup.kill" ]]

   printf '1\n' > "${machine_cgroup}/cgroup.kill"
   local child=""
   for _ in $(seq 1 100)
   do
      find "${machine_cgroup}" -mindepth 1 -depth -type d -exec rmdir {} \; >/dev/null 2>&1 || true
      child="$(find "${machine_cgroup}" -mindepth 1 -maxdepth 1 -type d -print -quit)"
      if [[ -z "${child}" && ! -s "${machine_cgroup}/cgroup.procs" ]]
      then
         local enabled=" $(<"${machine_cgroup}/cgroup.subtree_control") "
         local controller=""
         for controller in cpuset cpu memory pids
         do
            [[ "${enabled}" != *" ${controller} "* ]] || printf -- '-%s\n' "${controller}" > "${machine_cgroup}/cgroup.subtree_control"
         done
         return 0
      fi
      sleep 0.02
   done
   return 1
}

# A replacement runtime can only re-adopt live application processes through
# the authenticated recovery handoff. An ordinary fresh runtime has neither
# that checkpoint nor the retained container control context.
# Returns 0 for retained processes, 1 only for a populated=0 cgroup, and 2
# when the kernel's authoritative cgroup event state cannot be read safely.
machine_application_container_state()
{
   local index="$1"
   local events_path="${cgroup_root}/machine${index}/cgroup.events"
   local key="" value="" extra="" populated=""
   [[ "${index}" =~ ^[0-9]+$ && "${index}" -ge 1 && "${index}" -le "${machine_count}" ]] || return 2
   [[ -r "${events_path}" ]] || return 2
   while read -r key value extra
   do
      [[ "${key}" == "populated" ]] || continue
      [[ -z "${populated}" && "${value}" =~ ^[01]$ && -z "${extra}" ]] || return 2
      populated="${value}"
   done < "${events_path}"
   [[ -n "${populated}" ]] || return 2
   if [[ "${populated}" == "1" ]]
   then
      return 0
   fi
   return 1
}

machine_exit_is_held()
{
   local index="$1"
   [[ "${machine_exit_held[$((index - 1))]:-0}" -ne 0 &&
      ! -e "${workspace}/fault-machine-${index}" &&
      ! -e "${workspace}/fault-machine-reset-${index}" ]]
}

hold_unexpected_runtime_exit()
{
   local index="$1"
   local machine_pid="$2"
   local reason="$3"
   machine_exit_held[$((index - 1))]=1
   printf 'MOTHERSHIP_RUNTIME_EXIT_HOLD epoch=%(%s)T machine=%s pid=%s reason=%s\n' \
      -1 "${index}" "${machine_pid}" "${reason}" >>"${workspace}/machine-exits.log" || true
}

handle_machine_exit()
{
   local index="$1"
   local machine_pid="$2"
   local application_state=0
   local reset_marker="${workspace}/fault-machine-reset-${index}"
   local reset_pid="" reset_extra=""
   # A current marker keeps the explicit fault in progress. A reset marker is
   # durable authorization to finish its deliberate whole-machine teardown.
   [[ -e "${workspace}/fault-machine-${index}" ]] && return 0
   if [[ -e "${reset_marker}" ]]
   then
      if read -r reset_pid reset_extra < "${reset_marker}" &&
         [[ "${reset_pid}" =~ ^[0-9]+$ && -z "${reset_extra}" && "${reset_pid}" == "${machine_pid}" ]]
      then
         reset_machine_cgroup "${index}"
         start_machine "${index}"
         publish_runtime
         rm -f "${reset_marker}"
         machine_exit_held[$((index - 1))]=0
         return 0
      fi
      # A delayed fault may outlive the failed runtime it targeted. It cannot
      # authorize tearing down a later runtime or its retained applications.
      printf 'MOTHERSHIP_RUNTIME_FAULT_RESET_STALE epoch=%(%s)T machine=%s observedPid=%s ticketPid=%s\n' \
         -1 "${index}" "${machine_pid}" "${reset_pid}" >>"${workspace}/machine-exits.log" || true
      rm -f "${reset_marker}"
   fi
   if machine_application_container_state "${index}"
   then
      application_state=0
   else
      application_state=$?
   fi
   if [[ "${application_state}" -eq 0 ]]
   then
      hold_unexpected_runtime_exit "${index}" "${machine_pid}" "retained-machine-cgroup-populated"
      return 0
   fi
   if [[ "${application_state}" -ne 1 ]]
   then
      hold_unexpected_runtime_exit "${index}" "${machine_pid}" "machine-cgroup-state-unavailable"
      return 0
   fi
   reset_machine_cgroup "${index}"
   start_machine "${index}"
   publish_runtime
}

start_initial_runtime()
{
   # Mothership publishes canonical seed material first.  Followers are not
   # allowed to create an unowned identity while the seed is being configured.
   start_machine 1
   printf '%s\n' "${machine_pids[0]}" > "${seed_runtime_path}.${pid}.tmp"
   mv -f "${seed_runtime_path}.${pid}.tmp" "${seed_runtime_path}"
   if [[ "${machine_count}" -gt 1 ]]
   then
      while [[ ! -r "${members_provisioned_path}" ]]
      do
         sleep 0.05
      done
      [[ "$(<"${members_provisioned_path}")" == "members" ]] || return 1
      for index in $(seq 2 "${machine_count}")
      do
         start_machine "${index}"
         sleep 0.25
      done
   fi
}

if [[ "${adopted_mode}" -eq 0 ]]
then
   start_initial_runtime
else
   # Retained cgroup membership and the runtime receipt are the adoption source
   # of truth: application processes may have been reparented after worker exit.
   old_provider_pid="$(<"${pid_path}")"
   [[ "${old_provider_pid}" =~ ^[0-9]+$ && -r "/proc/${old_provider_pid}/cgroup" ]] || failed 1 "$LINENO"
   old_provider_cgroup="$(cut -d: -f3 "/proc/${old_provider_pid}/cgroup")"
   [[ "${old_provider_cgroup}" == */prodigy-vdc-${runtime_identity}/provider ]] || failed 1 "$LINENO"
   cgroup_root="/sys/fs/cgroup${old_provider_cgroup%/provider}"
   cgroup_scope="${cgroup_root%/prodigy-vdc-${runtime_identity}}"
   cgroup_control="${cgroup_scope}/prodigy-vdc-control"
   cgroup_lock="/run/prodigy-vdc-cgroup-$(stat -Lc %i "${cgroup_scope}").lock"
   [[ -d "${filesystem_root}" && -r "${runtime_path}" && -d "${cgroup_root}" && -d "${cgroup_scope}" && -d "${cgroup_control}" && -w "${cgroup_root}/provider/cgroup.procs" ]] || failed 1 "$LINENO"
   mapfile -t machine_pids < "${runtime_path}"
   [[ "${#machine_pids[@]}" -eq "${machine_count}" ]] || failed 1 "$LINENO"
   if [[ -r "${workspace}/virtual-datacenter.forwarding" ]]
   then
      read -r host_ipv4_forward host_ipv6_forward < "${workspace}/virtual-datacenter.forwarding"
      [[ "${host_ipv4_forward}" =~ ^[01]$ && "${host_ipv6_forward}" =~ ^[01]$ ]] || failed 1 "$LINENO"
   else
      # Legacy providers have no observable baseline; cleanup deliberately leaves it unchanged.
      host_ipv4_forward=""; host_ipv6_forward=""
   fi
   for index in $(seq 1 "${machine_count}")
   do
      child_names+=("pvd-m${index}-${runtime_identity}")
      [[ -d "${cgroup_root}/machine${index}" && -d "${filesystem_root}/machines/${index}" ]] || failed 1 "$LINENO"
      # The adoption process enters the original provider mount namespace. A
      # machine's bpffs is a host resource in that namespace, never a worker
      # process resource; do not publish an adopter that would create new maps.
      valid_machine_bpffs "${index}" || failed 1 "$LINENO"
      for device in $(seq 1 "${storage_device_count}")
      do
         storage_mounts+=("${filesystem_root}/storage/${index}/${device}")
      done
   done
fi

if [[ "${adopted_mode}" -eq 1 ]]
then
   selected_path="${adopted_operation_dir}/selected-machine"
   [[ -r "${selected_path}" ]] || failed 1 "$LINENO"
   recovering_machine="$(<"${selected_path}")"
   [[ "${recovering_machine}" =~ ^[1-9][0-9]*$ && "${recovering_machine}" -le "${machine_count}" ]] || failed 1 "$LINENO"
   # Ready is written before PID/manifest publication and before any worker or
   # root mutation. C++ binds all four values to its durable operation record.
   start_time="$(awk '{print $22}' /proc/$$/stat)"
   mount_namespace="$(stat -Lc %i /proc/$$/ns/mnt)"
   ready_path_for_operation="${adopted_operation_dir}/ready"
   ready_temporary="${ready_path_for_operation}.${pid}.tmp"
   printf "%s %s %s %s\n" "${pid}" "${start_time}" "${mount_namespace}" "${runtime_identity}" > "${ready_temporary}"
   mv -f "${ready_temporary}" "${ready_path_for_operation}"
   commit_path="${adopted_operation_dir}/commit"
   operation_id="${adopted_operation_dir##*/}"
   recovery_operation_id="${operation_id}"
   while [[ ! -r "${commit_path}" || "$(<"${commit_path}")" != "${operation_id}" ]]
   do
      sleep 0.05
   done
   # The committed adopter becomes the real provider process in the retained
   # provider cgroup. This is intentionally after the precommit receipt.
   printf "%s\n" "${pid}" > "${cgroup_root}/provider/cgroup.procs"
   atomic_write "${pid_path}" "${pid}\n"
   atomic_write "${identity_path}" "${runtime_identity}\n"
atomic_write "${workspace}/virtual-datacenter.cgroup" "${cgroup_root}\n"
   adoption_committed=1
fi

publish_runtime()
{
   local index host_octet role public6
{
   printf '{"workspaceRoot":"%s","manifestPath":"%s","controlSocketPath":"%s","parentNamespace":"%s","parentPid":%s,"datacenterFragment":%s,"privateIPv4Subnet":"%s","privateIPv6Subnet":"%s","machineCount":%s,"brainCount":%s,"machineLogicalCores":%s,"machineMemoryMB":%s,"machineStorageMB":%s,"storageDeviceCount":%s,"storageDeviceMB":%s,"interContainerMTU":%s,"leaderIndex":0,"leaderNamespace":"","nodes":[' \
      "${workspace}" "${manifest_path}" "${control_socket_path}" "${parent_ns}" "${pid}" "${datacenter_fragment}" "${private4_subnet}" "${private6_subnet}" "${machine_count}" "${brain_count}" "${machine_logical_cores}" "${machine_memory_mb}" "${machine_storage_mb}" "${storage_device_count}" "${storage_device_mb}" "${inter_container_mtu}"
   for index in $(seq 1 "${machine_count}")
   do
      [[ "${index}" -eq 1 ]] || printf ','
      host_octet=$((9 + index))
      role="neuron"
      [[ "${index}" -gt "${brain_count}" ]] || role="brain"
      if [[ "${fake_boundary}" == "1" ]]
      then
         public6="2602:fac0:0:12ab:34cd::$(printf '%x' "${host_octet}")"
      else
         public6="2001:db8:100::$(printf '%x' "${host_octet}")"
      fi
      printf '{"index":%s,"role":"%s","namespace":"%s","pid":%s,"stdoutLog":"%s/machine%s.log","ipv4":"%s.%s","private6":"%s::%x","public6":"%s"}' \
         "${index}" "${role}" "${child_names[$((index - 1))]}" "${machine_pids[$((index - 1))]}" "${workspace}" "${index}" "${private4_prefix}" "${host_octet}" "${private6_prefix}" "${host_octet}" "${public6}"
   done
   printf ']}\n'
} > "${manifest_path}.${pid}.tmp"
mv -f "${manifest_path}.${pid}.tmp" "${manifest_path}"
printf '%s\n' "${machine_pids[@]}" > "${runtime_path}.${pid}.tmp"
mv -f "${runtime_path}.${pid}.tmp" "${runtime_path}"
}

recovery_hold()
{
   recovery_failed=1
   printf "%s\n" "$1" > "${adopted_operation_dir}/failure.${pid}.tmp" 2>/dev/null || true
   mv -f "${adopted_operation_dir}/failure.${pid}.tmp" "${adopted_operation_dir}/failure" 2>/dev/null || true
}

publish_runtime
pair_unlock_workspace "${workspace_startup_lock_fd}"
workspace_startup_lock_fd=""

while true
do
   for index in $(seq 1 "${machine_count}")
   do
      machine_pid="${machine_pids[$((index - 1))]}"
      if [[ "${index}" -eq "${recovering_machine}" ]]
      then
         # A selected recovery is C++-owned. Never cgroup-kill it or let the
         # ordinary supervisor race the staged root swap.
         if [[ -r "${adopted_operation_dir}/complete" && "$(<"${adopted_operation_dir}/complete")" == "${recovery_operation_id}" ]]
         then
            recovering_machine=0
         elif [[ "${recovery_launch_started}" -eq 0 && -r "${adopted_operation_dir}/launch" && "$(<"${adopted_operation_dir}/launch")" == "${recovery_operation_id}" ]] && ! kill -0 "${machine_pid}" >/dev/null 2>&1
         then
            wait "${machine_pid}" >/dev/null 2>&1 || true
            recovery_launch_started=1
            if ! start_machine "${index}"
            then
               recovery_hold "selected-worker-start-failed"
               continue
            fi
            if ! publish_runtime
            then
               recovery_hold "selected-worker-publish-failed"
               continue
            fi
            replacement_pid="${machine_pids[$((index - 1))]}"
            expected_netns="$(stat -Lc %i "/var/run/netns/${child_names[$((index - 1))]}" 2>/dev/null || true)"
            replacement_start=""
            replacement_netns=""
            for _ in $(seq 1 100)
            do
               if [[ -r "/proc/${replacement_pid}/stat" && -e "/proc/${replacement_pid}/ns/net" ]]
               then
                  replacement_start="$(awk '{print $22}' "/proc/${replacement_pid}/stat" 2>/dev/null || true)"
                  replacement_netns="$(stat -Lc %i "/proc/${replacement_pid}/ns/net" 2>/dev/null || true)"
                  [[ -n "${replacement_start}" && -n "${expected_netns}" && "${replacement_netns}" == "${expected_netns}" ]] && break
               fi
               sleep 0.05
            done
            if [[ -z "${replacement_start}" || -z "${expected_netns}" || "${replacement_netns}" != "${expected_netns}" ]]
            then
               recovery_hold "selected-worker-not-ready"
               continue
            fi
            replacement_path="${adopted_operation_dir}/replaced"
            if ! printf "%s %s %s\n" "${replacement_pid}" "${replacement_start}" "${replacement_netns}" > "${replacement_path}.${pid}.tmp" || ! mv -f "${replacement_path}.${pid}.tmp" "${replacement_path}"
            then
               recovery_hold "selected-worker-receipt-failed"
            fi
         fi
         continue
      fi
      if ! kill -0 "${machine_pid}" >/dev/null 2>&1
      then
         machine_exit_is_held "${index}" && continue
         machine_wait_status=0
         wait "${machine_pid}" >/dev/null 2>&1 || machine_wait_status=$?
         # Retain the supervisor observation before resetting the machine cgroup.
         # An adopted non-child can return 127; this is a wait status, not a
         # claim about that process's exit code.
         printf 'MOTHERSHIP_RUNTIME_EXIT epoch=%(%s)T machine=%s pid=%s waitStatus=%s\n' \
            -1 "${index}" "${machine_pid}" "${machine_wait_status}" >>"${workspace}/machine-exits.log" || true
         handle_machine_exit "${index}" "${machine_pid}"
      fi
   done
   sleep 0.1
done
