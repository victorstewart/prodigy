#!/usr/bin/env bash
set -Eeuo pipefail

enter_machine()
{
   [[ "$#" -eq 12 ]]
   local machine_cgroup="$1"
   shift
   printf '%s\n' "$$" > "${machine_cgroup}/cgroup.procs"
   exec unshare --cgroup --mount --propagation private -- bash "$0" --run-machine "$@"
}

run_machine()
{
   [[ "$#" -eq 11 ]]
   local workspace="$1"
   local machine_root="$2"
   local containers_root="$3"
   local shared_store="$4"
   local storage_root="$5"
   local storage_device_count="$6"
   local child_ns="$7"
   local boot_path="$8"
   local host_netns_inode="$9"
   local brain_count="${10}"
   local fake_ingress="${11}"

   mkdir -p /mnt/prodigy-vdc-workspace /containers /root /sys/fs/cgroup /sys/fs/bpf /var/log/prodigy "${machine_root}/var/log/prodigy"
   mount --bind "${workspace}" /mnt/prodigy-vdc-workspace
   mount --bind "${machine_root}/var/log/prodigy" /var/log/prodigy
   mount --bind "${machine_root}/root" /root
   mount --bind "${containers_root}" /containers
   mkdir -p "${workspace}" /containers/store
   mount --bind /mnt/prodigy-vdc-workspace "${workspace}"
   mount --bind "${shared_store}" /containers/store

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
      "PRODIGY_DEV_SHARED_TRANSPORT_TLS_DIR=/containers/store/prodigy-transport-tls"
      "PRODIGY_CRASH_REPORT_PATH=/root/prodigy-crashreport.txt"
      "PRODIGY_STATE_DB=/containers/prodigy.state"
   )
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
      mkdir /sys/fs/cgroup/prodigy-runtime
      printf "%s\n" "$$" > /sys/fs/cgroup/prodigy-runtime/cgroup.procs
      umount /sys/fs/bpf >/dev/null 2>&1 || true
      mount -t bpf bpf /sys/fs/bpf
      exec "$@"
   ' _ /root/prodigy/prodigy --isolated --netdev=bond0 "--boot-json=${boot_json}"
}

valid_workspace()
{
   local canonical
   canonical="$(realpath -m -- "$1")" || return 1
   [[ "${canonical}" == "$1" && "$1" == /*/* && "$1" != */ ]]
}

valid_control_socket_path()
{
   [[ "$1" =~ ^/tmp/prodigy-vdc-0x[0-9a-fA-F]{1,32}/mothership\.sock$ ]]
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

restore_cgroup_scope_if_idle()
{
   resolve_cgroup_scope || return 0
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
   local command_line
   command_line="$(tr '\0' ' ' < "/proc/${candidate}/cmdline")"
   [[ "${command_line}" =~ bash[[:space:]]+/proc/self/fd/[0-9]+[[:space:]]+--serve[[:space:]] ]] &&
      [[ "${command_line}" == *" --serve ${workspace} "* ]]
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
   local parent_ns="pvd-p-${provider_pid}"
   local -a parent_netns=(nsenter -t "${provider_pid}" -m -- ip netns exec "${parent_ns}")
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
            "${parent_netns[@]}" ip link set "vp${index}" down
         done
         if [[ "${mode}" == "link" && "${duration_ms}" -eq 0 ]]
         then
            return 0
         fi
         sleep_milliseconds "${link_down_ms}"
         for index in "${parsed[@]}"
         do
            "${parent_netns[@]}" ip link set "vp${index}" up
         done
         [[ "${cycle}" -eq "${repetitions}" ]] || sleep_milliseconds "${link_up_ms}"
      done
      return 0
   fi

   local marker=""
   for index in "${parsed[@]}"
   do
      marker="${workspace}/fault-machine-${index}"
      : > "${marker}"
      kill -KILL -- "-${machine_pids[$((index - 1))]}" >/dev/null 2>&1 || true
      kill -KILL "${machine_pids[$((index - 1))]}" >/dev/null 2>&1 || true
   done
   [[ "${duration_ms}" -ne 0 ]] || return 0
   sleep_milliseconds "${duration_ms}"
   for index in "${parsed[@]}"
   do
      rm -f "${workspace}/fault-machine-${index}"
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
   local namespace="pvd-p-${provider_pid}"
   if [[ "${source_index}" != "0" ]]
   then
      local -a machine_pids=()
      mapfile -t machine_pids < "${workspace}/virtual-datacenter.runtime"
      [[ "${source_index}" =~ ^[0-9]+$ && "${source_index}" -ge 1 && "${source_index}" -le "${#machine_pids[@]}" ]] || return 2
      namespace="pvd-m${source_index}-${provider_pid}"
   fi
   local timeout_seconds=""
   printf -v timeout_seconds '%d.%03d' "$((timeout_ms / 1000))" "$((timeout_ms % 1000))"
   nsenter -t "${provider_pid}" -m -- ip netns exec "${namespace}" timeout "${timeout_seconds}" bash -c '
      exec 3<>"/dev/tcp/$1/$2"
      printf "%s\n" "$3" >&3
      [[ -n "$4" ]] || exit 0
      response=""
      IFS= read -r response <&3
      [[ "${response}" == "$4" ]]
   ' _ "${address}" "${port}" "${payload}" "${expected}"
}

stop_datacenter()
{
   [[ "$#" -eq 2 && "${EUID}" -eq 0 ]] || return 2
   local workspace="$1"
   local control_socket_path="$2"
   command -v find >/dev/null
   command -v flock >/dev/null
   command -v ip >/dev/null
   command -v realpath >/dev/null
   command -v seq >/dev/null
   command -v tr >/dev/null
   valid_workspace "${workspace}" && valid_control_socket_path "${control_socket_path}" || return 2
   local pid_path="${workspace}/virtual-datacenter.pid"
   local provider_pid=""
   [[ ! -r "${pid_path}" ]] || provider_pid="$(<"${pid_path}")"
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
      resolve_cgroup_scope
      local cgroup_root="${cgroup_scope}/prodigy-vdc-${provider_pid}"
      [[ ! -w "${cgroup_root}/cgroup.kill" ]] || printf '1\n' > "${cgroup_root}/cgroup.kill"
      for _ in $(seq 1 50)
      do
         find "${cgroup_root}" -depth -type d -exec rmdir {} \; >/dev/null 2>&1 || true
         [[ -d "${cgroup_root}" ]] || break
         sleep 0.02
      done
      [[ ! -d "${cgroup_root}" ]]
      ip link del "vdh${provider_pid: -8}" >/dev/null 2>&1 || true
   fi
   restore_cgroup_scope_if_idle
   rm -f -- "${control_socket_path}"
   rmdir -- "${control_socket_path%/*}" 2>/dev/null || true
   rm -rf -- "${workspace}"
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
   stop_datacenter "${workspace}" "${control_socket_path}"
   mkdir -p "${workspace%/*}" "${workspace}"
   setsid nohup bash "$0" --serve "$@" > "${workspace}/virtual-datacenter.log" 2>&1 < /dev/null &
}

case "${1:-}" in
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
   --serve)
      shift
      ;;
   *)
      echo "virtual datacenter provider requires --launch or --stop" >&2
      exit 2
      ;;
esac

if [[ "${PRODIGY_VDC_MOUNT_NAMESPACE_READY:-0}" != "1" ]]
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

required=(btrfs find flock install ip mkfs.btrfs mount mountpoint mv realpath rm rmdir seq setsid stat tr truncate umount unshare xargs)
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

pid="$$"
underlay_mtu=$((inter_container_mtu + 40))
parent_ns="pvd-p-${pid}"
filesystem_root="/mnt/prodigy-vdc-${pid}"
filesystem_image="${workspace}/virtual-datacenter.btrfs"
cgroup_scope=""
cgroup_control=""
cgroup_lock=""
cgroup_root=""
shared_store="${filesystem_root}/shared-store"
provisioned_path="${workspace}/virtual-datacenter.provisioned"
ready_path="${workspace}/virtual-datacenter.ready"
runtime_path="${workspace}/virtual-datacenter.runtime"
pid_path="${workspace}/virtual-datacenter.pid"
failure_path="${workspace}/virtual-datacenter.failure"
manifest_path="${workspace}/test-cluster-manifest.json"
boundary_lock="/run/prodigy-virtual-datacenter.boundary.lock"
boundary_bpffs="${workspace}/boundary-bpffs"
host_edge="vdh${pid: -8}"
parent_edge="vdp${pid: -8}"
child_names=()
machine_pids=()
storage_mounts=()
host_ipv4_forward=""
host_ipv6_forward=""
cleaned=0

atomic_write()
{
   local path="$1"
   local temporary="${path}.${pid}.tmp"
   shift
   printf '%b' "$*" > "${temporary}"
   mv -f "${temporary}" "${path}"
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

   iptables -D FORWARD -i "${host_edge}" ! -o "${host_edge}" -j ACCEPT >/dev/null 2>&1 || true
   iptables -D FORWARD ! -i "${host_edge}" -o "${host_edge}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || true
   iptables -t nat -D POSTROUTING -s 172.31.0.2/32 ! -o "${host_edge}" -j MASQUERADE >/dev/null 2>&1 || true
   ip route del 10.0.0.0/24 via 172.31.0.2 dev "${host_edge}" >/dev/null 2>&1 || true
   ip6tables -D FORWARD -i "${host_edge}" ! -o "${host_edge}" -j ACCEPT >/dev/null 2>&1 || true
   ip6tables -D FORWARD ! -i "${host_edge}" -o "${host_edge}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || true
   ip6tables -t nat -D POSTROUTING -s 2602:fac0:0:12ab:34cd::/88 -j MASQUERADE >/dev/null 2>&1 || true
   ip6tables -t nat -D POSTROUTING -s fd00:31::2/128 -j MASQUERADE >/dev/null 2>&1 || true
   [[ -z "${host_ipv4_forward}" ]] || sysctl -q -w "net.ipv4.ip_forward=${host_ipv4_forward}" >/dev/null 2>&1 || true
   [[ -z "${host_ipv6_forward}" ]] || sysctl -q -w "net.ipv6.conf.all.forwarding=${host_ipv6_forward}" >/dev/null 2>&1 || true
   ip link del "${host_edge}" >/dev/null 2>&1 || true
   mountpoint -q "${boundary_bpffs}" && umount "${boundary_bpffs}" >/dev/null 2>&1 || true
   rm -rf "${boundary_bpffs}" "${boundary_lock}" >/dev/null 2>&1 || true

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
   mountpoint -q "${filesystem_root}" && umount "${filesystem_root}" >/dev/null 2>&1 || true
   rm -rf "${filesystem_root}" >/dev/null 2>&1 || true
   rm -f "${filesystem_image}" "${workspace}"/machine*.storage*.ext4 >/dev/null 2>&1 || true

   [[ -z "${cgroup_control}" || ! -w "${cgroup_control}/cgroup.procs" ]] || printf '%s\n' "${pid}" > "${cgroup_control}/cgroup.procs" 2>/dev/null || true
   [[ ! -e "${cgroup_root}/cgroup.kill" ]] || printf '1\n' > "${cgroup_root}/cgroup.kill" 2>/dev/null || true
   find "${cgroup_root}" -depth -type d -exec rmdir {} \; >/dev/null 2>&1 || true
   restore_cgroup_scope_if_idle
   rm -f "${ready_path}" "${runtime_path}" >/dev/null 2>&1 || true
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

mkdir -p "${workspace}/boot" "${filesystem_root}"
install -d -m 0700 "${control_socket_path%/*}"
rm -f "${provisioned_path}" "${ready_path}" "${runtime_path}" "${failure_path}" "${manifest_path}" "${control_socket_path}"
filesystem_size_bytes=$(( (machine_storage_mb * machine_count + 4096) * 1048576 ))
machine_memory_bytes=$(( machine_memory_mb * 1048576 ))
machine_storage_bytes=$(( machine_storage_mb * 1048576 ))
truncate -s "${filesystem_size_bytes}" "${filesystem_image}"
mkfs.btrfs -f "${filesystem_image}" >/dev/null
mount -o loop "${filesystem_image}" "${filesystem_root}"
mkdir -p "${shared_store}" "${filesystem_root}/machines"
btrfs quota enable "${filesystem_root}"

prepare_cgroup_scope
cgroup_root="${cgroup_scope}/prodigy-vdc-${pid}"
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
ip netns exec "${parent_ns}" ip link set dev vdcbr0 type bridge mcast_snooping 0
ip netns exec "${parent_ns}" ip link set vdcbr0 mtu "${underlay_mtu}" gso_max_size "${underlay_mtu}" gso_max_segs 1 gro_max_size "${underlay_mtu}" gso_ipv4_max_size "${underlay_mtu}" gro_ipv4_max_size "${underlay_mtu}"
ip netns exec "${parent_ns}" ip addr add 10.0.0.1/24 dev vdcbr0
ip netns exec "${parent_ns}" ip -6 addr add fd00:10::1/64 nodad dev vdcbr0
if [[ "${fake_boundary}" == "1" ]]
then
   ip netns exec "${parent_ns}" ip -6 addr add 2602:fac0:0:12ab:ffff::1/64 nodad dev vdcbr0
else
   ip netns exec "${parent_ns}" ip -6 addr add 2001:db8:100::1/64 nodad dev vdcbr0
fi
ip netns exec "${parent_ns}" ip link set vdcbr0 up

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
   ip netns exec "${child_ns}" ip addr add "10.0.0.${host_octet}/24" dev bond0
   ip netns exec "${child_ns}" ip -6 addr add "fd00:10::$(printf '%x' "${host_octet}")/64" nodad dev bond0
   if [[ "${fake_boundary}" == "1" ]]
   then
      ip netns exec "${child_ns}" ip -6 addr add "2602:fac0:0:12ab:34cd::$(printf '%x' "${host_octet}")/64" nodad dev bond0
   else
      ip netns exec "${child_ns}" ip -6 addr add "2001:db8:100::$(printf '%x' "${host_octet}")/64" nodad dev bond0
   fi
   ip netns exec "${child_ns}" ip route replace default via 10.0.0.1 dev bond0
   ip netns exec "${child_ns}" ip -6 route replace default via fd00:10::1 dev bond0
done

atomic_write "${pid_path}" "${pid}\n"
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
   ip route replace 10.0.0.0/24 via 172.31.0.2 dev "${host_edge}"
   ip netns exec "${parent_ns}" ip link set "${parent_edge}" up
   ip netns exec "${parent_ns}" ip addr add 172.31.0.2/30 dev "${parent_edge}"
   ip netns exec "${parent_ns}" ip -6 addr add fd00:31::2/126 dev "${parent_edge}"
   ip netns exec "${parent_ns}" ip route replace default via 172.31.0.1 dev "${parent_edge}"
   ip netns exec "${parent_ns}" ip -6 route replace default via fd00:31::1 dev "${parent_edge}"
   ip netns exec "${parent_ns}" ip route replace 198.18.0.0/16 via 10.0.0.10 dev vdcbr0 src 10.0.0.1
   ip netns exec "${parent_ns}" ip -6 route replace 2602:fac0:0:12ab:34cd::/88 via fd00:10::a dev vdcbr0
   ip netns exec "${parent_ns}" sysctl -q -w net.ipv4.ip_forward=1
   ip netns exec "${parent_ns}" sysctl -q -w net.ipv6.conf.all.forwarding=1
   ip netns exec "${parent_ns}" ip6tables -t nat -A POSTROUTING -s 2602:fac0:0:12ab:34cd::/88 -o "${parent_edge}" -j SNAT --to-source fd00:31::2

   host_ipv4_forward="$(sysctl -n net.ipv4.ip_forward)"
   host_ipv6_forward="$(sysctl -n net.ipv6.conf.all.forwarding)"
   sysctl -q -w net.ipv4.ip_forward=1
   sysctl -q -w net.ipv6.conf.all.forwarding=1
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

start_machine()
{
   local index="$1"
   local child_ns="${child_names[$((index - 1))]}"
   local machine_root="${workspace}/machines/${index}"
   local containers_root="${filesystem_root}/machines/${index}"
   local storage_root="${filesystem_root}/storage/${index}"
   local machine_cgroup="${cgroup_root}/machine${index}"
   local boot_path="${workspace}/boot/${index}.json"
   local log_path="${workspace}/machine${index}.log"
   local fake_ingress=""
   [[ "${fake_boundary}" != "1" ]] || fake_ingress="/root/prodigy/host.ingress.router.dev.ebpf.o"
   [[ -x "${machine_root}/root/prodigy/prodigy" && -r "${boot_path}" ]]

   setsid bash "$0" --enter-machine \
      "${machine_cgroup}" "${workspace}" "${machine_root}" "${containers_root}" "${shared_store}" "${storage_root}" "${storage_device_count}" "${child_ns}" "${boot_path}" "${host_netns_inode}" "${brain_count}" "${fake_ingress}" \
      >> "${log_path}" 2>&1 &
   machine_pids[$((index - 1))]="$!"
}

for index in $(seq 1 "${machine_count}")
do
   start_machine "${index}"
   sleep 0.25
done

publish_runtime()
{
{
   printf '{"workspaceRoot":"%s","manifestPath":"%s","controlSocketPath":"%s","parentNamespace":"%s","parentPid":%s,"machineCount":%s,"brainCount":%s,"machineLogicalCores":%s,"machineMemoryMB":%s,"machineStorageMB":%s,"storageDeviceCount":%s,"storageDeviceMB":%s,"interContainerMTU":%s,"leaderIndex":0,"leaderNamespace":"","nodes":[' \
      "${workspace}" "${manifest_path}" "${control_socket_path}" "${parent_ns}" "${pid}" "${machine_count}" "${brain_count}" "${machine_logical_cores}" "${machine_memory_mb}" "${machine_storage_mb}" "${storage_device_count}" "${storage_device_mb}" "${inter_container_mtu}"
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
      printf '{"index":%s,"role":"%s","namespace":"%s","pid":%s,"stdoutLog":"%s/machine%s.log","ipv4":"10.0.0.%s","private6":"fd00:10::%x","public6":"%s"}' \
         "${index}" "${role}" "${child_names[$((index - 1))]}" "${machine_pids[$((index - 1))]}" "${workspace}" "${index}" "${host_octet}" "${host_octet}" "${public6}"
   done
   printf ']}\n'
} > "${manifest_path}.${pid}.tmp"
mv -f "${manifest_path}.${pid}.tmp" "${manifest_path}"
printf '%s\n' "${machine_pids[@]}" > "${runtime_path}.${pid}.tmp"
mv -f "${runtime_path}.${pid}.tmp" "${runtime_path}"
}

publish_runtime

while true
do
   for index in $(seq 1 "${machine_count}")
   do
      machine_pid="${machine_pids[$((index - 1))]}"
      if ! kill -0 "${machine_pid}" >/dev/null 2>&1
      then
         wait "${machine_pid}" >/dev/null 2>&1 || true
         if [[ -e "${workspace}/fault-machine-${index}" ]]
         then
            continue
         fi
         start_machine "${index}"
         publish_runtime
      fi
   done
   sleep 0.1
done
