#!/usr/bin/env bash
set -Eeuo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
READY_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"
DISCOMBOBULATOR_MANIFEST="${REPO_ROOT}/prodigy/discombobulator/Cargo.toml"
EXPECTED_MTU=9000
APPLICATION_ID=62021
DEPLOY_WAIT_S=240

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${READY_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_ready_container"
   exit 2
fi

if [[ "${EUID}" -ne 0 ]]
then
   echo "SKIP: requires root for isolated netns harness"
   exit 77
fi

for path in "${PRODIGY_BIN}" "${MOTHERSHIP_BIN}" "${READY_BIN}" "${HARNESS}" "${DISCOMBOBULATOR_MANIFEST}"
do
   if [[ ! -e "${path}" ]]
   then
      echo "FAIL: required path missing: ${path}"
      exit 1
   fi
done

deps=(awk basename bpftool cargo cut find ip ls mkfs.btrfs mktemp mount nsenter python3 readlink rg sed stat timeout truncate umount uname)
for cmd in "${deps[@]}"
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}"
      exit 77
   fi
done

PRODIGY_BIN="$(readlink -f "${PRODIGY_BIN}" 2>/dev/null || printf '%s' "${PRODIGY_BIN}")"
MOTHERSHIP_BIN="$(readlink -f "${MOTHERSHIP_BIN}" 2>/dev/null || printf '%s' "${MOTHERSHIP_BIN}")"
READY_BIN="$(readlink -f "${READY_BIN}" 2>/dev/null || printf '%s' "${READY_BIN}")"
switchboard_balancer_ebpf="$(dirname "${PRODIGY_BIN}")/balancer.ebpf.o"
if [[ ! -x "${READY_BIN}" ]]
then
   fail "ready container binary is not executable: ${READY_BIN}"
fi
if [[ ! -e "${switchboard_balancer_ebpf}" ]]
then
   fail "required switchboard balancer eBPF is missing: ${switchboard_balancer_ebpf}"
fi

tmpdir="$(mktemp -d "${REPO_ROOT}/.run/prodigy-dev-container-netkit-mtu-unit.XXXXXX")"
workspace_root="${tmpdir}/workspace"
workspace_archive="${tmpdir}/workspace-retained"
manifest_path="${workspace_root}/test-cluster-manifest.json"
plan_json="${tmpdir}/deploy.plan.json"
container_blob="${tmpdir}/deploy.container.zst"
discombobulator_file="${tmpdir}/NetkitMTU.DiscombobuFile"
discombobulator_log="${tmpdir}/discombobulator-build.log"
mothership_db_path="${tmpdir}/mothership-netkit-mtu.tidesdb"
cluster_name="test-netkit-mtu-$(date -u +%Y%m%d-%H%M%S)-$$"
application_name="${cluster_name}.ready"
cluster_created=0
cluster_removed=0
containers_dir_created=0
containers_mount_created=0
containers_loop_image=""
keep_tmpdir=0

capture_workspace()
{
   set +e

   if [[ -d "${workspace_root}" ]]
   then
      rm -rf "${workspace_archive}" >/dev/null 2>&1 || true
      cp -a "${workspace_root}" "${workspace_archive}" >/dev/null 2>&1 || true
   fi
}

dump_failure_context()
{
   set +e
   local workspace_dump_root="${workspace_root}"

   if [[ -d "${workspace_archive}" ]]
   then
      workspace_dump_root="${workspace_archive}"
   fi

   if [[ -f "${discombobulator_log}" ]]
   then
      echo "discombobulator log: ${discombobulator_log}" >&2
      sed -n '1,120p' "${discombobulator_log}" >&2 || true
   fi

   if [[ -f "${tmpdir}/harness.log" ]]
   then
      echo "harness log: ${tmpdir}/harness.log" >&2
      sed -n '1,200p' "${tmpdir}/harness.log" >&2 || true
   fi

   if [[ -f "${tmpdir}/mothership.deploy.log" ]]
   then
      echo "mothership deploy log: ${tmpdir}/mothership.deploy.log" >&2
      sed -n '1,200p' "${tmpdir}/mothership.deploy.log" >&2 || true
   fi

   if [[ -f "${tmpdir}/create_cluster.log" ]]
   then
      echo "mothership createCluster log: ${tmpdir}/create_cluster.log" >&2
      sed -n '1,200p' "${tmpdir}/create_cluster.log" >&2 || true
   fi

   if [[ -f "${tmpdir}/mothership.reserve.log" ]]
   then
      echo "mothership reserveApplicationID log: ${tmpdir}/mothership.reserve.log" >&2
      sed -n '1,200p' "${tmpdir}/mothership.reserve.log" >&2 || true
   fi

   if [[ -f "${tmpdir}/mothership.applicationreport.log" ]]
   then
      echo "mothership applicationReport log: ${tmpdir}/mothership.applicationreport.log" >&2
      sed -n '1,200p' "${tmpdir}/mothership.applicationreport.log" >&2 || true
   fi

   if [[ -f "${tmpdir}/mothership.configure.log" ]]
   then
      echo "mothership configure log: ${tmpdir}/mothership.configure.log" >&2
      sed -n '1,200p' "${tmpdir}/mothership.configure.log" >&2 || true
   fi

   if [[ -f "${tmpdir}/mothership.clusterreport.log" ]]
   then
      echo "mothership clusterReport log: ${tmpdir}/mothership.clusterreport.log" >&2
      sed -n '1,200p' "${tmpdir}/mothership.clusterreport.log" >&2 || true
   fi

   if [[ -f "${workspace_dump_root}/mothership.deploy.log" ]]
   then
      echo "mothership deploy log: ${workspace_dump_root}/mothership.deploy.log" >&2
      sed -n '1,200p' "${workspace_dump_root}/mothership.deploy.log" >&2 || true
   fi

   if compgen -G "${workspace_dump_root}/logs/brain*.stdout.log" >/dev/null
   then
      for brain_log in "${workspace_dump_root}"/logs/brain*.stdout.log
      do
         echo "brain log tail: ${brain_log}" >&2
         tail -n 80 "${brain_log}" >&2 || true
      done
   fi
}

fail()
{
   keep_tmpdir=1
   capture_workspace
   echo "FAIL: $*" >&2
   dump_failure_context
   exit 1
}

unexpected_error()
{
   local rc="$?"
   trap - ERR
   keep_tmpdir=1
   capture_workspace
   echo "FAIL: unexpected command failure at line ${BASH_LINENO[0]} status=${rc}" >&2
   dump_failure_context
   exit "${rc}"
}
trap unexpected_error ERR

cleanup()
{
   set +e

   if [[ "${keep_tmpdir}" -eq 1 ]]
   then
      capture_workspace
   fi

   if [[ "${cluster_created}" -eq 1 && "${cluster_removed}" -eq 0 ]]
   then
      run_mothership removeCluster "${cluster_name}" >"${tmpdir}/remove_cluster.log" 2>&1 || true
   fi

   if [[ "${containers_mount_created}" -eq 1 ]]
   then
      umount /containers >/dev/null 2>&1 || true
   fi

   if [[ "${containers_dir_created}" -eq 1 ]]
   then
      rmdir /containers >/dev/null 2>&1 || true
   fi

   if [[ "${keep_tmpdir}" -eq 0 ]]
   then
      rm -rf "${tmpdir}"
   else
      echo "RETAINED: ${tmpdir}" >&2
   fi
}
trap cleanup EXIT

run_mothership()
{
   env \
      PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      PRODIGY_MOTHERSHIP_TEST_HARNESS="${HARNESS}" \
      PRODIGY_DEV_ALLOW_BPF_ATTACH=1 \
      PRODIGY_DEV_SWITCHBOARD_BALANCER_EBPF="${switchboard_balancer_ebpf}" \
      "${MOTHERSHIP_BIN}" "$@"
}

extract_link_mtu()
{
   awk '
      {
         for (i = 1; i <= NF; i += 1)
         {
            if ($i == "mtu" && (i + 1) <= NF)
            {
               mtu = $(i + 1)
            }
         }
      }
      END {
         if (mtu != "")
         {
            print mtu
         }
      }
   ' < <("$@")
}

extract_link_detail_field()
{
   local field="$1"
   shift

   awk -v want="${field}" '
      {
         for (i = 1; i <= NF; i += 1)
         {
            if ($i == want && (i + 1) <= NF)
            {
               value = $(i + 1)
            }
         }
      }
      END {
         if (value != "")
         {
            print value
         }
      }
   ' < <("$@")
}

find_runtime_netkit_if()
{
   local target_pid="$1"
   local suffix="$2"

   awk -F': ' -v suffix="${suffix}" '
      {
         if ($2 ~ (suffix "@"))
         {
            split($2, parts, "@")
            if (parts[1] != "")
            {
               name = parts[1]
            }
         }
      }
      END {
         if (name != "")
         {
            print name
         }
      }
   ' < <(nsenter -t "${target_pid}" -n ip -o link show)
}

assert_link_mtu()
{
   local observed_mtu="$1"
   local label="$2"

   if [[ "${observed_mtu}" != "${EXPECTED_MTU}" ]]
   then
      fail "${label} mtu=${observed_mtu} expected=${EXPECTED_MTU}"
   fi
}

assert_link_budget()
{
   local observed_value="$1"
   local field="$2"
   local label="$3"

   if [[ "${observed_value}" != "${EXPECTED_MTU}" ]]
   then
      fail "${label} ${field}=${observed_value} expected=${EXPECTED_MTU}"
   fi
}

assert_link_budget_segments()
{
   local observed_value="$1"
   local field="$2"
   local expected_value="$3"
   local label="$4"

   if [[ "${observed_value}" != "${expected_value}" ]]
   then
      fail "${label} ${field}=${observed_value} expected=${expected_value}"
   fi
}

find_netkit_prog_id()
{
   local brain_pid="$1"
   local host_if="$2"
   local prog_name="$3"

   awk -v dev="${host_if}" -v prog="${prog_name}" '
         $1 ~ ("^" dev "\\(") && $3 == prog {
            for (i = 1; i <= NF; i += 1) {
               if ($i == "prog_id" && (i + 1) <= NF) {
                  prog_id = $(i + 1)
               }
            }
         }
         END {
            if (prog_id != "")
            {
               print prog_id
            }
         }
      ' < <(nsenter -t "${brain_pid}" -n bpftool net)
}

find_named_map_id_for_prog()
{
   local brain_pid="$1"
   local prog_id="$2"
   local map_name="$3"

   python3 - "${brain_pid}" "${prog_id}" "${map_name}" <<'PY'
import json
import subprocess
import sys

brain_pid, prog_id, map_name = sys.argv[1:4]

prog = subprocess.run(
    ["nsenter", "-t", brain_pid, "-n", "bpftool", "-j", "prog", "show", "id", prog_id],
    check=True,
    capture_output=True,
    text=True,
)
prog_entries = json.loads(prog.stdout)
if isinstance(prog_entries, dict):
    prog_entries = [prog_entries]

for entry in prog_entries:
    for map_id in entry.get("map_ids", []):
        shown = subprocess.run(
            ["nsenter", "-t", brain_pid, "-n", "bpftool", "-j", "map", "show", "id", str(map_id)],
            check=True,
            capture_output=True,
            text=True,
        )
        map_entries = json.loads(shown.stdout)
        if isinstance(map_entries, dict):
            map_entries = [map_entries]
        for map_entry in map_entries:
            actual_name = map_entry.get("name") or ""
            if (
                actual_name == map_name
                or map_name.startswith(actual_name)
                or actual_name.startswith(map_name)
            ):
                print(map_id)
                raise SystemExit(0)

raise SystemExit(1)
PY
}

lookup_policy_inter_container_mtu()
{
   local brain_pid="$1"
   local policy_map_id="$2"

   python3 - "${brain_pid}" "${policy_map_id}" <<'PY'
import json
import subprocess
import sys

brain_pid, policy_map_id = sys.argv[1:3]

lookup = subprocess.run(
    ["nsenter", "-t", brain_pid, "-n", "bpftool", "-j", "map", "lookup", "id", policy_map_id, "key", "hex", "00", "00", "00", "00"],
    check=True,
    capture_output=True,
    text=True,
)
entry = json.loads(lookup.stdout)
if isinstance(entry, list):
    entry = entry[0]
value = entry.get("value", {})
if isinstance(value, dict):
    print(value.get("interContainerMTU", 0))
    raise SystemExit(0)

if isinstance(value, list):
    def parse_byte(raw):
        if isinstance(raw, int):
            return raw & 0xFF
        if isinstance(raw, str):
            return int(raw, 0) & 0xFF
        if isinstance(raw, dict):
            if "value" in raw:
                return parse_byte(raw["value"])
            if "byte" in raw:
                return parse_byte(raw["byte"])
        raise ValueError(f"unsupported bpftool byte payload: {raw!r}")

    decoded = [parse_byte(item) for item in value]
    if len(decoded) >= 8:
        mtu = decoded[4] | (decoded[5] << 8) | (decoded[6] << 16) | (decoded[7] << 24)
        print(mtu)
        raise SystemExit(0)

print(0)
PY
}

assert_policy_mtu()
{
   local observed_mtu="$1"
   local label="$2"

   if [[ "${observed_mtu}" != "${EXPECTED_MTU}" ]]
   then
      fail "${label} interContainerMTU=${observed_mtu} expected=${EXPECTED_MTU}"
   fi
}

detect_target_arch()
{
   local machine_arch
   machine_arch="$(uname -m)"
   case "${machine_arch}" in
      x86_64|amd64)
         echo "x86_64"
         ;;
      aarch64|arm64)
         echo "aarch64"
         ;;
      riscv64|riscv)
         echo "riscv64"
         ;;
      *)
         echo "FAIL: unsupported host architecture for discombobulator build: ${machine_arch}" >&2
         return 1
         ;;
   esac
}

target_arch="$(detect_target_arch)"

if [[ ! -d /containers ]]
then
   mkdir -p /containers
   containers_dir_created=1
fi

containers_fs_type="$(stat -f -c '%T' /containers 2>/dev/null || echo unknown)"
if [[ "${containers_fs_type}" != "btrfs" ]]
then
   if awk '$2 == "/containers" { found = 1 } END { exit(found ? 0 : 1) }' /proc/self/mounts
   then
      fail "/containers is mounted but not btrfs (found ${containers_fs_type})"
   fi

   if [[ -n "$(ls -A /containers 2>/dev/null)" ]]
   then
      existing_entries_ok=1
      while IFS= read -r existing_path
      do
         existing_name="$(basename "${existing_path}")"
         case "${existing_name}" in
            .prodigy-dev-fs-*)
               ;;
            store|storage)
               if [[ -d "${existing_path}" && -z "$(ls -A "${existing_path}" 2>/dev/null)" ]]
               then
                  :
               else
                  existing_entries_ok=0
                  break
               fi
               ;;
            *)
               existing_entries_ok=0
               break
               ;;
         esac
      done < <(find /containers -mindepth 1 -maxdepth 1 -print 2>/dev/null)

      if [[ "${existing_entries_ok}" -ne 1 ]]
      then
         fail "/containers exists on non-btrfs fs and is not safely overmountable"
      fi

      rmdir /containers/store /containers/storage >/dev/null 2>&1 || true
   fi

   containers_loop_image="${tmpdir}/containers.loop.img"
   truncate -s 2G "${containers_loop_image}"
   mkfs.btrfs -f "${containers_loop_image}" >/dev/null
   mount -o loop "${containers_loop_image}" /containers
   containers_mount_created=1
fi

mkdir -p /containers/store /containers/storage

cargo build --quiet --manifest-path "${DISCOMBOBULATOR_MANIFEST}"
DISCOMBOBULATOR_BIN="${REPO_ROOT}/prodigy/discombobulator/target/debug/discombobulator"
if [[ ! -x "${DISCOMBOBULATOR_BIN}" ]]
then
   fail "discombobulator binary is not executable: ${DISCOMBOBULATOR_BIN}"
fi

cat > "${discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {bin} ./$(basename "${READY_BIN}") /root/ready_container
SURVIVE /root/ready_container
COPY {ebpf} ./container.egress.router.ebpf.o /root/prodigy/container.egress.router.ebpf.o
COPY {ebpf} ./container.ingress.router.ebpf.o /root/prodigy/container.ingress.router.ebpf.o
SURVIVE /root/prodigy
EXECUTE ["/root/ready_container"]
EOF

if ! (
   cd "${tmpdir}"
   "${DISCOMBOBULATOR_BIN}" build \
      --file "${discombobulator_file}" \
      --output "${container_blob}" \
      --kind app \
      --context "bin=$(dirname "${READY_BIN}")" \
      --context "ebpf=$(dirname "${PRODIGY_BIN}")"
) >"${discombobulator_log}" 2>&1
then
   fail "discombobulator build failed"
fi

version_id=$(( ($(date +%s%N) & 281474976710655) ))
if [[ "${version_id}" -le 0 ]]
then
   version_id=1
fi

cat > "${plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${APPLICATION_ID},
    "versionID": ${version_id},
    "architecture": "${target_arch}",
    "filesystemMB": 64,
    "storageMB": 64,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 10000,
    "sTilHealthcheck": 10,
    "sTilKillable": 30
  },
  "minimumSubscriberCapacity": 1024,
  "isStateful": false,
  "canaryCount": 0,
  "canariesMustLiveForMinutes": 1,
  "stateless": {
    "nBase": 1,
    "maxPerRackRatio": 1.0,
    "maxPerMachineRatio": 1.0,
    "moveableDuringCompaction": true
  },
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF

read -r -d '' create_request <<EOF || true
{
  "name": "${cluster_name}",
  "deploymentMode": "test",
  "nBrains": 3,
  "machineSchemas": [
    {
      "schema": "bootstrap",
      "kind": "vm",
      "vmImageURI": "test://netns-local"
    }
  ],
  "test": {
    "workspaceRoot": "${workspace_root}",
    "machineCount": 3,
    "brainBootstrapFamily": "ipv4",
    "enableFakeIpv4Boundary": false,
    "interContainerMTU": ${EXPECTED_MTU},
    "host": {
      "mode": "local"
    }
  }
}
EOF

if ! run_mothership createCluster "${create_request}" >"${tmpdir}/create_cluster.log" 2>&1
then
   if rg -q "created=1" "${tmpdir}/create_cluster.log"
   then
      cluster_created=1
   fi
   fail "mothership createCluster did not succeed for MTU regression"
fi
cluster_created=1

if ! timeout 60s bash -lc '
   while [[ ! -s "'"${manifest_path}"'" ]]
   do
      sleep 0.1
   done
' >/dev/null
then
   fail "timed out waiting for createCluster manifest"
fi

reserved=0
reserve_json="$(printf '{"applicationName":"%s","requestedApplicationID":%u}' "${application_name}" "${APPLICATION_ID}")"
for _ in $(seq 1 40)
do
   if run_mothership reserveApplicationID "${cluster_name}" "${reserve_json}" >"${tmpdir}/mothership.reserve.log" 2>&1
   then
      if rg -q "reserveApplicationID success=1" "${tmpdir}/mothership.reserve.log" \
         && rg -q "appID=${APPLICATION_ID}" "${tmpdir}/mothership.reserve.log"
      then
         reserved=1
         break
      fi
   fi

   sleep 0.25
done

if [[ "${reserved}" -ne 1 ]]
then
   fail "reserveApplicationID did not succeed for MTU regression"
fi

deploy_ok=0
for _ in $(seq 1 "${DEPLOY_WAIT_S}")
do
   deploy_attempt_rc=0
   if ! run_mothership deploy "${cluster_name}" "$(cat "${plan_json}")" "${container_blob}" >"${tmpdir}/mothership.deploy.log" 2>&1
   then
      deploy_attempt_rc=$?
   fi

   if [[ "${deploy_attempt_rc}" -eq 0 ]] && rg -q "SpinApplicationResponseCode::okay" "${tmpdir}/mothership.deploy.log"
   then
      deploy_ok=1
      break
   fi

   if grep -Eq "cluster can only fit 0 total instances|we would need to schedule" "${tmpdir}/mothership.deploy.log"
   then
      sleep 1
      continue
   fi

   break
done

if [[ "${deploy_ok}" -ne 1 ]]
then
   run_mothership clusterReport "${cluster_name}" >"${tmpdir}/mothership.clusterreport.log" 2>&1 || true
   fail "mothership deploy did not succeed for MTU regression"
fi

healthy=0
for _ in $(seq 1 120)
do
   if run_mothership applicationReport "${cluster_name}" "${application_name}" >"${tmpdir}/mothership.applicationreport.log" 2>&1
   then
      if grep -Eq '^[[:space:]]*nHealthy:[[:space:]]*1$' "${tmpdir}/mothership.applicationreport.log"
      then
         healthy=1
         break
      fi
   fi

   sleep 0.5
done

if [[ "${healthy}" -ne 1 ]]
then
   run_mothership clusterReport "${cluster_name}" >"${tmpdir}/mothership.clusterreport.log" 2>&1 || true
   fail "deployed MTU regression container never became healthy"
fi

spin_match="$(rg -n "spinContainer start ok .* appID=${APPLICATION_ID}.* pid=" "${workspace_root}"/logs/brain*.stdout.log | tail -n 1 || true)"
if [[ -z "${spin_match}" ]]
then
   fail "unable to locate deployed container start log for appID=${APPLICATION_ID}"
fi

brain_log="${spin_match%%:*}"
container_pid="$(printf '%s\n' "${spin_match}" | sed -n 's/.* pid=\([0-9][0-9]*\).*/\1/p' | tail -n 1)"
brain_index="$(basename "${brain_log}" | sed -n 's/^brain\([0-9][0-9]*\)\..*/\1/p')"

if [[ -z "${container_pid}" || -z "${brain_index}" ]]
then
   echo "spin match: ${spin_match}" >&2
   fail "unable to parse deployment host details from log line"
fi

brain_pid="$(python3 - "${manifest_path}" "${brain_index}" <<'PY'
import json
import sys

manifest_path = sys.argv[1]
brain_index = int(sys.argv[2])

with open(manifest_path, "r", encoding="utf-8") as fh:
    manifest = json.load(fh)

for node in manifest["nodes"]:
    if int(node["index"]) == brain_index:
        print(node["pid"])
        raise SystemExit(0)

raise SystemExit(1)
PY
)" || true

if [[ -z "${brain_pid}" ]]
then
   fail "unable to resolve hosting brain pid for brain${brain_index}"
fi

host_netkit_if="$(find_runtime_netkit_if "${brain_pid}" "_netkit0")"
container_netkit_if="$(find_runtime_netkit_if "${container_pid}" "_netkit1")"

if [[ -z "${host_netkit_if}" || -z "${container_netkit_if}" ]]
then
   echo "brain pid=${brain_pid} container pid=${container_pid}" >&2
   nsenter -t "${brain_pid}" -n ip -o link show >&2 || true
   nsenter -t "${container_pid}" -n ip -o link show >&2 || true
   fail "unable to resolve runtime-created netkit interface names"
fi

host_netkit_mtu="$(extract_link_mtu nsenter -t "${brain_pid}" -n ip -o link show dev "${host_netkit_if}")"
container_netkit_mtu="$(extract_link_mtu nsenter -t "${container_pid}" -n ip -o link show dev "${container_netkit_if}")"
host_netkit_gso="$(extract_link_detail_field gso_max_size nsenter -t "${brain_pid}" -n ip -details link show dev "${host_netkit_if}")"
host_netkit_gso_segs="$(extract_link_detail_field gso_max_segs nsenter -t "${brain_pid}" -n ip -details link show dev "${host_netkit_if}")"
host_netkit_gro="$(extract_link_detail_field gro_max_size nsenter -t "${brain_pid}" -n ip -details link show dev "${host_netkit_if}")"
host_netkit_gso_ipv4="$(extract_link_detail_field gso_ipv4_max_size nsenter -t "${brain_pid}" -n ip -details link show dev "${host_netkit_if}")"
host_netkit_gro_ipv4="$(extract_link_detail_field gro_ipv4_max_size nsenter -t "${brain_pid}" -n ip -details link show dev "${host_netkit_if}")"
container_netkit_gso="$(extract_link_detail_field gso_max_size nsenter -t "${container_pid}" -n ip -details link show dev "${container_netkit_if}")"
container_netkit_gso_segs="$(extract_link_detail_field gso_max_segs nsenter -t "${container_pid}" -n ip -details link show dev "${container_netkit_if}")"
container_netkit_gro="$(extract_link_detail_field gro_max_size nsenter -t "${container_pid}" -n ip -details link show dev "${container_netkit_if}")"
container_netkit_gso_ipv4="$(extract_link_detail_field gso_ipv4_max_size nsenter -t "${container_pid}" -n ip -details link show dev "${container_netkit_if}")"
container_netkit_gro_ipv4="$(extract_link_detail_field gro_ipv4_max_size nsenter -t "${container_pid}" -n ip -details link show dev "${container_netkit_if}")"
egress_prog_id="$(find_netkit_prog_id "${brain_pid}" "${host_netkit_if}" "container_egress_router")"

if [[ -z "${egress_prog_id}" ]]
then
   fail "unable to resolve attached container egress program id for ${host_netkit_if}"
fi

policy_map_id="$(find_named_map_id_for_prog "${brain_pid}" "${egress_prog_id}" "container_network_policy_map" || true)"
if [[ -z "${policy_map_id}" ]]
then
   fail "unable to resolve container_network_policy_map for program ${egress_prog_id}"
fi

policy_mtu="$(lookup_policy_inter_container_mtu "${brain_pid}" "${policy_map_id}" || true)"
if [[ -z "${policy_mtu}" ]]
then
   fail "unable to read container_network_policy_map for program ${egress_prog_id}"
fi

echo "observed host mtu=${host_netkit_mtu} host_gso=${host_netkit_gso} host_gso_segs=${host_netkit_gso_segs} host_gro=${host_netkit_gro} host_gso_ipv4=${host_netkit_gso_ipv4} host_gro_ipv4=${host_netkit_gro_ipv4} container mtu=${container_netkit_mtu} container_gso=${container_netkit_gso} container_gso_segs=${container_netkit_gso_segs} container_gro=${container_netkit_gro} container_gso_ipv4=${container_netkit_gso_ipv4} container_gro_ipv4=${container_netkit_gro_ipv4} policy interContainerMTU=${policy_mtu} brain=${brain_index} host_if=${host_netkit_if} container_if=${container_netkit_if} prog_id=${egress_prog_id} policy_map=${policy_map_id}"

assert_link_mtu "${host_netkit_mtu}" "brain${brain_index}/${host_netkit_if}"
assert_link_mtu "${container_netkit_mtu}" "container/${container_netkit_if}"
assert_link_budget "${host_netkit_gso}" "gso_max_size" "brain${brain_index}/${host_netkit_if}"
assert_link_budget_segments "${host_netkit_gso_segs}" "gso_max_segs" "1" "brain${brain_index}/${host_netkit_if}"
assert_link_budget "${host_netkit_gro}" "gro_max_size" "brain${brain_index}/${host_netkit_if}"
assert_link_budget "${host_netkit_gso_ipv4}" "gso_ipv4_max_size" "brain${brain_index}/${host_netkit_if}"
assert_link_budget "${host_netkit_gro_ipv4}" "gro_ipv4_max_size" "brain${brain_index}/${host_netkit_if}"
assert_link_budget "${container_netkit_gso}" "gso_max_size" "container/${container_netkit_if}"
assert_link_budget_segments "${container_netkit_gso_segs}" "gso_max_segs" "1" "container/${container_netkit_if}"
assert_link_budget "${container_netkit_gro}" "gro_max_size" "container/${container_netkit_if}"
assert_link_budget "${container_netkit_gso_ipv4}" "gso_ipv4_max_size" "container/${container_netkit_if}"
assert_link_budget "${container_netkit_gro_ipv4}" "gro_ipv4_max_size" "container/${container_netkit_if}"
assert_policy_mtu "${policy_mtu}" "brain${brain_index}/${host_netkit_if}"

if ! run_mothership removeCluster "${cluster_name}" >"${tmpdir}/remove_cluster.log" 2>&1
then
   fail "removeCluster did not succeed after MTU regression"
fi
cluster_removed=1

echo "PASS: runtime-created container netkit links and egress policy inherit packet budget ${EXPECTED_MTU}"
