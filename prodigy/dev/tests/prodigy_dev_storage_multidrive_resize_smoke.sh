#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
PINGPONG_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/prodigy_dev_discombobulator_artifact_helpers.sh"
SCRIPT_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_STORAGE_MULTIDRIVE_RESIZE_SMOKE_MOUNT_NS_READY bash "${SCRIPT_SELF}" "$@"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${PINGPONG_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_pingpong_container"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for isolated multi-drive storage smoke"
   exit 77
fi

deps=(awk btrfs cargo mkfs.btrfs mount umount stat zstd timeout ip nsenter python3 rg)
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
PINGPONG_BIN="$(readlink -f "${PINGPONG_BIN}" 2>/dev/null || printf '%s' "${PINGPONG_BIN}")"
target_arch="$(prodigy_dev_detect_target_arch)"

tmpdir="$(mktemp -d)"
workspace_root="${tmpdir}/workspace"
manifest_path="${workspace_root}/test-cluster-manifest.json"
cluster_name="storage-multidrive-$(date -u +%Y%m%d-%H%M%S)"
mothership_db_path="${tmpdir}/mothership-storage.tidesdb"
keep_tmp="${PRODIGY_DEV_KEEP_TMP:-0}"
create_log="${tmpdir}/create_cluster.log"
deploy_log="${tmpdir}/deploy.log"
application_log="${tmpdir}/application_report.log"
cluster_report_log="${tmpdir}/cluster_report.log"
remove_log="${tmpdir}/remove_cluster.log"
btrfs_show_log="${tmpdir}/btrfs_filesystem_show.log"
traffic_log="${tmpdir}/traffic.log"

cluster_created=0
archive_workspace=0

cleanup()
{
   set +e

   if [[ "${archive_workspace}" -eq 1 && -d "${workspace_root}" ]]
   then
      rm -rf "${tmpdir}/workspace-archive" >/dev/null 2>&1 || true
      mkdir -p "${tmpdir}/workspace-archive"
      find "${workspace_root}" -maxdepth 1 -type f \( -name '*.log' -o -name '*.json' -o -name '*.ready' -o -name '*.failure' \) \
         -exec cp -a {} "${tmpdir}/workspace-archive/" \; >/dev/null 2>&1 || true
   fi

   if [[ "${cluster_created}" -eq 1 ]]
   then
      env \
         PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" removeCluster "${cluster_name}" \
         >"${remove_log}" 2>&1 || true
   fi

   if [[ "${keep_tmp}" -eq 1 ]]
   then
      echo "KEEP_TMP: ${tmpdir}"
   else
      rm -rf "${tmpdir}"
   fi
}
trap cleanup EXIT

mkdir -p "${workspace_root}"

application_id=6
version_id=$(( ($(date +%s%N) & 281474976710655) ))
if [[ "${version_id}" -le 0 ]]
then
   version_id=1
fi
deployment_id=$(( (application_id << 48) | version_id ))

read -r -d '' CREATE_REQUEST <<EOF || true
{
  "name": "${cluster_name}",
  "deploymentMode": "test",
  "autoscaleIntervalSeconds": 3,
  "nBrains": 1,
  "machineSchemas": [
    {
      "schema": "bootstrap",
      "kind": "vm",
      "vmImageURI": "test://netns-local"
    }
  ],
  "test": {
    "workspaceRoot": "${workspace_root}",
    "machineCount": 1,
    "machineStorageMB": 8192,
    "storageDeviceCount": 2,
    "storageDeviceMB": 1024,
    "brainBootstrapFamily": "ipv4",
    "enableFakeIpv4Boundary": false
  }
}
EOF

if ! env \
   PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" createCluster "${CREATE_REQUEST}" \
   >"${create_log}" 2>&1
then
   echo "FAIL: createCluster test cluster failed"
   sed -n '1,200p' "${create_log}" || true
   exit 1
fi
cluster_created=1

for _ in $(seq 1 300)
do
   if [[ -s "${manifest_path}" ]]
   then
      break
   fi
   sleep 0.2
done

if [[ ! -s "${manifest_path}" ]]
then
   echo "FAIL: test cluster manifest did not become ready"
   sed -n '1,200p' "${create_log}" || true
   exit 1
fi

brain_pid="$(python3 - "${manifest_path}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
print(next((node.get("pid", 0) for node in manifest.get("nodes", []) if node.get("role") == "brain"), 0))
PY
)"

if ! [[ "${brain_pid}" =~ ^[0-9]+$ ]] || [[ "${brain_pid}" -le 0 ]] || ! kill -0 "${brain_pid}" >/dev/null 2>&1
then
   echo "FAIL: unable to parse live brain pid"
   exit 1
fi

artifact_project_dir="${tmpdir}/storage-artifact"
discombobulator_file="${artifact_project_dir}/PingPongStorage.DiscombobuFile"
container_blob="${tmpdir}/storage.container.zst"
mkdir -p "${artifact_project_dir}"
cat > "${discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {bin} ./$(basename "${PINGPONG_BIN}") /root/pingpong_container
SURVIVE /root/pingpong_container
EOF
prodigy_dev_write_common_prodigy_assets "${discombobulator_file}"
cat >> "${discombobulator_file}" <<'EOF'
EXECUTE ["/root/pingpong_container"]
EOF

if ! prodigy_dev_run_discombobulator_build \
   "${artifact_project_dir}" \
   "${discombobulator_file}" \
   "${container_blob}" \
   "bin=$(dirname "${PINGPONG_BIN}")" \
   "ebpf=$(dirname "${PRODIGY_BIN}")"
then
   archive_workspace=1
   echo "FAIL: unable to build storage test artifact"
   exit 1
fi

plan_json="${tmpdir}/storage.plan.json"
cat > "${plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${application_id},
    "versionID": ${version_id},
    "architecture": "${target_arch}",
    "filesystemMB": 64,
    "storageMB": 256,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
    "sTilKillable": 30
  },
  "useHostNetworkNamespace": true,
  "minimumSubscriberCapacity": 1024,
  "isStateful": false,
  "stateless": {
    "nBase": 1,
    "maxPerRackRatio": 1.0,
    "maxPerMachineRatio": 1.0,
    "moveableDuringCompaction": true
  },
  "verticalScalers": [
    {
      "name": "pingpong.requests",
      "resource": "ScalingDimension::storage",
      "increment": 256,
      "percentile": 90,
      "lookbackSeconds": 15,
      "threshold": 0.5,
      "minValue": 256,
      "maxValue": 512,
      "direction": "upscale"
    }
  ],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF

if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" deploy "${cluster_name}" "$(cat "${plan_json}")" "${container_blob}" \
   >"${deploy_log}" 2>&1
then
   archive_workspace=1
   echo "FAIL: storage deployment failed"
   sed -n '1,200p' "${deploy_log}" || true
   exit 1
fi

healthy=0
for _ in $(seq 1 120)
do
   if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" Nametag \
      >"${application_log}" 2>&1
   then
      if rg -q '^[[:space:]]*nHealthy:[[:space:]]*1$' "${application_log}"
      then
         healthy=1
         break
      fi
   fi

   sleep 0.5
done

if [[ "${healthy}" -ne 1 ]]
then
   archive_workspace=1
   echo "FAIL: storage deployment never became healthy"
   sed -n '1,240p' "${application_log}" || true
   exit 1
fi

traffic_payload="$(printf 'ping\n%.0s' {1..80})"
if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" probeTestCluster "${cluster_name}" 10.0.0.10 19090 "${traffic_payload}" pong 10000 0 \
   >"${traffic_log}" 2>&1
then
   archive_workspace=1
   echo "FAIL: Mothership test-provider traffic probe failed"
   sed -n '1,160p' "${traffic_log}" || true
   exit 1
fi

scaled=0
for _ in $(seq 1 180)
do
   if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" Nametag \
      >"${application_log}" 2>&1
   then
      max_storage="$(python3 - "${application_log}" <<'PY'
import re
import sys
text = open(sys.argv[1], "r", encoding="utf-8", errors="replace").read()
values = [int(v) for v in re.findall(r"containerRuntime: cores=\d+ memMB=\d+ storMB=(\d+)", text)]
print(max(values) if values else 0)
PY
)"
      if [[ "${max_storage}" -ge 512 ]]
      then
         scaled=1
         break
      fi
   fi

   sleep 0.5
done

if [[ "${scaled}" -ne 1 ]]
then
   archive_workspace=1
   echo "FAIL: runtime storage never scaled to 512MB"
   sed -n '1,240p' "${application_log}" || true
   sed -n '1,120p' "${traffic_log}" || true
   exit 1
fi

brain_mount_exec=(nsenter -t "${brain_pid}" -m --)
mapfile -t storage_a_files < <("${brain_mount_exec[@]}" find /mnt/prodigy-storage/1/.prodigy/container-storage -maxdepth 1 -type f -name '*.btrfs.loop' | sort)
mapfile -t storage_b_files < <("${brain_mount_exec[@]}" find /mnt/prodigy-storage/2/.prodigy/container-storage -maxdepth 1 -type f -name '*.btrfs.loop' | sort)

if [[ "${#storage_a_files[@]}" -ne 1 || "${#storage_b_files[@]}" -ne 1 ]]
then
   archive_workspace=1
   echo "FAIL: expected one loop backing file per mounted filesystem"
   "${brain_mount_exec[@]}" find /mnt/prodigy-storage -maxdepth 4 -printf '%p\n' | sort
   exit 1
fi

storage_a_size="$("${brain_mount_exec[@]}" stat -c '%s' "${storage_a_files[0]}")"
storage_b_size="$("${brain_mount_exec[@]}" stat -c '%s' "${storage_b_files[0]}")"
min_bytes=$((256 * 1024 * 1024))
if [[ "${storage_a_size}" -lt "${min_bytes}" || "${storage_b_size}" -lt "${min_bytes}" ]]
then
   archive_workspace=1
   echo "FAIL: backing files did not grow to the resized per-device target"
   printf 'storage_a=%s bytes=%s\n' "${storage_a_files[0]}" "${storage_a_size}"
   printf 'storage_b=%s bytes=%s\n' "${storage_b_files[0]}" "${storage_b_size}"
   exit 1
fi

storage_root="$("${brain_mount_exec[@]}" sh -lc 'find /containers/storage -mindepth 1 -maxdepth 1 -type d | head -n 1' 2>/dev/null || true)"
if [[ -z "${storage_root}" ]]
then
   archive_workspace=1
   echo "FAIL: unable to locate live container storage root"
   exit 1
fi

"${brain_mount_exec[@]}" btrfs filesystem show "${storage_root}" >"${btrfs_show_log}" 2>&1 || {
   archive_workspace=1
   echo "FAIL: btrfs filesystem show failed"
   sed -n '1,200p' "${btrfs_show_log}" || true
   exit 1
}

if [[ "$(rg -c 'devid' "${btrfs_show_log}")" -lt 2 ]]
then
   archive_workspace=1
   echo "FAIL: live btrfs filesystem did not expose multiple devices"
   sed -n '1,200p' "${btrfs_show_log}" || true
   exit 1
fi

echo "PASS: multi-drive loop-backed storage smoke storageA=${storage_a_files[0]} storageB=${storage_b_files[0]}"
