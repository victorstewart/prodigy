#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
PINGPONG_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"

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

deps=(awk btrfs mkfs.btrfs mkfs.ext4 mount umount stat zstd ldd install timeout ip python3 rg losetup)
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

tmpdir="$(mktemp -d)"
workspace_root="${tmpdir}/workspace"
manifest_path="${workspace_root}/test-cluster-manifest.json"
cluster_name="storage-multidrive-$(date -u +%Y%m%d-%H%M%S)"
mothership_db_path="${tmpdir}/mothership-storage.tidesdb"
keep_tmp="${PRODIGY_DEV_KEEP_TMP:-0}"
allow_containers_overmount="${PRODIGY_DEV_ALLOW_CONTAINERS_OVERMOUNT:-0}"
create_log="${tmpdir}/create_cluster.log"
configure_log="${tmpdir}/configure.log"
deploy_log="${tmpdir}/deploy.log"
application_log="${tmpdir}/application_report.log"
cluster_report_log="${tmpdir}/cluster_report.log"
remove_log="${tmpdir}/remove_cluster.log"
btrfs_show_log="${tmpdir}/btrfs_filesystem_show.log"
traffic_log="${tmpdir}/traffic.log"

containers_dir_created=0
containers_mount_created=0
containers_loop_image=""
storage_a_img="${tmpdir}/storage-a.img"
storage_b_img="${tmpdir}/storage-b.img"
storage_a_mount="/mnt/prodigy-storage-a"
storage_b_mount="/mnt/prodigy-storage-b"
storage_a_mounted=0
storage_b_mounted=0
storage_a_dir_created=0
storage_b_dir_created=0
deployment_subvol=""
cluster_created=0
archive_workspace=0

cleanup()
{
   set +e

   if [[ "${archive_workspace}" -eq 1 && -d "${workspace_root}" ]]
   then
      rm -rf "${tmpdir}/workspace-archive" >/dev/null 2>&1 || true
      cp -a "${workspace_root}" "${tmpdir}/workspace-archive" >/dev/null 2>&1 || true
   fi

   if [[ "${cluster_created}" -eq 1 ]]
   then
      env PRODIGY_MOTHERSHIP_TEST_HARNESS="${HARNESS}" \
         PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" removeCluster "${cluster_name}" \
         >"${remove_log}" 2>&1 || true
   fi

   if [[ -n "${deployment_subvol}" && -e "${deployment_subvol}" ]]
   then
      btrfs property set -f "${deployment_subvol}" ro false >/dev/null 2>&1 || true
      btrfs subvolume delete "${deployment_subvol}" >/dev/null 2>&1 || true
   fi

   if [[ "${storage_a_mounted}" -eq 1 ]]
   then
      umount "${storage_a_mount}" >/dev/null 2>&1 || true
   fi

   if [[ "${storage_b_mounted}" -eq 1 ]]
   then
      umount "${storage_b_mount}" >/dev/null 2>&1 || true
   fi

   if [[ "${storage_a_dir_created}" -eq 1 ]]
   then
      rmdir "${storage_a_mount}" >/dev/null 2>&1 || true
   fi

   if [[ "${storage_b_dir_created}" -eq 1 ]]
   then
      rmdir "${storage_b_mount}" >/dev/null 2>&1 || true
   fi

   if [[ "${containers_mount_created}" -eq 1 ]]
   then
      umount /containers >/dev/null 2>&1 || true
   fi

   if [[ "${containers_dir_created}" -eq 1 ]]
   then
      rmdir /containers >/dev/null 2>&1 || true
   fi

   if [[ "${keep_tmp}" -eq 1 ]]
   then
      echo "KEEP_TMP: ${tmpdir}"
   else
      rm -rf "${tmpdir}"
   fi
}
trap cleanup EXIT

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
      if [[ "${allow_containers_overmount}" != "1" ]]
      then
         echo "FAIL: /containers is mounted but not btrfs (found ${containers_fs_type})"
         exit 1
      fi
   fi

   if [[ -n "$(ls -A /containers 2>/dev/null)" ]]
   then
      echo "FAIL: /containers exists on non-btrfs fs and is not empty"
      exit 1
   fi

   containers_loop_image="${tmpdir}/containers.loop.img"
   truncate -s 2G "${containers_loop_image}"
   mkfs.btrfs -f "${containers_loop_image}" >/dev/null
   mount -o loop "${containers_loop_image}" /containers
   containers_mount_created=1
fi

mkdir -p /containers/store /containers/storage "${workspace_root}"

if [[ ! -d "${storage_a_mount}" ]]
then
   mkdir -p "${storage_a_mount}"
   storage_a_dir_created=1
fi

if [[ ! -d "${storage_b_mount}" ]]
then
   mkdir -p "${storage_b_mount}"
   storage_b_dir_created=1
fi

truncate -s 1G "${storage_a_img}"
truncate -s 1G "${storage_b_img}"
mkfs.ext4 -F "${storage_a_img}" >/dev/null
mkfs.ext4 -F "${storage_b_img}" >/dev/null
mount -o loop "${storage_a_img}" "${storage_a_mount}"
storage_a_mounted=1
mount -o loop "${storage_b_img}" "${storage_b_mount}"
storage_b_mounted=1

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
    "brainBootstrapFamily": "ipv4",
    "enableFakeIpv4Boundary": false,
    "host": {
      "mode": "local"
    }
  }
}
EOF

if ! env PRODIGY_MOTHERSHIP_TEST_HARNESS="${HARNESS}" \
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

if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" configure "${cluster_name}" 122 bootstrap 4 8192 65536 3 \
   >"${configure_log}" 2>&1
then
   echo "FAIL: configure autoscale interval failed"
   sed -n '1,200p' "${configure_log}" || true
   exit 1
fi

read -r parent_ns <<EOF
$(python3 - "${manifest_path}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
print(manifest["parentNamespace"])
PY
)
EOF

if [[ -z "${parent_ns}" ]]
then
   echo "FAIL: unable to parse parent namespace"
   exit 1
fi

deployment_subvol="/containers/${deployment_id}"
btrfs subvolume create "${deployment_subvol}" >/dev/null
mkdir -p "${deployment_subvol}/root" "${deployment_subvol}/etc"
install -m 0755 "${PINGPONG_BIN}" "${deployment_subvol}/root/pingpong_container"

while IFS= read -r libpath
do
   if [[ -z "${libpath}" ]]
   then
      continue
   fi

   if [[ -e "${libpath}" ]]
   then
      cp -aL --parents "${libpath}" "${deployment_subvol}"
   fi
done < <(
   ldd "${PINGPONG_BIN}" | awk '
      /=>/ {
         if ($3 ~ /^\//) print $3;
      }
      /^[[:space:]]*\// {
         print $1;
      }
   ' | sort -u
)

plan_json="${tmpdir}/storage.plan.json"
cat > "${plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${application_id},
    "versionID": ${version_id},
    "filesystemMB": 64,
    "storageMB": 256,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
    "sTilKillable": 30
  },
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

container_blob="${tmpdir}/storage.container.zst"
btrfs property set -f "${deployment_subvol}" ro true >/dev/null
btrfs send "${deployment_subvol}" | zstd -19 -T0 -q -o "${container_blob}"
btrfs property set -f "${deployment_subvol}" ro false >/dev/null
btrfs subvolume delete "${deployment_subvol}" >/dev/null
deployment_subvol=""

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

ip netns exec "${parent_ns}" python3 - <<'PY' >"${traffic_log}" 2>&1
import socket
import time

target = ("10.0.0.10", 19090)
for _ in range(80):
    with socket.create_connection(target, timeout=2.0) as sock:
        sock.sendall(b"ping\n")
        data = sock.recv(64)
        if data != b"pong\n":
            raise SystemExit(f"unexpected reply: {data!r}")
    time.sleep(0.05)
PY

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

mapfile -t storage_a_files < <(find "${storage_a_mount}/.prodigy/container-storage" -maxdepth 1 -type f -name '*.btrfs.loop' | sort)
mapfile -t storage_b_files < <(find "${storage_b_mount}/.prodigy/container-storage" -maxdepth 1 -type f -name '*.btrfs.loop' | sort)

if [[ "${#storage_a_files[@]}" -ne 1 || "${#storage_b_files[@]}" -ne 1 ]]
then
   archive_workspace=1
   echo "FAIL: expected one loop backing file per mounted filesystem"
   find "${storage_a_mount}" "${storage_b_mount}" -maxdepth 3 -printf '%p\n' | sort
   exit 1
fi

storage_a_size="$(stat -c '%s' "${storage_a_files[0]}")"
storage_b_size="$(stat -c '%s' "${storage_b_files[0]}")"
min_bytes=$((256 * 1024 * 1024))
if [[ "${storage_a_size}" -lt "${min_bytes}" || "${storage_b_size}" -lt "${min_bytes}" ]]
then
   archive_workspace=1
   echo "FAIL: backing files did not grow to the resized per-device target"
   printf 'storage_a=%s bytes=%s\n' "${storage_a_files[0]}" "${storage_a_size}"
   printf 'storage_b=%s bytes=%s\n' "${storage_b_files[0]}" "${storage_b_size}"
   exit 1
fi

storage_root="$(find /containers/storage -mindepth 1 -maxdepth 1 -type d | head -n 1)"
if [[ -z "${storage_root}" ]]
then
   archive_workspace=1
   echo "FAIL: unable to locate live container storage root"
   exit 1
fi

btrfs filesystem show "${storage_root}" >"${btrfs_show_log}" 2>&1 || {
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
