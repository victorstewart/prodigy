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
   echo "SKIP: requires root for netns + container deployment smoke"
   exit 77
fi

if [[ ! -x "${PRODIGY_BIN}" ]]
then
   echo "FAIL: prodigy binary is not executable: ${PRODIGY_BIN}"
   exit 1
fi

if [[ ! -x "${MOTHERSHIP_BIN}" ]]
then
   echo "FAIL: mothership binary is not executable: ${MOTHERSHIP_BIN}"
   exit 1
fi

if [[ ! -x "${PINGPONG_BIN}" ]]
then
   echo "FAIL: pingpong container binary is not executable: ${PINGPONG_BIN}"
   exit 1
fi

if [[ ! -x "${HARNESS}" ]]
then
   echo "FAIL: harness is not executable: ${HARNESS}"
   exit 1
fi

deps=(awk btrfs cmake install ip ldd mkfs.btrfs mount python3 stat timeout umount zstd)
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
PRODIGY_DIR="$(dirname "${PRODIGY_BIN}")"

tmpdir="$(mktemp -d)"
workspace_root="${tmpdir}/workspace"
manifest_path="${workspace_root}/test-cluster-manifest.json"
mothership_db_path="${tmpdir}/mothership-pingpong.tidesdb"
keep_tmp="${PRODIGY_DEV_KEEP_TMP:-0}"
cluster_name="pingpong-deploy-$(date -u +%Y%m%d-%H%M%S)"
create_log="${tmpdir}/create_cluster.log"
reserve_log="${tmpdir}/reserve_application.log"
deploy_log="${tmpdir}/deploy.log"
application_log="${tmpdir}/application_report.log"
cluster_report_log="${tmpdir}/cluster_report.log"
deployment_subvol=""

cluster_created=0
target_arch=""
bundle_arch=""
containers_dir_created=0
containers_mount_created=0
containers_loop_image=""

detect_arches()
{
   local machine_arch

   machine_arch="$(uname -m)"
   case "${machine_arch}" in
      x86_64|amd64)
         target_arch="x86_64"
         bundle_arch="x86_64"
         ;;
      aarch64|arm64)
         target_arch="arm64"
         bundle_arch="aarch64"
         ;;
      riscv64|riscv)
         target_arch="riscv64"
         bundle_arch="riscv64"
         ;;
      *)
         echo "FAIL: unsupported host architecture for discombobulator smoke: ${machine_arch}" >&2
         return 1
         ;;
   esac
}

cleanup()
{
   set +e

   if [[ "${keep_tmp}" -eq 1 && -d "${workspace_root}" ]]
   then
      rm -rf "${tmpdir}/workspace-archive" >/dev/null 2>&1 || true
      cp -a "${workspace_root}" "${tmpdir}/workspace-archive" >/dev/null 2>&1 || true
   fi

   if [[ "${cluster_created}" -eq 1 ]]
   then
      env PRODIGY_MOTHERSHIP_TEST_HARNESS="${HARNESS}" \
         PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" removeCluster "${cluster_name}" >/dev/null 2>&1 || true
   fi

   if [[ -n "${deployment_subvol}" && -e "${deployment_subvol}" ]]
   then
      btrfs property set -f "${deployment_subvol}" ro false >/dev/null 2>&1 || true
      btrfs subvolume delete "${deployment_subvol}" >/dev/null 2>&1 || true
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

copy_binary_and_libs_into_subvol()
{
   local binary_path="$1"
   local subvol_root="$2"
   local install_path="${3:-/root/pingpong_container}"
   local execute_arch="$4"
   local rootfs_root="${subvol_root}/rootfs"
   local metadata_dir="${subvol_root}/.prodigy-private"

   mkdir -p "${rootfs_root}$(dirname "${install_path}")" "${rootfs_root}/etc" "${metadata_dir}"
   install -m 0755 "${binary_path}" "${rootfs_root}${install_path}"

   cat > "${metadata_dir}/launch.metadata" <<EOF
{
  "execute_path": "${install_path}",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "${execute_arch}"
}
EOF

   while IFS= read -r libpath
   do
      if [[ -z "${libpath}" ]]
      then
         continue
      fi

      if [[ -e "${libpath}" ]]
      then
         cp -aL --parents "${libpath}" "${rootfs_root}"
      fi
   done < <(
      ldd "${binary_path}" | awk '
         /=>/ {
            if ($3 ~ /^\//) print $3;
         }
         /^[[:space:]]*\// {
            print $1;
         }
      ' | sort -u
   )
}

detect_arches

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
      echo "FAIL: /containers is mounted but not btrfs (found ${containers_fs_type})"
      exit 1
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
            *)
               existing_entries_ok=0
               break
               ;;
         esac
      done < <(find /containers -mindepth 1 -maxdepth 1 -print 2>/dev/null)

      if [[ "${existing_entries_ok}" -ne 1 ]]
      then
         echo "FAIL: /containers exists on non-btrfs fs and is not safely overmountable"
         exit 1
      fi
   fi

   containers_loop_image="${tmpdir}/containers.loop.img"
   truncate -s 2G "${containers_loop_image}"
   mkfs.btrfs -f "${containers_loop_image}" >/dev/null
   mount -o loop "${containers_loop_image}" /containers
   containers_mount_created=1
fi

mkdir -p /containers/store /containers/storage "${workspace_root}"

bundle_path="${PRODIGY_DIR}/prodigy.${bundle_arch}.bundle.tar.zst"
if [[ ! -f "${bundle_path}" ]]
then
   if [[ -f "${PRODIGY_DIR}/CMakeCache.txt" ]]
   then
      cmake --build "${PRODIGY_DIR}" -j"$(nproc)" --target prodigy_bundle prodigy_bundle_sha256 >/dev/null
   fi
fi

if [[ ! -f "${bundle_path}" ]]
then
   echo "FAIL: required bundled prodigy artifact is missing: ${bundle_path}"
   exit 1
fi

application_id=101
application_name="${cluster_name}.pingpong"
version_id=$(( ($(date +%s%N) & 281474976710655) ))
if [[ "${version_id}" -le 0 ]]
then
   version_id=1
fi
deployment_id=$(( (application_id << 48) | version_id ))
ping_port=19090

plan_json="${tmpdir}/pingpong.plan.json"
cat > "${plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${application_id},
    "versionID": ${version_id},
    "architecture": "${bundle_arch}",
    "filesystemMB": 64,
    "storageMB": 64,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 10000,
    "sTilHealthcheck": 15,
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
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF

container_blob="${tmpdir}/pingpong.container.zst"
deployment_subvol="/containers/${deployment_id}"
btrfs subvolume create "${deployment_subvol}" >/dev/null
copy_binary_and_libs_into_subvol "${PINGPONG_BIN}" "${deployment_subvol}" "/root/pingpong_container" "${bundle_arch}"
btrfs property set -f "${deployment_subvol}" ro true >/dev/null
btrfs send "${deployment_subvol}" | zstd -19 -T0 -q -o "${container_blob}"
btrfs property set -f "${deployment_subvol}" ro false >/dev/null
btrfs subvolume delete "${deployment_subvol}" >/dev/null
deployment_subvol=""

read -r -d '' CREATE_REQUEST <<EOF || true
{
  "name": "${cluster_name}",
  "deploymentMode": "test",
  "nBrains": 1,
  "machineSchemas": [
    {
      "schema": "test-brain",
      "kind": "vm",
      "vmImageURI": "test://netns-local"
    }
  ],
  "test": {
    "workspaceRoot": "${workspace_root}",
    "machineCount": 2,
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
   sed -n '1,220p' "${create_log}" || true
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
   sed -n '1,220p' "${create_log}" || true
   exit 1
fi

read -r parent_ns <<EOF
$(python3 - "${manifest_path}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)

print(manifest["parentNamespace"])
PY
)
EOF

if [[ -z "${parent_ns}" ]]
then
   echo "FAIL: unable to resolve parent namespace from manifest"
   sed -n '1,220p' "${create_log}" || true
   exit 1
fi

mapfile -t node_ips < <(python3 - "${manifest_path}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)

for node in manifest["nodes"]:
    ip = node.get("ipv4", "")
    if ip:
        print(ip)
PY
)

if [[ "${#node_ips[@]}" -eq 0 ]]
then
   echo "FAIL: test cluster manifest did not include any node IPv4 addresses"
   sed -n '1,220p' "${create_log}" || true
   exit 1
fi

reserve_json="$(printf '{"applicationName":"%s","requestedApplicationID":%u}' "${application_name}" "${application_id}")"
reserved=0
for _ in $(seq 1 40)
do
   if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" reserveApplicationID "${cluster_name}" "${reserve_json}" \
      >"${reserve_log}" 2>&1
   then
      if grep -q "reserveApplicationID success=1" "${reserve_log}" \
         && grep -q "appID=${application_id}" "${reserve_log}"
      then
         reserved=1
         break
      fi
   fi

   sleep 0.25
done

if [[ "${reserved}" -ne 1 ]]
then
   echo "FAIL: reserveApplicationID for pingpong deployment failed"
   sed -n '1,220p' "${reserve_log}" || true
   exit 1
fi

deployed=0
for _ in $(seq 1 120)
do
   if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" deploy "${cluster_name}" "$(cat "${plan_json}")" "${container_blob}" \
      >"${deploy_log}" 2>&1
   then
      deployed=1
      break
   fi

   if ! grep -Eq 'cluster can only fit 0 total instances|we would need to schedule' "${deploy_log}"
   then
      break
   fi

   sleep 0.5
done

if [[ "${deployed}" -ne 1 ]]
then
   echo "FAIL: pingpong deployment failed"
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" \
      >"${cluster_report_log}" 2>&1 || true
   sed -n '1,240p' "${cluster_report_log}" || true
   sed -n '1,220p' "${deploy_log}" || true
   exit 1
fi

healthy=0
for _ in $(seq 1 120)
do
   if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" "${application_name}" \
      >"${application_log}" 2>&1
   then
      if grep -Eq '^[[:space:]]*nHealthy:[[:space:]]*1$' "${application_log}"
      then
         healthy=1
         break
      fi
   fi

   sleep 0.5
done

if [[ "${healthy}" -ne 1 ]]
then
   echo "FAIL: pingpong deployment never became healthy"
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" \
      >"${cluster_report_log}" 2>&1 || true
   sed -n '1,240p' "${cluster_report_log}" || true
   sed -n '1,200p' "${application_log}" || true
   sed -n '1,200p' "${deploy_log}" || true
   exit 1
fi

ping_ok=0
ping_ip=""
for _ in $(seq 1 120)
do
   for ip in "${node_ips[@]}"
   do
      if ip netns exec "${parent_ns}" \
         env PRODIGY_PING_IP="${ip}" PRODIGY_PING_PORT="${ping_port}" PRODIGY_PING_PAYLOAD="ping" PRODIGY_PING_EXPECT="pong" \
         timeout --preserve-status -k 1s 3s bash -lc '
            exec 3<>"/dev/tcp/${PRODIGY_PING_IP}/${PRODIGY_PING_PORT}" || exit 1
            printf "%s\n" "${PRODIGY_PING_PAYLOAD}" >&3

            if ! IFS= read -r -t 2 response <&3
            then
               exit 2
            fi

            [[ "${response}" == "${PRODIGY_PING_EXPECT}" ]]
         ' >/dev/null 2>&1
      then
         ping_ok=1
         ping_ip="${ip}"
         break 2
      fi
   done

   sleep 0.5
done

if [[ "${ping_ok}" -ne 1 ]]
then
   echo "FAIL: deployed pingpong container never answered ping"
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" \
      >"${cluster_report_log}" 2>&1 || true
   sed -n '1,240p' "${cluster_report_log}" || true
   sed -n '1,200p' "${application_log}" || true
   sed -n '1,200p' "${deploy_log}" || true
   exit 1
fi

echo "PASS: pingpong deploy smoke answered ping on ${ping_ip}:${ping_port}"
