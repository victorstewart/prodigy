#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
WHITEHOLE_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"
source "${SCRIPT_DIR}/prodigy_dev_discombobulator_artifact_helpers.sh"
SCRIPT_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_WHITEHOLE_FAKE_IPV4_SMOKE_MOUNT_NS_READY bash "${SCRIPT_SELF}" "$@"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${WHITEHOLE_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_whitehole_probe_container"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for isolated whitehole smoke"
   exit 77
fi

for path in "${PRODIGY_BIN}" "${MOTHERSHIP_BIN}" "${WHITEHOLE_BIN}" "${HARNESS}"
do
   if [[ ! -x "${path}" ]]
   then
      echo "FAIL: executable missing: ${path}"
      exit 1
   fi
done

deps=(awk btrfs cargo mkfs.btrfs mount umount stat zstd timeout ip nsenter python3 rg)
for cmd in "${deps[@]}"
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}"
      exit 77
   fi
done

if [[ "${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}" != "1" ]]
then
   echo "SKIP: whitehole fake IPv4 smoke requires fake IPv4 boundary BPF attach; set PRODIGY_DEV_ALLOW_BPF_ATTACH=1 only inside an authorized isolated VM"
   exit 77
fi

PRODIGY_BIN="$(readlink -f "${PRODIGY_BIN}" 2>/dev/null || printf '%s' "${PRODIGY_BIN}")"
MOTHERSHIP_BIN="$(readlink -f "${MOTHERSHIP_BIN}" 2>/dev/null || printf '%s' "${MOTHERSHIP_BIN}")"
WHITEHOLE_BIN="$(readlink -f "${WHITEHOLE_BIN}" 2>/dev/null || printf '%s' "${WHITEHOLE_BIN}")"
target_arch="$(prodigy_dev_detect_target_arch)"

tmpdir="$(mktemp -d)"
workspace_root="${tmpdir}/workspace"
manifest_path="${workspace_root}/test-cluster-manifest.json"
control_socket_path=""
keep_tmp="${PRODIGY_DEV_KEEP_TMP:-0}"
allow_containers_overmount="${PRODIGY_DEV_ALLOW_CONTAINERS_OVERMOUNT:-0}"
cluster_name="whitehole-fake-ipv4-$(date -u +%Y%m%d-%H%M%S)"
mothership_db_path="${tmpdir}/mothership-whitehole.tidesdb"
harness_log="${tmpdir}/harness.log"
create_log="${tmpdir}/create_cluster.log"
register_log="${tmpdir}/register_routable_subnet.log"
responder_log="${tmpdir}/whitehole_responder.log"
deploy_log="${tmpdir}/deploy.log"
cluster_status_log="${tmpdir}/cluster_status.log"
application_log="${tmpdir}/application_report.log"
cluster_report_log="${tmpdir}/cluster_report.log"
remove_log="${tmpdir}/remove_cluster.log"

containers_dir_created=0
containers_mount_created=0
containers_loop_image=""
responder_pid=""
cluster_created=0
archive_workspace=0

cleanup()
{
   set +e

   if [[ -n "${responder_pid}" ]]
   then
      kill "${responder_pid}" >/dev/null 2>&1 || true
      wait "${responder_pid}" 2>/dev/null || true
   fi

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

   if ! prodigy_dev_containers_root_is_safely_overmountable /containers
   then
      echo "FAIL: /containers exists on non-btrfs fs and is not safely overmountable"
      exit 1
   fi

   containers_loop_image="${tmpdir}/containers.loop.img"
   truncate -s 2G "${containers_loop_image}"
   mkfs.btrfs -f "${containers_loop_image}" >/dev/null
   mount -o loop "${containers_loop_image}" /containers
   containers_mount_created=1
fi

mkdir -p /containers/store /containers/storage "${workspace_root}"

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
  "bgp": {
    "enabled": true,
    "nextHop4": "10.0.0.1",
    "peers": [
      {
        "peerASN": 64512,
        "peerAddress": "10.0.0.1",
        "sourceAddress": "10.0.0.2"
      }
    ]
  },
  "test": {
    "workspaceRoot": "${workspace_root}",
    "machineCount": 1,
    "brainBootstrapFamily": "ipv4",
    "enableFakeIpv4Boundary": true,
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

read -r -d '' ROUTABLE_SUBNET_REQUEST <<EOF || true
{
  "name": "whitehole-fake-ipv4",
  "subnet": "198.18.0.0/16",
  "routing": "switchboardBGP",
  "usage": "whiteholes"
}
EOF

if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" registerRoutableSubnet "${cluster_name}" "${ROUTABLE_SUBNET_REQUEST}" \
   >"${register_log}" 2>&1
then
   echo "FAIL: registerRoutableSubnet for fake whitehole smoke failed"
   sed -n '1,200p' "${register_log}" || true
   exit 1
fi

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

read -r parent_pid control_socket_path <<EOF
$(python3 - "${manifest_path}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
print(manifest["parentPid"], manifest["controlSocketPath"])
PY
)
EOF

if [[ -z "${parent_pid}" || "${parent_pid}" == "0" || -z "${control_socket_path}" || ! -S "${control_socket_path}" ]]
then
   echo "FAIL: unable to parse persistent harness manifest or control socket path"
   exit 1
fi

parent_edge_ip="$(
   nsenter -t "${parent_pid}" -n ip -4 -o addr show | python3 -c '
import sys

for line in sys.stdin:
   fields = line.split()
   if len(fields) < 4 or fields[1] == "lo":
      continue

   address = fields[3].split("/", 1)[0]
   if address == "10.0.0.1":
      continue

   print(address)
   break
'
)"
if [[ -z "${parent_edge_ip}" ]]
then
   echo "FAIL: unable to resolve parent edge IPv4 from pid ${parent_pid}"
   exit 1
fi

hosts_context="${tmpdir}/whitehole-hosts"
artifact_project_dir="${tmpdir}/whitehole-fake-artifact"
discombobulator_file="${artifact_project_dir}/WhiteholeProbe.DiscombobuFile"
container_blob="${tmpdir}/whitehole.container.zst"
mkdir -p "${hosts_context}" "${artifact_project_dir}"
cat > "${hosts_context}/hosts" <<EOF
127.0.0.1 localhost
${parent_edge_ip} whitehole-target.test
EOF

cat > "${discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {bin} ./$(basename "${WHITEHOLE_BIN}") /root/whitehole_probe_container
COPY {hosts} ./hosts /etc/hosts
SURVIVE /root/whitehole_probe_container
SURVIVE /etc/hosts
EOF
prodigy_dev_write_common_prodigy_assets "${discombobulator_file}"
cat >> "${discombobulator_file}" <<'EOF'
EXECUTE ["/root/whitehole_probe_container"]
EOF

if ! prodigy_dev_run_discombobulator_build \
   "${artifact_project_dir}" \
   "${discombobulator_file}" \
   "${container_blob}" \
   "bin=$(dirname "${WHITEHOLE_BIN}")" \
   "hosts=${hosts_context}" \
   "ebpf=$(dirname "${PRODIGY_BIN}")"
then
   archive_workspace=1
   echo "FAIL: unable to build whitehole artifact"
   exit 1
fi

plan_json="${tmpdir}/whitehole.plan.json"
cat > "${plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${application_id},
    "versionID": ${version_id},
    "architecture": "${target_arch}",
    "filesystemMB": 64,
    "storageMB": 64,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 10000,
    "sTilHealthcheck": 15,
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
  "whiteholes": [
    {
      "transport": "quic",
      "family": "ipv4",
      "source": "distributableSubnet"
    }
  ],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF

nsenter -t "${parent_pid}" -n \
   env WHITEHOLE_TARGET_IP="${parent_edge_ip}" \
   WHITEHOLE_TARGET_PORT=32101 \
   WHITEHOLE_SPOOF_PORT=32102 \
   WHITEHOLE_RESPONDER_LOG="${responder_log}" \
   python3 - <<'PY' &
import os
import socket
import time

bind_ip = os.environ["WHITEHOLE_TARGET_IP"]
target_port = int(os.environ["WHITEHOLE_TARGET_PORT"])
spoof_port = int(os.environ["WHITEHOLE_SPOOF_PORT"])
log_path = os.environ["WHITEHOLE_RESPONDER_LOG"]

with open(log_path, "w", encoding="utf-8") as log:
    legit = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    legit.bind((bind_ip, target_port))
    spoof.bind((bind_ip, spoof_port))
    legit.settimeout(30.0)
    log.write(f"ready bind={bind_ip}:{target_port} spoof={bind_ip}:{spoof_port}\n")
    log.flush()
    payload, addr = legit.recvfrom(2048)
    log.write(f"recv addr={addr[0]}:{addr[1]} payload={payload.decode(errors='replace')}\n")
    log.flush()
    legit.sendto(b"whitehole-ok", addr)
    time.sleep(0.2)
    spoof.sendto(b"whitehole-spoof", addr)
    log.write("sent legit+spoof\n")
    log.flush()
PY
responder_pid=$!

deployed=0
for _ in $(seq 1 120)
do
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" \
      >"${cluster_status_log}" 2>&1 || true

   if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" deploy "${cluster_name}" "$(cat "${plan_json}")" "${container_blob}" \
      >"${deploy_log}" 2>&1
   then
      deployed=1
      break
   fi

   if ! rg -q 'cluster can only fit 0 total instances|we would need to schedule' "${deploy_log}"
   then
      break
   fi

   sleep 0.5
done

if [[ "${deployed}" -ne 1 ]]
then
   archive_workspace=1
   echo "FAIL: whitehole deployment failed"
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" \
      >"${cluster_report_log}" 2>&1 || true
   sed -n '1,240p' "${cluster_report_log}" || true
   sed -n '1,200p' "${cluster_status_log}" || true
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
      if rg -q '^[[:space:]]*nCrashes:[[:space:]]*[1-9]' "${application_log}"
      then
         break
      fi
   fi

   sleep 0.5
done

if [[ "${healthy}" -ne 1 ]]
then
   archive_workspace=1
   echo "FAIL: whitehole deployment never became healthy"
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" \
      >"${cluster_report_log}" 2>&1 || true
   sed -n '1,240p' "${cluster_report_log}" || true
   sed -n '1,200p' "${application_log}" || true
   sed -n '1,200p' "${deploy_log}" || true
   exit 1
fi

wait "${responder_pid}"
responder_pid=""

if ! rg -q 'sent legit\+spoof' "${responder_log}"
then
   archive_workspace=1
   echo "FAIL: responder did not complete the legit+spoof sequence"
   sed -n '1,120p' "${responder_log}" || true
   exit 1
fi

echo "PASS: whitehole fake IPv4 smoke"
