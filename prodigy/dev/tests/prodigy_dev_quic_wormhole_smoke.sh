#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
QUIC_PROBE_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"
source "${SCRIPT_DIR}/prodigy_dev_discombobulator_artifact_helpers.sh"
SCRIPT_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_QUIC_WORMHOLE_SMOKE_MOUNT_NS_READY bash "${SCRIPT_SELF}" "$@"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${QUIC_PROBE_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_quic_wormhole_probe_container"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for isolated QUIC wormhole smoke"
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

if [[ "${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}" != "1" ]]
then
   echo "SKIP: QUIC wormhole smoke requires fake IPv4 boundary BPF attach; set PRODIGY_DEV_ALLOW_BPF_ATTACH=1 only inside an authorized isolated VM"
   exit 77
fi

PRODIGY_BIN="$(readlink -f "${PRODIGY_BIN}" 2>/dev/null || printf '%s' "${PRODIGY_BIN}")"
MOTHERSHIP_BIN="$(readlink -f "${MOTHERSHIP_BIN}" 2>/dev/null || printf '%s' "${MOTHERSHIP_BIN}")"
QUIC_PROBE_BIN="$(readlink -f "${QUIC_PROBE_BIN}" 2>/dev/null || printf '%s' "${QUIC_PROBE_BIN}")"
target_arch="$(prodigy_dev_detect_target_arch)"

tmpdir="$(mktemp -d)"
workspace_root="${tmpdir}/workspace"
manifest_path="${workspace_root}/test-cluster-manifest.json"
cluster_name="quic-wormhole-$(date -u +%Y%m%d-%H%M%S)"
mothership_db_path="${tmpdir}/mothership-quic.tidesdb"
keep_tmp="${PRODIGY_DEV_KEEP_TMP:-0}"
allow_containers_overmount="${PRODIGY_DEV_ALLOW_CONTAINERS_OVERMOUNT:-0}"
create_log="${tmpdir}/create_cluster.log"
register_log="${tmpdir}/register.log"
deploy_log="${tmpdir}/deploy.log"
application_log="${tmpdir}/application_report.log"
cluster_report_log="${tmpdir}/cluster_report.log"
sender_log="${tmpdir}/sender.log"
remove_log="${tmpdir}/remove_cluster.log"

containers_dir_created=0
containers_mount_created=0
containers_loop_image=""
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

read -r parent_pid <<EOF
$(python3 - "${manifest_path}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
print(manifest["parentPid"])
PY
)
EOF

if [[ -z "${parent_pid}" || "${parent_pid}" == "0" ]]
then
   echo "FAIL: unable to parse persistent harness parent pid"
   exit 1
fi

register_request='{"name":"quic-test-ipv4","kind":"testFakeAddress","family":"ipv4"}'
if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" registerRoutableAddress "${cluster_name}" "${register_request}" \
   >"${register_log}" 2>&1
then
   echo "FAIL: registerRoutableAddress failed"
   sed -n '1,160p' "${register_log}" || true
   exit 1
fi

read -r routable_uuid routable_address <<EOF
$(python3 - "${register_log}" <<'PY'
import re, sys
text = open(sys.argv[1], "r", encoding="utf-8").read()
uuid = re.search(r"\buuid=([0-9a-fA-Fx]+)", text)
address = re.search(r"\baddress=([0-9a-fA-F:\\.]+)", text)
if not uuid or not address:
    raise SystemExit(1)
print(uuid.group(1), address.group(1))
PY
)
EOF

if [[ -z "${routable_uuid}" || -z "${routable_address}" ]]
then
   echo "FAIL: unable to parse registered QUIC routable address"
   sed -n '1,120p' "${register_log}" || true
   exit 1
fi

artifact_project_dir="${tmpdir}/quic-artifact"
discombobulator_file="${artifact_project_dir}/QuicWormholeProbe.DiscombobuFile"
container_blob="${tmpdir}/quic.container.zst"
mkdir -p "${artifact_project_dir}"
cat > "${discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {bin} ./$(basename "${QUIC_PROBE_BIN}") /root/quic_wormhole_probe_container
SURVIVE /root/quic_wormhole_probe_container
EOF
prodigy_dev_write_common_prodigy_assets "${discombobulator_file}"
cat >> "${discombobulator_file}" <<'EOF'
EXECUTE ["/root/quic_wormhole_probe_container"]
EOF

if ! prodigy_dev_run_discombobulator_build \
   "${artifact_project_dir}" \
   "${discombobulator_file}" \
   "${container_blob}" \
   "bin=$(dirname "${QUIC_PROBE_BIN}")" \
   "ebpf=$(dirname "${PRODIGY_BIN}")"
then
   archive_workspace=1
   echo "FAIL: unable to build QUIC wormhole artifact"
   exit 1
fi

plan_json="${tmpdir}/quic.plan.json"
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
    "msTilHealthy": 5000,
    "sTilHealthcheck": 5,
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
  "wormholes": [
    {
      "source": "registeredRoutableAddress",
      "routableAddressUUID": "${routable_uuid}",
      "externalPort": 18443,
      "containerPort": 18443,
      "layer4": "UDP",
      "isQuic": true,
      "quicCidKeyRotationHours": 24
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
   echo "FAIL: QUIC wormhole deployment failed"
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
   echo "FAIL: QUIC wormhole deployment never became healthy"
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" \
      >"${cluster_report_log}" 2>&1 || true
   sed -n '1,240p' "${cluster_report_log}" || true
   sed -n '1,200p' "${application_log}" || true
   exit 1
fi

probe_log=""
probe_trace_log="${tmpdir}/quic_probe_trace.log"
for _ in $(seq 1 120)
do
   for stdout_log in $(python3 - "${manifest_path}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
for node in manifest["nodes"]:
    print(node["stdoutLog"])
PY
)
   do
      if [[ -f "${stdout_log}" ]] && rg -q 'probe\.cid ' "${stdout_log}"
      then
         probe_log="${stdout_log}"
         break
      fi

      container_pid="$(
         rg -o 'spinContainer start ok deploymentID=[0-9]+ appID=6 .* pid=[0-9]+' "${stdout_log}" 2>/dev/null \
            | tail -n 1 \
            | sed -E 's/.* pid=([0-9]+).*/\1/'
      )"
      if [[ -n "${container_pid}" ]] && kill -0 "${container_pid}" >/dev/null 2>&1
      then
         container_trace_path="/proc/${container_pid}/root/quic_wormhole_probe_trace.log"
         if [[ -r "${container_trace_path}" ]] && rg -q 'probe\.cid ' "${container_trace_path}"
         then
            probe_log="${container_trace_path}"
            break
         fi

         cat "${container_trace_path}" >"${probe_trace_log}" 2>/dev/null || true
      fi
   done

   if [[ -n "${probe_log}" ]]
   then
      break
   fi
   sleep 0.5
done

if [[ -z "${probe_log}" ]]
then
   archive_workspace=1
   echo "FAIL: unable to locate QUIC wormhole probe log with CID"
   exit 1
fi

cid_hex="$(python3 - "${probe_log}" <<'PY'
import re
import sys
text = open(sys.argv[1], "r", encoding="utf-8", errors="replace").read()
match = re.search(r"probe\.cid ([0-9a-f]+)", text)
if not match:
    raise SystemExit(1)
print(match.group(1))
PY
)"

if [[ -z "${cid_hex}" ]]
then
   archive_workspace=1
   echo "FAIL: unable to parse QUIC CID from probe log"
   sed -n '1,160p' "${probe_log}" || true
   exit 1
fi

if ! nsenter -t "${parent_pid}" -n \
   env QUIC_WORMHOLE_TARGET="${routable_address}" \
   QUIC_WORMHOLE_PORT="18443" \
   QUIC_WORMHOLE_CID="${cid_hex}" \
   python3 - <<'PY' >"${sender_log}" 2>&1
import os
import socket

target = (os.environ["QUIC_WORMHOLE_TARGET"], int(os.environ["QUIC_WORMHOLE_PORT"]))
cid = bytes.fromhex(os.environ["QUIC_WORMHOLE_CID"])
if len(cid) != 16:
    raise SystemExit("invalid cid length")

packet = bytearray()
packet.append(0x80)
packet += (1).to_bytes(4, "little")
packet.append(len(cid))
packet += cid
packet += b"\x00"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5.0)
sock.sendto(packet, target)
reply, addr = sock.recvfrom(256)
print(f"reply={reply.decode(errors='replace')} from={addr[0]}:{addr[1]}")
PY
then
   archive_workspace=1
   echo "FAIL: QUIC wormhole sender command failed"
   sed -n '1,120p' "${sender_log}" || true
   exit 1
fi

if ! rg -q 'reply=wormhole-ok' "${sender_log}"
then
   archive_workspace=1
   echo "FAIL: QUIC wormhole sender did not receive reply"
   sed -n '1,120p' "${sender_log}" || true
   exit 1
fi

for _ in $(seq 1 60)
do
   if rg -q 'probe.success' "${probe_log}"
   then
      break
   fi
   sleep 0.2
done

if ! rg -q 'probe.success' "${probe_log}"
then
   archive_workspace=1
   echo "FAIL: QUIC wormhole container never reported success"
   sed -n '1,200p' "${probe_log}" || true
   exit 1
fi

echo "PASS: QUIC wormhole smoke address=${routable_address}:18443 cid=${cid_hex}"
