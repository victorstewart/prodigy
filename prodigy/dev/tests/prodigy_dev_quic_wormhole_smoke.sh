#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
QUIC_PROBE_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"

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

deps=(awk btrfs mkfs.btrfs mount umount stat zstd ldd install timeout ip python3 rg)
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
QUIC_PROBE_BIN="$(readlink -f "${QUIC_PROBE_BIN}" 2>/dev/null || printf '%s' "${QUIC_PROBE_BIN}")"

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

read -r parent_ns <<EOF
$(python3 - "${manifest_path}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
print(manifest["parentNamespace"])
PY
)
EOF

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

deployment_subvol="/containers/${deployment_id}"
btrfs subvolume create "${deployment_subvol}" >/dev/null
mkdir -p "${deployment_subvol}/root"
install -m 0755 "${QUIC_PROBE_BIN}" "${deployment_subvol}/root/quic_wormhole_probe_container"

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
   ldd "${QUIC_PROBE_BIN}" | awk '
      /=>/ {
         if ($3 ~ /^\//) print $3;
      }
      /^[[:space:]]*\// {
         print $1;
      }
   ' | sort -u
)

plan_json="${tmpdir}/quic.plan.json"
cat > "${plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${application_id},
    "versionID": ${version_id},
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

container_blob="${tmpdir}/quic.container.zst"
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

ip netns exec "${parent_ns}" \
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
