#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
WHITEHOLE_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${WHITEHOLE_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_whitehole_probe_container"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for isolated whitehole host-source smoke"
   exit 77
fi

for path in "${PRODIGY_BIN}" "${MOTHERSHIP_BIN}" "${WHITEHOLE_BIN}" "${HARNESS}"
do
   if [[ ! -e "${path}" ]]
   then
      echo "FAIL: required path missing: ${path}"
      exit 1
   fi
done

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
WHITEHOLE_BIN="$(readlink -f "${WHITEHOLE_BIN}" 2>/dev/null || printf '%s' "${WHITEHOLE_BIN}")"

tmpdir="$(mktemp -d)"
workspace_root="${tmpdir}/workspace"
manifest_path="${workspace_root}/test-cluster-manifest.json"
keep_tmp="${PRODIGY_DEV_KEEP_TMP:-0}"
allow_containers_overmount="${PRODIGY_DEV_ALLOW_CONTAINERS_OVERMOUNT:-0}"
cluster_name="whitehole-host-ipv4-$(date -u +%Y%m%d-%H%M%S)"
mothership_db_path="${tmpdir}/mothership-whitehole-host.tidesdb"
create_log="${tmpdir}/create_cluster.log"
deploy_log="${tmpdir}/deploy.log"
application_log="${tmpdir}/application_report.log"
cluster_report_log="${tmpdir}/cluster_report.log"
remove_log="${tmpdir}/remove_cluster.log"
responder_log="${tmpdir}/whitehole_responder.log"

containers_dir_created=0
containers_mount_created=0
containers_loop_image=""
deployment_subvol=""
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

read -r parent_ns control_socket_path <<EOF
$(python3 - "${manifest_path}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
print(manifest["parentNamespace"], manifest["controlSocketPath"])
PY
)
EOF

if [[ -z "${parent_ns}" || -z "${control_socket_path}" || ! -S "${control_socket_path}" ]]
then
   echo "FAIL: unable to parse persistent harness manifest or control socket path"
   exit 1
fi

parent_edge_ip="$(
   ip netns exec "${parent_ns}" ip -4 -o addr show | python3 -c '
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
   echo "FAIL: unable to resolve parent edge IPv4 from ${parent_ns}"
   exit 1
fi

deployment_subvol="/containers/${deployment_id}"
btrfs subvolume create "${deployment_subvol}" >/dev/null
mkdir -p "${deployment_subvol}/root" "${deployment_subvol}/etc"
install -m 0755 "${WHITEHOLE_BIN}" "${deployment_subvol}/root/whitehole_probe_container"

cat > "${deployment_subvol}/etc/hosts" <<EOF
127.0.0.1 localhost
${parent_edge_ip} whitehole-target.test
EOF

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
   ldd "${WHITEHOLE_BIN}" | awk '
      /=>/ {
         if ($3 ~ /^\//) print $3;
      }
      /^[[:space:]]*\// {
         print $1;
      }
   ' | sort -u
)

plan_json="${tmpdir}/whitehole.plan.json"
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
      "source": "hostPublicAddress"
    }
  ],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF

container_blob="${tmpdir}/whitehole.container.zst"
btrfs property set -f "${deployment_subvol}" ro true >/dev/null
btrfs send "${deployment_subvol}" | zstd -19 -T0 -q -o "${container_blob}"
btrfs property set -f "${deployment_subvol}" ro false >/dev/null
btrfs subvolume delete "${deployment_subvol}" >/dev/null
deployment_subvol=""

ip netns exec "${parent_ns}" \
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

if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" deploy "${cluster_name}" "$(cat "${plan_json}")" "${container_blob}" \
   >"${deploy_log}" 2>&1
then
   archive_workspace=1
   echo "FAIL: whitehole host-source deployment failed"
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
   echo "FAIL: whitehole host-source deployment never became healthy"
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

probe_log=""
for stdout_log in $(python3 - "${manifest_path}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
for node in manifest["nodes"]:
    print(node["stdoutLog"])
PY
)
do
   if [[ -f "${stdout_log}" ]] && rg -q 'probe\.(success|fail|bind)' "${stdout_log}"
   then
      probe_log="${stdout_log}"
      break
   fi
done

if [[ -z "${probe_log}" ]]
then
   archive_workspace=1
   echo "FAIL: unable to locate whitehole probe container stdout log"
   exit 1
fi

if ! rg -q 'probe.success' "${probe_log}"
then
   archive_workspace=1
   echo "FAIL: whitehole host-source probe container did not report success"
   sed -n '1,160p' "${probe_log}" || true
   exit 1
fi

if rg -q 'unexpected_second_reply' "${probe_log}"
then
   archive_workspace=1
   echo "FAIL: spoofed reply reached the host-source whitehole container"
   sed -n '1,160p' "${probe_log}" || true
   exit 1
fi

bound_ip="$(python3 - "${probe_log}" <<'PY'
import re
import sys

text = open(sys.argv[1], "r", encoding="utf-8", errors="replace").read()
match = re.search(r"probe\.bind ([0-9.]+):", text)
if not match:
    raise SystemExit(1)
print(match.group(1))
PY
)"

if [[ -z "${bound_ip}" ]]
then
   archive_workspace=1
   echo "FAIL: unable to parse bound host-source address from probe log"
   sed -n '1,160p' "${probe_log}" || true
   exit 1
fi

python3 - "${bound_ip}" <<'PY'
import ipaddress
import sys

ip = ipaddress.ip_address(sys.argv[1])
if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_private:
    raise SystemExit(1)
PY

echo "PASS: whitehole host-source IPv4 smoke bound=${bound_ip}"
