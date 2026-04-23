#!/usr/bin/env bash
set -Eeuo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
READY_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"
DISCOMBOBULATOR_MANIFEST="${REPO_ROOT}/prodigy/discombobulator/Cargo.toml"
APPLICATION_ID=62022
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

deps=(awk bpftool cargo cut find grep ip ls mkfs.btrfs mktemp mount nsenter python3 readlink rg sed stat timeout truncate umount uname)
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

tmpdir="$(mktemp -d "${REPO_ROOT}/.run/prodigy-dev-host-tcp-unit.XXXXXX")"
workspace_root="${tmpdir}/workspace"
workspace_archive="${tmpdir}/workspace-retained"
manifest_path="${workspace_root}/test-cluster-manifest.json"
plan_json="${tmpdir}/deploy.plan.json"
container_blob="${tmpdir}/deploy.container.zst"
discombobulator_file="${tmpdir}/HostTCP.DiscombobuFile"
discombobulator_log="${tmpdir}/discombobulator-build.log"
mothership_db_path="${tmpdir}/mothership-host-tcp.tidesdb"
cluster_name="test-host-tcp-$(date -u +%Y%m%d-%H%M%S)-$$"
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

capture_live_cluster_context()
{
   set +e

   if [[ "${cluster_created}" -eq 1 && "${cluster_removed}" -eq 0 ]]
   then
      run_mothership clusterReport "${cluster_name}" >"${tmpdir}/mothership.clusterreport.log" 2>&1 || true
      run_mothership applicationReport "${cluster_name}" "${application_name}" >"${tmpdir}/mothership.applicationreport.log" 2>&1 || true
   fi

   if [[ ! -s "${manifest_path}" ]]
   then
      return
   fi

   python3 - <<'PY' "${manifest_path}" >"${tmpdir}/manifest.nodes.txt" 2>/dev/null || true
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
   manifest = json.load(fh)

for node in sorted(manifest["nodes"], key=lambda item: item["index"]):
   print(f'{node["index"]} {node["pid"]} {node["ipv4"]}')
PY

   while read -r index pid ipv4
   do
      if [[ -z "${index}" || -z "${pid}" ]]
      then
         continue
      fi

      nsenter -t "${pid}" -n ip -4 addr show dev bond0 >"${tmpdir}/brain${index}.bond0.addr.txt" 2>&1 || true
      nsenter -t "${pid}" -m -n bpftool net show >"${tmpdir}/brain${index}.bpftool.net.txt" 2>&1 || true
      nsenter -t "${pid}" -n ss -tan >"${tmpdir}/brain${index}.ss.txt" 2>&1 || true
      nsenter -t "${pid}" -n ip route show >"${tmpdir}/brain${index}.routes.txt" 2>&1 || true
      nsenter -t "${pid}" -n ip neigh show >"${tmpdir}/brain${index}.neigh.txt" 2>&1 || true
   done <"${tmpdir}/manifest.nodes.txt"
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

   for log_path in \
      "${tmpdir}/create_cluster.log" \
      "${tmpdir}/mothership.reserve.log" \
      "${tmpdir}/mothership.deploy.log" \
      "${tmpdir}/mothership.applicationreport.log" \
      "${tmpdir}/mothership.clusterreport.log"
   do
      if [[ -f "${log_path}" ]]
      then
         echo "log: ${log_path}" >&2
         sed -n '1,200p' "${log_path}" >&2 || true
      fi
   done

   for diag_path in "${tmpdir}"/brain*.bpftool.net.txt "${tmpdir}"/brain*.ss.txt "${tmpdir}"/brain*.routes.txt "${tmpdir}"/brain*.neigh.txt
   do
      if [[ -f "${diag_path}" ]]
      then
         echo "diag: ${diag_path}" >&2
         sed -n '1,200p' "${diag_path}" >&2 || true
      fi
   done

   if compgen -G "${workspace_dump_root}/logs/brain*.stdout.log" >/dev/null
   then
      for brain_log in "${workspace_dump_root}"/logs/brain*.stdout.log
      do
         echo "brain log tail: ${brain_log}" >&2
         tail -n 120 "${brain_log}" >&2 || true
      done
   fi
}

fail()
{
   keep_tmpdir=1
   capture_live_cluster_context
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
   capture_live_cluster_context
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

wait_for_brain_transport_path()
{
   local brain_pid="$1"
   local brain_ip="$2"
   local label="$3"

   if ! timeout 90s bash -lc '
      while true
      do
         if ! kill -0 "'"${brain_pid}"'" >/dev/null 2>&1
         then
            exit 1
         fi

         if nsenter -t "'"${brain_pid}"'" -n ip -4 addr show dev bond0 2>/dev/null | grep -F "inet '"${brain_ip}"'/24" >/dev/null 2>&1 \
            && nsenter -t "'"${brain_pid}"'" -m -n bpftool net show 2>/dev/null | grep -F "host_ingress_router" >/dev/null 2>&1 \
            && nsenter -t "'"${brain_pid}"'" -m -n bpftool net show 2>/dev/null | grep -F "host_egress_router" >/dev/null 2>&1
         then
            exit 0
         fi

         sleep 0.1
      done
   ' >/dev/null
   then
      fail "${label} did not finish wiring host TCP transport hooks after deployment"
   fi
}

run_tcp_roundtrip()
{
   local src_pid="$1"
   local src_ip="$2"
   local dst_pid="$3"
   local dst_ip="$4"
   local port="$5"
   local label="$6"
   local listener_log="${tmpdir}/${label}.listener.log"
   local client_log="${tmpdir}/${label}.client.log"
   local src_sniffer_log="${tmpdir}/${label}.src.sniffer.log"
   local dst_sniffer_log="${tmpdir}/${label}.dst.sniffer.log"
   local listener_pid=""
   local src_sniffer_pid=""
   local dst_sniffer_pid=""

   if [[ -z "${src_ip}" ]]
   then
      fail "${label} missing source IP"
   fi

   SNIFF_SRC_IP="${src_ip}" SNIFF_DST_IP="${dst_ip}" SNIFF_PORT="${port}" \
      nsenter -t "${src_pid}" -n python3 -u - <<'PY' >"${src_sniffer_log}" 2>&1 &
import binascii
import os
import socket
import struct
import time

src_ip = os.environ["SNIFF_SRC_IP"]
dst_ip = os.environ["SNIFF_DST_IP"]
dst_port = int(os.environ["SNIFF_PORT"])

sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sniffer.bind(("bond0", 0))
sniffer.settimeout(6.0)


def checksum(data: bytes) -> int:
   if len(data) & 1:
      data += b"\x00"

   total = 0
   for index in range(0, len(data), 2):
      total += (data[index] << 8) | data[index + 1]

   while total >> 16:
      total = (total & 0xFFFF) + (total >> 16)

   return (~total) & 0xFFFF


deadline = time.time() + 6.0
while time.time() < deadline:
   try:
      frame, addr = sniffer.recvfrom(65535)
   except TimeoutError:
      continue

   if len(frame) < 14 + 20 + 20:
      continue

   eth_proto = struct.unpack("!H", frame[12:14])[0]
   if eth_proto != 0x0800:
      continue

   version_ihl = frame[14]
   ihl = (version_ihl & 0x0F) * 4
   if len(frame) < 14 + ihl + 20:
      continue

   total_length = struct.unpack("!H", frame[16:18])[0]
   if total_length < ihl + 20 or len(frame) < 14 + total_length:
      continue

   if frame[23] != 6:
      continue

   packet_src = socket.inet_ntoa(frame[26:30])
   packet_dst = socket.inet_ntoa(frame[30:34])
   if packet_src != src_ip or packet_dst != dst_ip:
      continue

   tcp_offset = 14 + ihl
   tcp_header = frame[tcp_offset:tcp_offset + 20]
   source_port, dest_port, seq, ack, data_offset_flags, window, packet_checksum, urg = struct.unpack("!HHIIHHHH", tcp_header)
   if dest_port != dst_port:
      continue

   data_offset = ((data_offset_flags >> 12) & 0x0F) * 4
   tcp_segment = bytearray(frame[tcp_offset:14 + total_length])
   if len(tcp_segment) < data_offset:
      continue

   tcp_segment[16] = 0
   tcp_segment[17] = 0
   pseudo_header = socket.inet_aton(packet_src) + socket.inet_aton(packet_dst) + b"\x00" + bytes([6]) + struct.pack("!H", len(tcp_segment))
   computed_checksum = checksum(pseudo_header + tcp_segment)
   flags = data_offset_flags & 0x01FF
   packet_type = addr[2] if isinstance(addr, tuple) and len(addr) >= 3 else "unknown"
   print(
      f"SYN frame packetType={packet_type} src={packet_src}:{source_port} dst={packet_dst}:{dest_port} "
      f"flags=0x{flags:03x} seq={seq} ack={ack} "
      f"wireChecksum=0x{packet_checksum:04x} computedChecksum=0x{computed_checksum:04x}",
      flush=True,
   )
   print(f"FRAME {binascii.hexlify(frame[:14 + total_length]).decode()}", flush=True)
   raise SystemExit(0)

print("NO_MATCH", flush=True)
raise SystemExit(1)
PY
   src_sniffer_pid="$!"

   SNIFF_SRC_IP="${src_ip}" SNIFF_DST_IP="${dst_ip}" SNIFF_PORT="${port}" \
      nsenter -t "${dst_pid}" -n python3 -u - <<'PY' >"${dst_sniffer_log}" 2>&1 &
import binascii
import os
import socket
import struct
import time

src_ip = os.environ["SNIFF_SRC_IP"]
dst_ip = os.environ["SNIFF_DST_IP"]
dst_port = int(os.environ["SNIFF_PORT"])

sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sniffer.bind(("bond0", 0))
sniffer.settimeout(6.0)


def checksum(data: bytes) -> int:
   if len(data) & 1:
      data += b"\x00"

   total = 0
   for index in range(0, len(data), 2):
      total += (data[index] << 8) | data[index + 1]

   while total >> 16:
      total = (total & 0xFFFF) + (total >> 16)

   return (~total) & 0xFFFF


deadline = time.time() + 6.0
while time.time() < deadline:
   try:
      frame, addr = sniffer.recvfrom(65535)
   except TimeoutError:
      continue

   if len(frame) < 14 + 20 + 20:
      continue

   eth_proto = struct.unpack("!H", frame[12:14])[0]
   if eth_proto != 0x0800:
      continue

   version_ihl = frame[14]
   ihl = (version_ihl & 0x0F) * 4
   if len(frame) < 14 + ihl + 20:
      continue

   total_length = struct.unpack("!H", frame[16:18])[0]
   if total_length < ihl + 20 or len(frame) < 14 + total_length:
      continue

   if frame[23] != 6:
      continue

   packet_src = socket.inet_ntoa(frame[26:30])
   packet_dst = socket.inet_ntoa(frame[30:34])
   if packet_src != src_ip or packet_dst != dst_ip:
      continue

   tcp_offset = 14 + ihl
   tcp_header = frame[tcp_offset:tcp_offset + 20]
   source_port, dest_port, seq, ack, data_offset_flags, window, packet_checksum, urg = struct.unpack("!HHIIHHHH", tcp_header)
   if dest_port != dst_port:
      continue

   data_offset = ((data_offset_flags >> 12) & 0x0F) * 4
   tcp_segment = bytearray(frame[tcp_offset:14 + total_length])
   if len(tcp_segment) < data_offset:
      continue

   tcp_segment[16] = 0
   tcp_segment[17] = 0
   pseudo_header = socket.inet_aton(packet_src) + socket.inet_aton(packet_dst) + b"\x00" + bytes([6]) + struct.pack("!H", len(tcp_segment))
   computed_checksum = checksum(pseudo_header + tcp_segment)
   flags = data_offset_flags & 0x01FF
   packet_type = addr[2] if isinstance(addr, tuple) and len(addr) >= 3 else "unknown"
   print(
      f"SYN frame packetType={packet_type} src={packet_src}:{source_port} dst={packet_dst}:{dest_port} "
      f"flags=0x{flags:03x} seq={seq} ack={ack} "
      f"wireChecksum=0x{packet_checksum:04x} computedChecksum=0x{computed_checksum:04x}",
      flush=True,
   )
   print(f"FRAME {binascii.hexlify(frame[:14 + total_length]).decode()}", flush=True)
   raise SystemExit(0)

print("NO_MATCH", flush=True)
raise SystemExit(1)
PY
   dst_sniffer_pid="$!"

   LISTEN_IP="${dst_ip}" LISTEN_PORT="${port}" \
      nsenter -t "${dst_pid}" -n python3 -u - <<'PY' >"${listener_log}" 2>&1 &
import os
import socket

listen_ip = os.environ["LISTEN_IP"]
listen_port = int(os.environ["LISTEN_PORT"])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((listen_ip, listen_port))
sock.listen(1)
sock.settimeout(8)
print("LISTEN", flush=True)
conn, addr = sock.accept()
print(f"ACCEPT {addr[0]}:{addr[1]}", flush=True)
data = conn.recv(16)
print(f"DATA {data.decode('utf-8', 'ignore')}", flush=True)
conn.sendall(b"ok")
conn.close()
sock.close()
PY
   listener_pid="$!"

   if ! LISTENER_LOG="${listener_log}" LISTENER_PID="${listener_pid}" timeout 5s bash -lc '
      while true
      do
         if grep -q "^LISTEN$" "${LISTENER_LOG}" 2>/dev/null
         then
            exit 0
         fi

         if ! kill -0 "${LISTENER_PID}" >/dev/null 2>&1
         then
            exit 1
         fi

         sleep 0.05
      done
   ' >/dev/null
   then
      kill -TERM "${src_sniffer_pid}" >/dev/null 2>&1 || true
      kill -TERM "${dst_sniffer_pid}" >/dev/null 2>&1 || true
      wait "${src_sniffer_pid}" 2>/dev/null || true
      wait "${dst_sniffer_pid}" 2>/dev/null || true
      echo "listener log: ${listener_log}" >&2
      cat "${listener_log}" >&2 || true
      fail "${label} listener did not become ready"
   fi

   if ! TARGET_IP="${dst_ip}" TARGET_PORT="${port}" \
      nsenter -t "${src_pid}" -n python3 -u - <<'PY' >"${client_log}" 2>&1
import os
import socket

target_ip = os.environ["TARGET_IP"]
target_port = int(os.environ["TARGET_PORT"])

sock = socket.create_connection((target_ip, target_port), timeout=4)
sock.sendall(b"ping")
print(sock.recv(16).decode("utf-8", "ignore"), flush=True)
sock.close()
PY
   then
      echo "listener log: ${listener_log}" >&2
      cat "${listener_log}" >&2 || true
      echo "client log: ${client_log}" >&2
      cat "${client_log}" >&2 || true
      echo "source sniffer log: ${src_sniffer_log}" >&2
      cat "${src_sniffer_log}" >&2 || true
      echo "destination sniffer log: ${dst_sniffer_log}" >&2
      cat "${dst_sniffer_log}" >&2 || true
      kill -TERM "${listener_pid}" >/dev/null 2>&1 || true
      wait "${listener_pid}" 2>/dev/null || true
      kill -TERM "${src_sniffer_pid}" >/dev/null 2>&1 || true
      kill -TERM "${dst_sniffer_pid}" >/dev/null 2>&1 || true
      wait "${src_sniffer_pid}" 2>/dev/null || true
      wait "${dst_sniffer_pid}" 2>/dev/null || true
      fail "${label} client connect/send failed"
   fi

   if ! wait "${listener_pid}"
   then
      echo "listener log: ${listener_log}" >&2
      cat "${listener_log}" >&2 || true
      echo "client log: ${client_log}" >&2
      cat "${client_log}" >&2 || true
      echo "source sniffer log: ${src_sniffer_log}" >&2
      cat "${src_sniffer_log}" >&2 || true
      echo "destination sniffer log: ${dst_sniffer_log}" >&2
      cat "${dst_sniffer_log}" >&2 || true
      kill -TERM "${src_sniffer_pid}" >/dev/null 2>&1 || true
      kill -TERM "${dst_sniffer_pid}" >/dev/null 2>&1 || true
      wait "${src_sniffer_pid}" 2>/dev/null || true
      wait "${dst_sniffer_pid}" 2>/dev/null || true
      fail "${label} listener exited unsuccessfully"
   fi

   # The transport round-trip itself is the regression signal. These AF_PACKET
   # sniffers are retained as best-effort diagnostics only, because the current
   # host-router fast-pass can still complete the connection even when the
   # capture socket misses the short SYN window.
   sleep 0.2
   kill -TERM "${src_sniffer_pid}" >/dev/null 2>&1 || true
   kill -TERM "${dst_sniffer_pid}" >/dev/null 2>&1 || true
   wait "${src_sniffer_pid}" 2>/dev/null || true
   wait "${dst_sniffer_pid}" 2>/dev/null || true

   if ! grep -q '^ACCEPT ' "${listener_log}" || ! grep -q '^DATA ping$' "${listener_log}" || ! grep -q '^ok$' "${client_log}"
   then
      echo "listener log: ${listener_log}" >&2
      cat "${listener_log}" >&2 || true
      echo "client log: ${client_log}" >&2
      cat "${client_log}" >&2 || true
      echo "source sniffer log: ${src_sniffer_log}" >&2
      cat "${src_sniffer_log}" >&2 || true
      echo "destination sniffer log: ${dst_sniffer_log}" >&2
      cat "${dst_sniffer_log}" >&2 || true
      fail "${label} tcp round-trip output mismatch"
   fi
}

detect_target_arch()
{
   local machine_arch=""
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
    "nBase": 3,
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
    "interContainerMTU": 9000,
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
   fail "mothership createCluster did not succeed for host tcp regression"
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
   fail "reserveApplicationID did not succeed for host tcp regression"
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
   fail "mothership deploy did not succeed for host tcp regression"
fi

mapfile -t node_specs < <(
   python3 - <<'PY' "${manifest_path}"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
   manifest = json.load(fh)

for node in sorted(manifest["nodes"], key=lambda item: item["index"]):
   print(f'{node["index"]} {node["pid"]} {node["ipv4"]}')
PY
)

if [[ "${#node_specs[@]}" -ne 3 ]]
then
   fail "expected 3 manifest nodes, saw ${#node_specs[@]}"
fi

brain1_pid=""
brain1_ip=""
brain2_pid=""
brain2_ip=""
brain3_pid=""
brain3_ip=""

for spec in "${node_specs[@]}"
do
   read -r index pid ipv4 <<<"${spec}"
   case "${index}" in
      1)
         brain1_pid="${pid}"
         brain1_ip="${ipv4}"
         ;;
      2)
         brain2_pid="${pid}"
         brain2_ip="${ipv4}"
         ;;
      3)
         brain3_pid="${pid}"
         brain3_ip="${ipv4}"
         ;;
   esac
done

for item in \
   "${brain1_pid}:${brain1_ip}:brain1" \
   "${brain2_pid}:${brain2_ip}:brain2" \
   "${brain3_pid}:${brain3_ip}:brain3"
do
   IFS=':' read -r pid ipv4 label <<<"${item}"
   if [[ -z "${pid}" || -z "${ipv4}" ]]
   then
      fail "incomplete manifest entry for ${label}"
   fi
   wait_for_brain_transport_path "${pid}" "${ipv4}" "${label}"
done

run_tcp_roundtrip "${brain1_pid}" "${brain1_ip}" "${brain2_pid}" "${brain2_ip}" 40131 "brain1-to-brain2"
run_tcp_roundtrip "${brain1_pid}" "${brain1_ip}" "${brain3_pid}" "${brain3_ip}" 40132 "brain1-to-brain3"

if ! run_mothership removeCluster "${cluster_name}" >"${tmpdir}/remove_cluster.log" 2>&1
then
   fail "removeCluster did not succeed after host tcp regression"
fi
cluster_removed=1

echo "PASS: prodigy host routers preserve native host TCP delivery after fragment assignment"
