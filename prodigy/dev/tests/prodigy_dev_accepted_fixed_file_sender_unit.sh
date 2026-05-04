#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]
then
   echo "usage: $0 /path/to/prodigy_transport_tls_unit"
   exit 64
fi

transport_unit_bin="$1"

deps=(ip mktemp python3 rg ss timeout)
for dep in "${deps[@]}"
do
   if ! command -v "${dep}" >/dev/null 2>&1
   then
      echo "SKIP: missing dependency ${dep}"
      exit 77
   fi
done

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for netns setup"
   exit 77
fi

if [[ ! -x "${transport_unit_bin}" ]]
then
   echo "FAIL: missing transport unit binary at ${transport_unit_bin}"
   exit 1
fi

mkdir -p /root/prodigy/.run
workdir="$(mktemp -d /root/prodigy/.run/prodigy-dev-accepted-fixed-file-sender-unit.XXXXXX)"
server_log="${workdir}/server.log"
client_log="${workdir}/client.log"

server_ns="prodigy-dev-accepted-sender-server-$$-${RANDOM}"
client_ns="prodigy-dev-accepted-sender-client-$$-${RANDOM}"
server_pid=""
keep_workdir=0

cleanup()
{
   set +e
   if [[ -n "${server_pid}" ]]
   then
      kill "${server_pid}" >/dev/null 2>&1 || true
      wait "${server_pid}" >/dev/null 2>&1 || true
   fi

   ip netns del "${server_ns}" >/dev/null 2>&1 || true
   ip netns del "${client_ns}" >/dev/null 2>&1 || true

   if [[ "${keep_workdir}" -eq 0 ]]
   then
      rm -rf "${workdir}"
   fi
}
trap cleanup EXIT

ip netns add "${server_ns}"
ip netns add "${client_ns}"
ip -n "${server_ns}" link set lo up
ip -n "${client_ns}" link set lo up

ip link add paccsvr0 type veth peer name pacccli0
ip link set paccsvr0 netns "${server_ns}"
ip link set pacccli0 netns "${client_ns}"

ip -n "${server_ns}" link set paccsvr0 name bond0
ip -n "${client_ns}" link set pacccli0 name bond0

ip -n "${server_ns}" link set bond0 mtu 9000 up
ip -n "${client_ns}" link set bond0 mtu 9000 up
ip -n "${server_ns}" addr add 10.61.0.1/24 dev bond0
ip -n "${client_ns}" addr add 10.61.0.2/24 dev bond0

ip netns exec "${server_ns}" bash -lc 'sysctl -qw net.ipv4.tcp_ecn=1 >/dev/null 2>&1 || true'
ip netns exec "${client_ns}" bash -lc 'sysctl -qw net.ipv4.tcp_ecn=1 >/dev/null 2>&1 || true'

payload_bytes=$((8 * 1024 * 1024))
port=19091
tcp_maxseg=8948

timeout --preserve-status -k 2s 20s \
   ip netns exec "${server_ns}" \
   "${transport_unit_bin}" \
   --accepted-send-server 10.61.0.1 "${port}" "${payload_bytes}" "${tcp_maxseg}" \
   >"${server_log}" 2>&1 &
server_pid=$!

server_ready=0
for _attempt in $(seq 1 200)
do
   if ip netns exec "${server_ns}" ss -ltn 2>/dev/null | rg -q ":${port}[[:space:]]"
   then
      server_ready=1
      break
   fi

   sleep 0.05
done

if [[ "${server_ready}" -ne 1 ]]
then
   keep_workdir=1
   echo "FAIL: accepted fixed-file sender helper never started listening; logs in ${workdir}"
   cat "${server_log}" || true
   exit 1
fi

if ! timeout --preserve-status -k 2s 20s \
   ip netns exec "${client_ns}" \
   python3 - "${payload_bytes}" "${tcp_maxseg}" "${port}" >"${client_log}" 2>&1 <<'PY'
import socket
import sys

payload_bytes = int(sys.argv[1])
tcp_maxseg = int(sys.argv[2])
port = int(sys.argv[3])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10.0)

try:
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, b"dctcp")
except (AttributeError, OSError):
    pass

try:
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, tcp_maxseg)
except (AttributeError, OSError):
    pass

sock.connect(("10.61.0.1", port))

received = 0
while received < payload_bytes:
    chunk = sock.recv(min(262144, payload_bytes - received))
    if not chunk:
        raise SystemExit(f"short recv after {received} bytes")

    for index, byte in enumerate(chunk):
        expected = ord("a") + ((received + index) % 23)
        if byte != expected:
            raise SystemExit(
                f"payload mismatch at offset {received + index}: got {byte} expected {expected}"
            )

    received += len(chunk)

sock.settimeout(1.0)
extra = sock.recv(1)
if extra not in (b"",):
    raise SystemExit("server sent extra bytes after expected payload")

print(f"client received {received} bytes")
PY
then
   keep_workdir=1
   echo "FAIL: accepted fixed-file sender client failed; logs in ${workdir}"
   echo "--- server ---"
   cat "${server_log}" || true
   echo "--- client ---"
   cat "${client_log}" || true
   exit 1
fi

if ! wait "${server_pid}"
then
   keep_workdir=1
   echo "FAIL: accepted fixed-file sender helper failed; logs in ${workdir}"
   echo "--- server ---"
   cat "${server_log}" || true
   echo "--- client ---"
   cat "${client_log}" || true
   exit 1
fi
server_pid=""

echo "PASS: accepted fixed-file sender delivered ${payload_bytes} bytes across isolated namespaces"
