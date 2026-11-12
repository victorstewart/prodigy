#!/usr/bin/env python3
"""Kernel regression for the retained-VDC public ingress source policy.

Run only in the verified Linux KVM test guest.  The test creates all network
namespaces, veth pairs, NAT rules, bpffs pins, and sockets inside an unshared
network and mount namespaces; it never touches the caller's network namespace.
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


if len(sys.argv) != 3:
    fail(f"usage: {sys.argv[0]} <mothership.virtual.datacenter.provider.sh> <fake_ipv4_boundary_nat.ebpf.o>")

provider = pathlib.Path(sys.argv[1]).resolve()
boundary_elf = pathlib.Path(sys.argv[2]).resolve()
if not provider.is_file() or not boundary_elf.is_file():
    fail("provider source or boundary BPF ELF is missing")

required = ("unshare", "ip", "iptables", "iptables-restore", "tc", "bpftool", "python3")
missing = [name for name in required if shutil.which(name) is None]
if missing:
    fail("missing Linux kernel-test tools: " + ", ".join(missing))

script = r'''#!/usr/bin/env bash
set -Eeuo pipefail
provider="$1"; boundary_elf="$2"; root="$3"
[[ "${EUID}" -eq 0 ]]
[[ "$(systemd-detect-virt --vm)" == kvm ]]
[[ "$(< /run/prodigy-disposable-linux)" == prodigy-disposable-linux-v1 ]]
runtime=42424242
suffix=42424242
edge="vdh${suffix}"
parent_edge="vdp${suffix}"
parent="pvd-p-${runtime}"
workspace="${root}/workspace"
bpffs="${workspace}/boundary-bpffs"
bin="${root}/bin"
server_pid=""
mkdir -p "${workspace}" "${bin}" "${bpffs}"

cleanup() {
  [[ -z "${server_pid}" ]] || { kill "${server_pid}" 2>/dev/null || true; wait "${server_pid}" 2>/dev/null || true; }
  ip netns del "${parent}" 2>/dev/null || true
  ip link del "${edge}" 2>/dev/null || true
  umount "${bpffs}" 2>/dev/null || true
}
trap cleanup EXIT
[[ "$(stat -Lc %i /proc/self/ns/net)" != "$(stat -Lc %i /proc/1/ns/net)" ]]

# Extract precisely the provider operation under test, instead of maintaining a
# second implementation in the test fixture.
awk '/^public_ingress_policy\(\)/ {on=1} on {print} /^configure_public_ingress_source\(\)/ {exit}' "${provider}" | sed '$d' > "${root}/policy.sh"
grep -q '^public_ingress_policy()' "${root}/policy.sh"

mount -t bpf bpf "${bpffs}"
mkdir -p "${bpffs}/programs"
bpftool prog loadall "${boundary_elf}" "${bpffs}/programs"
test -r "${bpffs}/programs/fake_nat_eg"

# Host edge and the retained parent namespace are a real veth pair. The host
# holds the synthetic client and the parent owns the selected public listener:
# request SNAT happens in host POSTROUTING and replies cross fake_nat_eg.
ip netns add "${parent}"
ip link add "${edge}" type veth peer name "${parent_edge}"
ip link set "${parent_edge}" netns "${parent}"
ip addr add 172.31.0.1/30 dev "${edge}"
ip link set "${edge}" up
ip addr add 203.0.113.2/32 dev lo
ip route add 198.18.0.0/16 via 172.31.0.2 dev "${edge}"
sysctl -q -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING ! -s 172.31.0.0/30 -d 198.18.0.0/16 -o "${edge}" -j SNAT --to-source 172.31.0.1

ip netns exec "${parent}" ip addr add 172.31.0.2/30 dev "${parent_edge}"
ip netns exec "${parent}" ip link set lo up
ip netns exec "${parent}" ip link set "${parent_edge}" up
ip netns exec "${parent}" ip addr add 198.18.0.1/32 dev lo
ip netns exec "${parent}" ip addr add 198.18.0.2/32 dev lo
ip netns exec "${parent}" ip route add default via 172.31.0.1 dev "${parent_edge}"
[[ "$(stat -Lc %i /proc/self/ns/net)" != "$(ip netns exec "${parent}" stat -Lc %i /proc/self/ns/net)" ]]

ip netns exec "${parent}" tc qdisc add dev "${parent_edge}" clsact
ip netns exec "${parent}" tc filter add dev "${parent_edge}" egress pref 200 handle 1 bpf da pinned "${bpffs}/programs/fake_nat_eg"

cat > "${bin}/iptables-restore" <<'EOF'
#!/usr/bin/env bash
if [[ "${PUBLIC_INGRESS_TEST_FAIL_RESTORE:-}" == 1 ]]; then exit 88; fi
exec /usr/sbin/iptables-restore "$@"
EOF
chmod 0755 "${bin}/iptables-restore"

cat > "${root}/server.py" <<'PY'
import pathlib,socket,sys,threading
out=pathlib.Path(sys.argv[1]); host,port,label=sys.argv[2],int(sys.argv[3]),sys.argv[4]; out.mkdir(parents=True,exist_ok=True)
def tcp(host,port,label):
 s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((host,port)); s.listen(1)
 c,peer=s.accept(); (out/(label+'.tcp.peer')).write_text(peer[0]+'\n'); c.sendall(b'ok'); c.close(); s.close()
def udp(host,port,label):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((host,port)); data,peer=s.recvfrom(64); (out/(label+'.udp.peer')).write_text(peer[0]+'\n'); s.sendto(b'ok',peer); s.close()
threads=[]
for fn in (tcp,udp):
 t=threading.Thread(target=fn,args=(host,port,label),daemon=True); t.start(); threads.append(t)
for t in threads:t.join(20)
if any(t.is_alive() for t in threads): raise SystemExit('server timeout')
PY
cat > "${root}/client.py" <<'PY'
import pathlib,socket,sys
host,port,label,out=sys.argv[1:]
out=pathlib.Path(out)
for kind in ('tcp','udp'):
 if kind=='tcp':
  s=socket.socket(); s.bind(('203.0.113.2',0)); s.settimeout(10); s.connect((host,int(port))); assert s.recv(2)==b'ok'; peer=s.getpeername()[0]
 else:
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('203.0.113.2',0)); s.settimeout(10); s.sendto(b'x',(host,int(port))); data,peeraddr=s.recvfrom(8); assert data==b'ok'; peer=peeraddr[0]
 (out/(label+'.'+kind+'.reply')).write_text(peer+'\n'); s.close()
PY

start_servers() {
  rm -rf "${root}/observed"; mkdir -p "${root}/observed"
  ip netns exec "${parent}" python3 "${root}/server.py" "${root}/observed" "$1" "$2" "$3" & server_pid=$!
  sleep .2
}
run_client() { python3 "${root}/client.py" "$1" "$2" "$3" "${root}/observed"; wait "${server_pid}"; }
assert_eq() { [[ "$(<"$1")" == "$2" ]] || { echo "expected $1=$2 got $(<"$1")" >&2; exit 1; }; }
assert_policy() {
  local selected="$1"
  iptables -t nat -C POSTROUTING ! -s 172.31.0.0/30 -d 198.18.0.0/16 -o "${edge}" -j SNAT --to-source 172.31.0.1
  if [[ -n "${selected}" ]]; then
    for p in tcp udp; do iptables -t nat -C POSTROUTING ! -s 172.31.0.0/30 -d "${selected}/32" -o "${edge}" -p "$p" -m "$p" --dport 443 -m comment --comment "prodigy-public-ingress-${runtime}" -j ACCEPT; done
    ip netns exec "${parent}" tc -j filter show dev "${parent_edge}" egress pref 100 | python3 -c $'import json,sys\nx=[r for r in json.load(sys.stdin) if r.get("options",{}).get("handle") is not None]; want=sys.argv[1]\nassert len(x)==2\nfor r in x:\n o=r["options"]; k=o["keys"]\n assert int(str(o["handle"]),0) in (1,2) and k["src_ip"].split("/")[0] == want and k["src_port"] == 443' "${selected}"
  else
    ! iptables -t nat -S POSTROUTING | grep -q "prodigy-public-ingress-${runtime}"
    [[ "$(ip netns exec "${parent}" tc -j filter show dev "${parent_edge}" egress pref 100)" == "[]" ]]
  fi
}

export PATH="${bin}:$PATH"
source "${root}/policy.sh"
public_ingress_policy "${workspace}" "${runtime}" '' 198.18.0.2
assert_policy 198.18.0.2
# Idempotence must leave exactly the owned pair of NAT and TC rules.
public_ingress_policy "${workspace}" "${runtime}" 198.18.0.2 198.18.0.2
assert_policy 198.18.0.2

start_servers 198.18.0.2 443 selected
run_client 198.18.0.2 443 selected
assert_eq "${root}/observed/selected.tcp.peer" 203.0.113.2
assert_eq "${root}/observed/selected.udp.peer" 203.0.113.2
assert_eq "${root}/observed/selected.tcp.reply" 198.18.0.2
assert_eq "${root}/observed/selected.udp.reply" 198.18.0.2

# The default listener and another selected-address port keep generic SNAT.
start_servers 198.18.0.1 443 default
run_client 198.18.0.1 443 default
for row in default.tcp.peer default.udp.peer; do assert_eq "${root}/observed/${row}" 172.31.0.1; done
for row in default.tcp.reply default.udp.reply; do assert_eq "${root}/observed/${row}" 198.18.0.1; done
start_servers 198.18.0.2 444 otherport
run_client 198.18.0.2 444 otherport
for row in otherport.tcp.peer otherport.udp.peer; do assert_eq "${root}/observed/${row}" 172.31.0.1; done
for row in otherport.tcp.reply otherport.udp.reply; do assert_eq "${root}/observed/${row}" 198.18.0.2; done

# A failed transactional transition restores the prior destination's exact
# exemptions and reply filters rather than leaving a partially switched policy.
if PUBLIC_INGRESS_TEST_FAIL_RESTORE=1 public_ingress_policy "${workspace}" "${runtime}" 198.18.0.2 198.18.0.3; then exit 1; fi
assert_policy 198.18.0.2

public_ingress_policy "${workspace}" "${runtime}" 198.18.0.2 ''
assert_policy ''
start_servers 198.18.0.2 443 selected
run_client 198.18.0.2 443 selected
assert_eq "${root}/observed/selected.tcp.peer" 172.31.0.1
assert_eq "${root}/observed/selected.udp.peer" 172.31.0.1
assert_eq "${root}/observed/selected.tcp.reply" 198.18.0.2
assert_eq "${root}/observed/selected.udp.reply" 198.18.0.2
echo 'public ingress source kernel regression passed'
'''

with tempfile.TemporaryDirectory(prefix="prodigy-public-ingress-source-") as temp:
    runner = pathlib.Path(temp) / "run.sh"
    runner.write_text(script)
    runner.chmod(0o755)
    command = ["unshare", "--net", "--mount", "--mount-proc", str(runner), str(provider), str(boundary_elf), temp]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    sys.stdout.write(result.stdout)
    if result.returncode:
        fail(f"isolated kernel regression failed with exit status {result.returncode}")
