#!/usr/bin/env bash
set -euo pipefail

RUNTIME_TARBALL="${1:-${PRODIGY_DEV_VM_RUNTIME_TARBALL:-}}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_WORK_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
WORK_ROOT="${PRODIGY_DEV_VM_OS_UPDATE_WORK_ROOT:-${REPO_WORK_ROOT}/.run/heterogeneous-os-update-vms}"
IMAGE_ROOT="${WORK_ROOT}/images"
VM_ROOT="${WORK_ROOT}/vms"
SHARED_ROOT="${WORK_ROOT}/shared"
SSH_KEY="${WORK_ROOT}/vm_ed25519"
KNOWN_HOSTS="${WORK_ROOT}/known_hosts"

CONTROL_SOCKET="/run/prodigy-test/prodigy-mothership.sock"
WORKSPACE_ROOT="/run/prodigy-test"
MCAST_GROUP="${PRODIGY_DEV_VM_OS_UPDATE_MCAST_GROUP:-230.88.0.1}"
MCAST_PORT="${PRODIGY_DEV_VM_OS_UPDATE_MCAST_PORT:-12345}"
SSH_BASE_PORT="${PRODIGY_DEV_VM_OS_UPDATE_SSH_BASE_PORT:-25220}"
VM_MEMORY_MB="${PRODIGY_DEV_VM_OS_UPDATE_MEMORY_MB:-3072}"
VM_CPUS="${PRODIGY_DEV_VM_OS_UPDATE_CPUS:-2}"
BOOT_TIMEOUT_S="${PRODIGY_DEV_VM_OS_UPDATE_BOOT_TIMEOUT_S:-240}"
ROLLOUT_TIMEOUT_S="${PRODIGY_DEV_VM_OS_UPDATE_ROLLOUT_TIMEOUT_S:-1200}"
KEEP_VMS="${PRODIGY_DEV_VM_OS_UPDATE_KEEP_VMS:-0}"
REAL_PACKAGE_UPDATE="${PRODIGY_DEV_VM_OS_UPDATE_REAL_PACKAGE_UPDATE:-1}"
FULL_DISTRO_UPGRADE="${PRODIGY_DEV_VM_OS_UPDATE_FULL_DISTRO_UPGRADE:-0}"
TLS_NOT_BEFORE_BACKDATE_S="${PRODIGY_DEV_VM_OS_UPDATE_TLS_NOT_BEFORE_BACKDATE_S:-300}"

UBUNTU_IMAGE_URL="${PRODIGY_DEV_VM_OS_UPDATE_UBUNTU_IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
DEBIAN_IMAGE_URL="${PRODIGY_DEV_VM_OS_UPDATE_DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2}"
FEDORA_IMAGE_URL="${PRODIGY_DEV_VM_OS_UPDATE_FEDORA_IMAGE_URL:-https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2}"

DISTRO_NAMES=(ubuntu debian fedora)
DISTRO_URLS=("${UBUNTU_IMAGE_URL}" "${DEBIAN_IMAGE_URL}" "${FEDORA_IMAGE_URL}")
DISTRO_DISKS=("${IMAGE_ROOT}/ubuntu.qcow2" "${IMAGE_ROOT}/debian.qcow2" "${IMAGE_ROOT}/fedora.qcow2")
DISTRO_PRIVATE4=(10.88.0.11 10.88.0.12 10.88.0.13)
DISTRO_PRIVATE6=(fd00:88::11 fd00:88::12 fd00:88::13)
DISTRO_HOSTS=(prodigy-ubuntu prodigy-debian prodigy-fedora)
DISTRO_TARGETS=()

log()
{
   printf '%s\n' "$*"
}

fail()
{
   log "FAIL: $*"
   exit 1
}

require_cmd()
{
   local cmd="$1"
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      fail "missing required command: ${cmd}"
   fi
}

vm_ssh_port()
{
   local idx="$1"
   echo $((SSH_BASE_PORT + idx))
}

vm_cluster_mac()
{
   local idx="$1"
   printf '52:54:00:88:%02x:02\n' "${idx}"
}

vm_mgmt_mac()
{
   local idx="$1"
   printf '52:54:00:88:%02x:01\n' "${idx}"
}

ssh_vm()
{
   local idx="$1"
   shift

   ssh \
      -i "${SSH_KEY}" \
      -p "$(vm_ssh_port "${idx}")" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile="${KNOWN_HOSTS}" \
      -o ConnectTimeout=5 \
      root@127.0.0.1 \
      "$@"
}

scp_to_vm()
{
   local idx="$1"
   local src="$2"
   local dst="$3"

   scp \
      -i "${SSH_KEY}" \
      -P "$(vm_ssh_port "${idx}")" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile="${KNOWN_HOSTS}" \
      -o ConnectTimeout=5 \
      "${src}" \
      "root@127.0.0.1:${dst}"
}

wait_for_ssh()
{
   local idx="$1"
   local deadline=$(( $(date +%s) + BOOT_TIMEOUT_S ))

   while [[ "$(date +%s)" -lt "${deadline}" ]]
   do
      if ssh_vm "${idx}" "true" >/dev/null 2>&1
      then
         return 0
      fi

      sleep 1
   done

   return 1
}

runtime_cmd="/usr/local/bin/prodigy-runtime"

run_mothership()
{
   local idx="$1"
   shift

   ssh_vm "${idx}" "timeout 8s env PRODIGY_MOTHERSHIP_SOCKET=${CONTROL_SOCKET} PRODIGY_STATE_DB=/var/lib/prodigy/mothership-state ${runtime_cmd} /opt/prodigy/runtime/mothership $*"
}

mothership_socket_accepting()
{
   local idx="$1"

   ssh_vm "${idx}" "python3 - '${CONTROL_SOCKET}'" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(0.25)
try:
    sock.connect(sys.argv[1])
except Exception:
    sys.exit(1)
finally:
    sock.close()
PY
}

download_image()
{
   local url="$1"
   local output="$2"

   if [[ -f "${output}" ]]
   then
      return 0
   fi

   mkdir -p "$(dirname "${output}")"
   log "IMAGE_DOWNLOAD url=${url} output=${output}"
   curl -L --fail --retry 3 --connect-timeout 20 -o "${output}.partial" "${url}"
   mv "${output}.partial" "${output}"
}

make_seed_image()
{
   local idx="$1"
   local name="${DISTRO_NAMES[$((idx - 1))]}"
   local hostname="${DISTRO_HOSTS[$((idx - 1))]}"
   local private4="${DISTRO_PRIVATE4[$((idx - 1))]}"
   local private6="${DISTRO_PRIVATE6[$((idx - 1))]}"
   local mgmt_mac cluster_mac
   mgmt_mac="$(vm_mgmt_mac "${idx}")"
   cluster_mac="$(vm_cluster_mac "${idx}")"

   local seed_dir="${VM_ROOT}/${name}/seed"
   local seed_img="${VM_ROOT}/${name}/seed.img"
   local seed_mnt="${VM_ROOT}/${name}/seedmnt"
   rm -rf "${seed_dir}" "${seed_mnt}" "${seed_img}"
   mkdir -p "${seed_dir}" "${seed_mnt}"

   cat > "${seed_dir}/meta-data" <<EOF_META
instance-id: prodigy-os-update-${name}
local-hostname: ${hostname}
EOF_META

   cat > "${seed_dir}/network-config" <<EOF_NET
version: 2
ethernets:
  mgmt0:
    match:
      macaddress: "${mgmt_mac}"
    set-name: eth0
    dhcp4: true
    optional: true
  cluster0:
    match:
      macaddress: "${cluster_mac}"
    set-name: eth1
    dhcp4: false
    dhcp6: false
    optional: true
EOF_NET

   cat > "${seed_dir}/user-data" <<EOF_USER
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - default
  - name: root
    lock_passwd: false
    ssh_authorized_keys:
      - $(cat "${SSH_KEY}.pub")
write_files:
  - path: /usr/local/bin/prodigy-runtime
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      exec /opt/prodigy/runtime/ld-linux-x86-64.so.2 --library-path /opt/prodigy/runtime/lib "\$@"
  - path: /usr/local/bin/prodigy-netns-setup
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      cluster_mac="${cluster_mac}"
      private4="${private4}"
      private6="${private6}"
      mkdir -p /run/prodigy-test /var/lib/prodigy
      if ! ip netns list | awk '{print \$1}' | grep -qx prodigy
      then
         ip netns add prodigy
      fi
      if ! ip netns exec prodigy ip link show bond0 >/dev/null 2>&1
      then
         cluster_if="\$(ip -o link | awk -v mac="\${cluster_mac}" 'tolower(\$0) ~ tolower("link/ether " mac) {gsub(":", "", \$2); print \$2; exit}')"
         if [[ -z "\${cluster_if}" ]]
         then
            echo "missing cluster interface with mac \${cluster_mac}" >&2
            exit 1
         fi
         ip link set "\${cluster_if}" netns prodigy
         ip netns exec prodigy ip link set "\${cluster_if}" name bond0
      fi
      ip netns exec prodigy ip link set lo up
      ip netns exec prodigy ip addr replace "\${private4}/24" dev bond0
      ip netns exec prodigy ip addr replace "\${private6}/64" dev bond0
      ip netns exec prodigy ip link set bond0 up
  - path: /usr/local/bin/prodigy-test-start
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      mkdir -p /var/lib/prodigy /var/log/prodigy /run/prodigy-test
      if [[ ! -s /var/lib/prodigy/prodigy-dev-os-release ]]
      then
         . /etc/os-release
         printf 'ID=%s\nVERSION_ID=%s\n' "\${ID}" "\${VERSION_ID:-0}" > /var/lib/prodigy/prodigy-dev-os-release
      fi
      host_netns_ino="\$(stat -Lc %i /proc/1/ns/net)"
      exec ip netns exec prodigy env \\
         PRODIGY_DEV_MODE=1 \\
         PRODIGY_DEV_ALLOW_BPF_ATTACH=0 \\
         PRODIGY_HOST_INGRESS_EBPF= \\
         PRODIGY_HOST_EGRESS_EBPF= \\
         PRODIGY_HOST_NETNS_INO="\${host_netns_ino}" \\
         PRODIGY_BOOTSTRAP_BRAIN_COUNT=3 \\
         PRODIGY_DEV_SHARED_TRANSPORT_TLS_DIR=/var/lib/prodigy/transport-tls \\
         PRODIGY_DEV_OS_RELEASE_PATH=/var/lib/prodigy/prodigy-dev-os-release \\
         PRODIGY_DEV_OS_UPDATE_CADENCE_MS=1000 \\
         PRODIGY_STATE_DB=/var/lib/prodigy/state \\
         /opt/prodigy/runtime/ld-linux-x86-64.so.2 \\
         --library-path /opt/prodigy/runtime/lib \\
         /opt/prodigy/runtime/prodigy \\
         --isolated \\
         --netdev=bond0 \\
         --boot-json-path=/etc/prodigy/boot.json
  - path: /etc/systemd/system/prodigy-netns.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Prodigy test netns
      After=network.target

      [Service]
      Type=oneshot
      RemainAfterExit=yes
      ExecStart=/usr/local/bin/prodigy-netns-setup

      [Install]
      WantedBy=multi-user.target
  - path: /etc/systemd/system/prodigy-test.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Prodigy heterogeneous OS update VM test
      After=prodigy-netns.service
      Requires=prodigy-netns.service

      [Service]
      Restart=always
      RestartSec=1
      ExecStart=/usr/local/bin/prodigy-test-start

      [Install]
      WantedBy=multi-user.target
runcmd:
  - mkdir -p /opt/prodigy /etc/prodigy /var/lib/prodigy /run/prodigy-test
  - . /etc/os-release; printf 'ID=%s\nVERSION_ID=%s\n' "\$ID" "\${VERSION_ID:-0}" > /var/lib/prodigy/prodigy-dev-os-release
  - systemctl daemon-reload
EOF_USER

   dd if=/dev/zero of="${seed_img}" bs=1M count=16 status=none
   mkfs.vfat -n CIDATA "${seed_img}" >/dev/null
   mount -o loop "${seed_img}" "${seed_mnt}"
   cp "${seed_dir}/meta-data" "${seed_dir}/network-config" "${seed_dir}/user-data" "${seed_mnt}/"
   umount "${seed_mnt}"
   rmdir "${seed_mnt}"
}

prepare_runtime()
{
   mkdir -p "${SHARED_ROOT}"
   if [[ -n "${RUNTIME_TARBALL}" ]]
   then
      [[ -f "${RUNTIME_TARBALL}" ]] || fail "runtime tarball not found: ${RUNTIME_TARBALL}"
      rm -rf "${SHARED_ROOT}/runtime"
      tar -C "${SHARED_ROOT}" -xzf "${RUNTIME_TARBALL}"
   fi

   [[ -x "${SHARED_ROOT}/runtime/prodigy" ]] || fail "missing shared runtime/prodigy"
   [[ -x "${SHARED_ROOT}/runtime/mothership" ]] || fail "missing shared runtime/mothership"
   [[ -x "${SHARED_ROOT}/runtime/prodigy_test_cluster_boot_json" ]] || fail "missing shared runtime/prodigy_test_cluster_boot_json"
   [[ -x "${SHARED_ROOT}/runtime/ld-linux-x86-64.so.2" ]] || fail "missing shared runtime loader"
   mkdir -p "${SHARED_ROOT}/transport-tls"

   if [[ -z "${RUNTIME_TARBALL}" ]]
   then
      RUNTIME_TARBALL="${SHARED_ROOT}/prodigy-runtime-package.tgz"
      tar -C "${SHARED_ROOT}" -czf "${RUNTIME_TARBALL}" runtime
   fi

   if [[ ! -s "${SHARED_ROOT}/transport-tls/cluster-root.pem" || ! -s "${SHARED_ROOT}/transport-tls/cluster-root.key.pem" ]]
   then
      local not_before=""
      not_before="$(date -u -d "@$(( $(date +%s) - TLS_NOT_BEFORE_BACKDATE_S ))" +%Y%m%d%H%M%SZ)"
      local csr_path="${SHARED_ROOT}/transport-tls/cluster-root.csr.pem"
      local ext_path="${SHARED_ROOT}/transport-tls/cluster-root.ext"
      cat > "${ext_path}" <<'EOF_EXT'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF_EXT
      openssl genpkey -algorithm ED25519 -out "${SHARED_ROOT}/transport-tls/cluster-root.key.pem" >/dev/null 2>&1
      openssl req \
         -new \
         -key "${SHARED_ROOT}/transport-tls/cluster-root.key.pem" \
         -out "${csr_path}" \
         -subj "/CN=Prodigy Dev Transport Root" >/dev/null 2>&1
      openssl x509 \
         -req \
         -in "${csr_path}" \
         -signkey "${SHARED_ROOT}/transport-tls/cluster-root.key.pem" \
         -out "${SHARED_ROOT}/transport-tls/cluster-root.pem" \
         -days 3650 \
         -not_before "${not_before}" \
         -extfile "${ext_path}" >/dev/null 2>&1
      rm -f "${csr_path}" "${ext_path}"
   fi
}

start_vm()
{
   local idx="$1"
   local name="${DISTRO_NAMES[$((idx - 1))]}"
   local base="${DISTRO_DISKS[$((idx - 1))]}"
   local vm_dir="${VM_ROOT}/${name}"
   local disk="${vm_dir}/disk.qcow2"
   local seed="${vm_dir}/seed.img"
   local pidfile="${vm_dir}/qemu.pid"
   local serial="${vm_dir}/serial.log"
   local mgmt_mac cluster_mac
   mgmt_mac="$(vm_mgmt_mac "${idx}")"
   cluster_mac="$(vm_cluster_mac "${idx}")"

   mkdir -p "${vm_dir}"
   rm -f "${disk}"
   qemu-img create -f qcow2 -F qcow2 -b "${base}" "${disk}" 12G >/dev/null
   customize_vm_disk_for_fast_boot "${disk}"
   qemu-system-x86_64 \
      -enable-kvm \
      -m "${VM_MEMORY_MB}" \
      -smp "${VM_CPUS}" \
      -display none \
      -serial "file:${serial}" \
      -pidfile "${pidfile}" \
      -daemonize \
      -drive "if=virtio,format=qcow2,file=${disk}" \
      -drive "if=virtio,format=raw,file=${seed},readonly=on" \
      -netdev "user,id=mgmt,hostfwd=tcp:127.0.0.1:$(vm_ssh_port "${idx}")-:22" \
      -device "virtio-net-pci,netdev=mgmt,mac=${mgmt_mac}" \
      -netdev "socket,id=cluster,mcast=${MCAST_GROUP}:${MCAST_PORT}" \
      -device "virtio-net-pci,netdev=cluster,mac=${cluster_mac}"
}

stop_vms()
{
   local pidfile=""

   if [[ "${KEEP_VMS}" == "1" ]]
   then
      return 0
   fi

   for pidfile in "${VM_ROOT}"/*/qemu.pid
   do
      [[ -f "${pidfile}" ]] || continue
      local pid=""
      pid="$(cat "${pidfile}" 2>/dev/null || true)"
      if [[ -n "${pid}" ]]
      then
         kill "${pid}" >/dev/null 2>&1 || true
      fi
   done
}

customize_vm_disk_for_fast_boot()
{
   local disk="$1"
   local nbd=""
   local mount_root="${WORK_ROOT}/disk-mount"
   local mounted=0

   modprobe nbd max_part=16 >/dev/null 2>&1 || true
   mkdir -p "${mount_root}"

   for candidate in /dev/nbd{0..15}
   do
      if qemu-nbd -c "${candidate}" "${disk}" >/dev/null 2>&1
      then
         nbd="${candidate}"
         break
      fi
   done

   [[ -n "${nbd}" ]] || fail "could not attach ${disk} to an nbd device"

   cleanup_nbd()
   {
      if [[ "${mounted}" == "1" ]]
      then
         umount "${mount_root}" >/dev/null 2>&1 || true
      fi
      qemu-nbd -d "${nbd}" >/dev/null 2>&1 || true
   }

   blockdev --rereadpt "${nbd}" >/dev/null 2>&1 || true
   udevadm settle >/dev/null 2>&1 || true

   local candidates=("${nbd}")
   local part=""
   shopt -s nullglob
   local parts=()
   local attempt=0
   for attempt in $(seq 1 20)
   do
      parts=("${nbd}"p*)
      if [[ "${#parts[@]}" -gt 0 ]]
      then
         break
      fi
      sleep 0.25
   done
   for part in "${parts[@]}"
   do
      candidates+=("${part}")
   done
   shopt -u nullglob

   for part in "${candidates[@]}"
   do
      if mount "${part}" "${mount_root}" >/dev/null 2>&1
      then
         mounted=1
         local guest_root=""
         if [[ -d "${mount_root}/etc" ]]
         then
            guest_root="${mount_root}"
         elif [[ -d "${mount_root}/root/etc" ]]
         then
            guest_root="${mount_root}/root"
         fi

         if [[ -n "${guest_root}" ]]
         then
            mkdir -p "${guest_root}/etc/systemd/system"
            ln -sfn /dev/null "${guest_root}/etc/systemd/system/systemd-networkd-wait-online.service"
            ln -sfn /dev/null "${guest_root}/etc/systemd/system/NetworkManager-wait-online.service"
            sync
            cleanup_nbd
            return 0
         fi

         umount "${mount_root}" >/dev/null
         mounted=0
      fi
   done

   cleanup_nbd
   fail "could not find root filesystem in ${disk}"
}

collect_guest_os_metadata()
{
   local idx="$1"
   ssh_vm "${idx}" ". /etc/os-release; printf '%s\t%s\n' \"\$ID\" \"\${VERSION_ID:-0}\""
}

install_runtime_on_vm()
{
   local idx="$1"

   ssh_vm "${idx}" "mkdir -p /opt/prodigy /var/lib/prodigy/transport-tls /etc/prodigy /run/prodigy-test"
   scp_to_vm "${idx}" "${RUNTIME_TARBALL}" "/opt/prodigy/runtime.tgz"
   scp_to_vm "${idx}" "${SHARED_ROOT}/transport-tls/cluster-root.pem" "/var/lib/prodigy/transport-tls/cluster-root.pem"
   scp_to_vm "${idx}" "${SHARED_ROOT}/transport-tls/cluster-root.key.pem" "/var/lib/prodigy/transport-tls/cluster-root.key.pem"
   ssh_vm "${idx}" "tar -C /opt/prodigy -xzf /opt/prodigy/runtime.tgz && chmod +x /opt/prodigy/runtime/prodigy /opt/prodigy/runtime/mothership /opt/prodigy/runtime/prodigy_test_cluster_boot_json /opt/prodigy/runtime/ld-linux-x86-64.so.2"
   ssh_vm "${idx}" "${runtime_cmd} /opt/prodigy/runtime/prodigy_test_cluster_boot_json --role=brain --control-socket-path=${CONTROL_SOCKET} --local-index=${idx} --brains=3 --peer-family=private6 --machine=${DISTRO_PRIVATE4[0]},${DISTRO_PRIVATE6[0]},-,1 --machine=${DISTRO_PRIVATE4[1]},${DISTRO_PRIVATE6[1]},-,1 --machine=${DISTRO_PRIVATE4[2]},${DISTRO_PRIVATE6[2]},-,1 > /etc/prodigy/boot.json"
   ssh_vm "${idx}" "systemctl daemon-reload && systemctl enable prodigy-netns.service prodigy-test.service"
}

install_policy_json_on_vm()
{
   local idx="$1"

   scp_to_vm "${idx}" "${SHARED_ROOT}/os-update-policies.json" "/var/lib/prodigy/os-update-policies.json"
}

install_os_update_script_on_vm()
{
   local idx="$1"
   local os_id="$2"
   local script="${SHARED_ROOT}/os-update-${idx}.sh"

   cat > "${script}" <<'EOF_SCRIPT'
#!/bin/sh
set -eu

wait_for_network()
{
   nsenter --net=/proc/1/ns/net -- python3 - "$1" "$2" <<'PY'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
deadline = time.time() + 60
last = None
while time.time() < deadline:
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        for info in infos:
            sock = socket.socket(info[0], info[1], info[2])
            sock.settimeout(3)
            try:
                sock.connect(info[4])
                sock.close()
                raise SystemExit(0)
            except Exception as exc:
                last = exc
            finally:
                sock.close()
    except Exception as exc:
        last = exc
    time.sleep(1)
raise SystemExit("network not ready for %s:%s: %s" % (host, port, last))
PY
}

run_package_update()
{
EOF_SCRIPT

   if [[ "${REAL_PACKAGE_UPDATE}" == "0" ]]
   then
      cat >> "${script}" <<'EOF_SCRIPT'
   return 0
EOF_SCRIPT
   elif [[ "${os_id}" == "ubuntu" || "${os_id}" == "debian" ]]
   then
      if [[ "${FULL_DISTRO_UPGRADE}" == "1" ]]
      then
         cat >> "${script}" <<'EOF_SCRIPT'
   wait_for_network archive.ubuntu.com 80
   nsenter --net=/proc/1/ns/net -- sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get -o Acquire::ForceIPv4=true -o APT::Update::Error-Mode=any update; apt-get -o Acquire::ForceIPv4=true -y -o Dpkg::Options::=--force-confold upgrade'
EOF_SCRIPT
      else
         cat >> "${script}" <<'EOF_SCRIPT'
   wait_for_network archive.ubuntu.com 80
   nsenter --net=/proc/1/ns/net -- sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get -o Acquire::ForceIPv4=true -o APT::Update::Error-Mode=any update; apt-get -o Acquire::ForceIPv4=true -y --only-upgrade install bash'
EOF_SCRIPT
      fi
   elif [[ "${os_id}" == "fedora" ]]
   then
      if [[ "${FULL_DISTRO_UPGRADE}" == "1" ]]
      then
         cat >> "${script}" <<'EOF_SCRIPT'
   wait_for_network mirrors.fedoraproject.org 443
   nsenter --net=/proc/1/ns/net -- sh -c 'dnf -y --setopt=ip_resolve=4 upgrade --refresh'
   /usr/sbin/restorecon -RF /usr/sbin/sshd /usr/libexec/openssh /usr/bin/bash /etc/ssh /root
   /usr/sbin/matchpathcon -V /usr/sbin/sshd /usr/libexec/openssh/sshd-session /usr/bin/bash
EOF_SCRIPT
      else
         cat >> "${script}" <<'EOF_SCRIPT'
   wait_for_network mirrors.fedoraproject.org 443
   nsenter --net=/proc/1/ns/net -- sh -c 'dnf -y --setopt=ip_resolve=4 makecache --refresh; dnf -y --setopt=ip_resolve=4 upgrade bash --refresh'
EOF_SCRIPT
      fi
   else
      fail "unsupported distro in VM OS update matrix: ${os_id}"
   fi

   cat >> "${script}" <<'EOF_SCRIPT'
}

run_package_update
mkdir -p /var/lib/prodigy
printf 'ID=%s\nVERSION_ID=%s\n' "${PRODIGY_CURRENT_OS_ID}" "${PRODIGY_TARGET_OS_VERSION_ID}" > "${PRODIGY_DEV_OS_RELEASE_PATH}"
systemctl reboot
EOF_SCRIPT

   chmod 0755 "${script}"
   ssh_vm "${idx}" "mkdir -p /var/lib/prodigy"
   scp_to_vm "${idx}" "${script}" "/var/lib/prodigy/os-update.sh"
   ssh_vm "${idx}" "chmod 0755 /var/lib/prodigy/os-update.sh"
}

start_prodigy_on_vm()
{
   local idx="$1"

   ssh_vm "${idx}" "systemctl start prodigy-netns.service && systemctl restart prodigy-test.service"
}

restart_prodigy_main_on_vm()
{
   local idx="$1"

   ssh_vm "${idx}" "systemctl kill --kill-who=main -s KILL prodigy-test.service || true; systemctl reset-failed prodigy-test.service; systemctl start prodigy-test.service"
}

assert_single_prodigy_process_on_vm()
{
   local idx="$1"

   ssh_vm "${idx}" "python3 -" <<'PY'
import pathlib
import sys

needle = b"/opt/prodigy/runtime/prodigy\x00--isolated\x00--netdev=bond0\x00--boot-json-path=/etc/prodigy/boot.json"
matches = []
for path in pathlib.Path("/proc").iterdir():
    if not path.name.isdigit():
        continue
    try:
        cmdline = (path / "cmdline").read_bytes()
    except OSError:
        continue
    if needle in cmdline:
        matches.append(path.name)

if len(matches) != 1:
    print("bad prodigy process count: count=%d pids=%s" % (len(matches), ",".join(matches)), file=sys.stderr)
    raise SystemExit(1)
PY
}

assert_single_prodigy_processes()
{
   local idx=0

   for idx in 1 2 3
   do
      assert_single_prodigy_process_on_vm "${idx}" || fail "unexpected Prodigy process count on ${DISTRO_NAMES[$((idx - 1))]}"
   done
}

write_policy_json()
{
   local metadata_json="$1"
   local output="${SHARED_ROOT}/os-update-policies.json"

   PRODIGY_VM_METADATA_JSON="${metadata_json}" \
   python3 - "${output}" <<'PY'
import json
import os
import sys

metadata = json.loads(os.environ["PRODIGY_VM_METADATA_JSON"])
policies = []

for item in metadata:
    os_id = item["osID"]
    version = item["versionID"] or "0"
    target = version + "-prodigy-updated"
    if os_id not in ("ubuntu", "debian", "fedora"):
        raise SystemExit(f"unsupported distro in VM OS update matrix: {os_id}")
    policies.append({
        "osID": os_id,
        "targetVersionID": target,
        "command": "/var/lib/prodigy/os-update.sh",
        "includeVMs": True
    })
    item["targetVersionID"] = target

with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(policies, f, separators=(",", ":"))

print(json.dumps(metadata, separators=(",", ":")))
PY
}

configure_cluster()
{
   local idx=0
   local attempt=0

   for attempt in $(seq 1 180)
   do
      for idx in 1 2 3
      do
         if mothership_socket_accepting "${idx}" >/dev/null 2>&1
         then
            log "CONFIGURE_ATTEMPT leaderCandidate=${idx}"
            if ssh_vm "${idx}" "POLICIES=\"\$(cat /var/lib/prodigy/os-update-policies.json)\"; env PRODIGY_DEV_CONFIGURE_OS_UPDATES_ENABLED=1 PRODIGY_DEV_CONFIGURE_OS_UPDATE_POLICIES_JSON=\"\$POLICIES\" PRODIGY_DEV_CONFIGURE_MAX_OS_DRAINS=1 PRODIGY_DEV_CONFIGURE_MACHINE_UPDATE_CADENCE_MINS=1 ${runtime_cmd} /opt/prodigy/runtime/mothership configureTestCluster ${WORKSPACE_ROOT} 3 3 private6 0 9000 17 1 prodigy-dev bareMetal 8 16384 262144"
            then
               log "CONFIGURE_SUCCESS leader=${idx}"
               return 0
            fi
         fi
      done

      sleep 1
   done

   return 1
}

cluster_report_from_any_vm()
{
   local output="$1"
   local idx=0

   for idx in 1 2 3
   do
      if mothership_socket_accepting "${idx}" >/dev/null 2>&1 \
         && run_mothership "${idx}" "clusterReport local" > "${output}" 2>&1
      then
         echo "${idx}"
         return 0
      fi
   done

   return 1
}

wait_for_initial_healthy()
{
   local deadline=$(( $(date +%s) + BOOT_TIMEOUT_S ))
   local report="${WORK_ROOT}/initial.clusterReport.log"
   local leader=""

   while [[ "$(date +%s)" -lt "${deadline}" ]]
   do
      if leader="$(cluster_report_from_any_vm "${report}" 2>/dev/null)" \
         && [[ "$(grep -c 'Machine: state=healthy ' "${report}" 2>/dev/null || true)" -ge 3 ]]
      then
         log "INITIAL_HEALTHY leader=${leader}"
         return 0
      fi

      sleep 1
   done

   cat "${report}" 2>/dev/null || true
   return 1
}

wait_for_rollout_complete()
{
   local targets_json="$1"
   local deadline=$(( $(date +%s) + ROLLOUT_TIMEOUT_S ))
   local report="${WORK_ROOT}/final.clusterReport.log"
   local leader=""

   while [[ "$(date +%s)" -lt "${deadline}" ]]
   do
      if leader="$(cluster_report_from_any_vm "${report}" 2>/dev/null)"
      then
         if PRODIGY_VM_TARGETS_JSON="${targets_json}" python3 - "${report}" <<'PY'
import json
import os
import sys

report = open(sys.argv[1], encoding="utf-8", errors="ignore").read()
if "updatingOS=1" in report:
    raise SystemExit(1)
if "rebooting=1" in report:
    raise SystemExit(1)
if report.count("Machine: state=healthy ") < 3:
    raise SystemExit(1)
PY
         then
            local idx=0
            local markers_ok=1
            for idx in 1 2 3
            do
               local target_version=""
               target_version="$(
                  PRODIGY_VM_TARGETS_JSON="${targets_json}" python3 - "${idx}" <<'PY'
import json
import os
import sys

idx = int(sys.argv[1]) - 1
print(json.loads(os.environ["PRODIGY_VM_TARGETS_JSON"])[idx]["targetVersionID"])
PY
               )"

               if ! ssh_vm "${idx}" "systemctl is-active --quiet prodigy-test.service && grep -q 'VERSION_ID=${target_version}' /var/lib/prodigy/prodigy-dev-os-release" >/dev/null 2>&1
               then
                  markers_ok=0
                  break
               fi
            done

            if [[ "${markers_ok}" == "1" ]]
            then
               assert_single_prodigy_processes
               log "HETEROGENEOUS_VM_OS_UPDATE_PASS leader=${leader}"
               return 0
            fi
         fi
      fi

      sleep 2
   done

   cat "${report}" 2>/dev/null || true
   return 1
}

main()
{
   [[ "$(id -u)" -eq 0 ]] || fail "requires root for seed-image loop mounts and KVM"
   require_cmd curl
   require_cmd qemu-system-x86_64
   require_cmd qemu-img
   require_cmd qemu-nbd
   require_cmd mkfs.vfat
   require_cmd mount
   require_cmd umount
   require_cmd ssh
   require_cmd scp
   require_cmd python3
   require_cmd openssl

   mkdir -p "${IMAGE_ROOT}" "${VM_ROOT}" "${SHARED_ROOT}"
   : > "${KNOWN_HOSTS}"

   if [[ ! -f "${SSH_KEY}" ]]
   then
      ssh-keygen -q -t ed25519 -N "" -f "${SSH_KEY}"
   fi

   prepare_runtime

   local idx=0
   for idx in 1 2 3
   do
      download_image "${DISTRO_URLS[$((idx - 1))]}" "${DISTRO_DISKS[$((idx - 1))]}"
      make_seed_image "${idx}"
   done

   trap stop_vms EXIT
   stop_vms
   rm -f "${VM_ROOT}"/*/qemu.pid

   for idx in 1 2 3
   do
      start_vm "${idx}"
   done

   for idx in 1 2 3
   do
      wait_for_ssh "${idx}" || fail "ssh did not become ready for ${DISTRO_NAMES[$((idx - 1))]}"
      log "SSH_READY distro=${DISTRO_NAMES[$((idx - 1))]}"
   done

   local metadata="["
   for idx in 1 2 3
   do
      local os_line os_id version_id
      os_line="$(collect_guest_os_metadata "${idx}")"
      os_id="${os_line%%$'\t'*}"
      version_id="${os_line#*$'\t'}"
      install_os_update_script_on_vm "${idx}" "${os_id}"
      [[ "${metadata}" == "[" ]] || metadata+=","
      metadata+="{\"osID\":\"${os_id}\",\"versionID\":\"${version_id}\"}"
   done
   metadata+="]"

   local targets_json=""
   targets_json="$(write_policy_json "${metadata}")"
   log "OS_UPDATE_POLICIES $(cat "${SHARED_ROOT}/os-update-policies.json")"

   for idx in 1 2 3
   do
      install_runtime_on_vm "${idx}"
      install_policy_json_on_vm "${idx}"
      log "RUNTIME_READY distro=${DISTRO_NAMES[$((idx - 1))]}"
   done

   for idx in 1 2 3
   do
      (start_prodigy_on_vm "${idx}" && log "PRODIGY_STARTED distro=${DISTRO_NAMES[$((idx - 1))]}") &
   done
   wait
   assert_single_prodigy_processes

   sleep 3
   for idx in 1 2 3
   do
      (restart_prodigy_main_on_vm "${idx}" && log "PRODIGY_RESTARTED_FOR_PEER_MESH distro=${DISTRO_NAMES[$((idx - 1))]}") &
   done
   wait
   assert_single_prodigy_processes

   configure_cluster || fail "could not configure Prodigy cluster from any VM"
   wait_for_initial_healthy || fail "cluster did not become initially healthy"
   wait_for_rollout_complete "${targets_json}" || fail "heterogeneous VM OS update rollout did not complete"

   log "OS_UPDATE_HETEROGENEOUS_VM_MATRIX_PASS"
}

main "$@"
