#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" != 0 ]]
then
   echo "SKIP: requires root for isolated fake-machine SSH bootstrap smoke"
   exit 0
fi

for cmd in ip sshd timeout unshare mount mktemp stat bash df getconf sed tr cut cp chmod cat
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command ${cmd}"
      exit 0
   fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
ASSETS_DIR="${SCRIPT_DIR}/assets/ssh"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/.run/build/prodigy-dev-clang-owned}"
PRODIGY_BIN="${PRODIGY_BIN:-${BUILD_DIR}/prodigy}"
SMOKE_BIN="${PRODIGY_REMOTE_BOOTSTRAP_SMOKE_BIN:-${BUILD_DIR}/prodigy_remote_bootstrap_smoke}"
SSHD_BIN="$(command -v sshd)"

if [[ ! -x "${PRODIGY_BIN}" ]]
then
   echo "FAIL: missing prodigy binary at ${PRODIGY_BIN}"
   exit 1
fi

if [[ ! -x "${SMOKE_BIN}" ]]
then
   echo "FAIL: missing remote bootstrap smoke binary at ${SMOKE_BIN}"
   exit 1
fi

for asset in client_ed25519 client_ed25519.pub bootstrap_seed_ed25519 bootstrap_seed_ed25519.pub sshd_host_ed25519
do
   if [[ ! -f "${ASSETS_DIR}/${asset}" ]]
   then
      echo "FAIL: missing SSH test asset ${ASSETS_DIR}/${asset}"
      exit 1
   fi
done

scratch="$(mktemp -d /tmp/prodigy-remote-bootstrap-ssh-smoke-XXXXXX)"
master_ns="prodigy-rbs-master-$$"
target_ns="prodigy-rbs-target-$$"
master_if="rbsm$$"
target_if="rbst$$"
master_ip="10.211.0.1"
target_ip="10.211.0.2"
sshd_pid=""

cleanup()
{
   set +e

   if [[ -n "${sshd_pid}" ]]
   then
      kill "${sshd_pid}" >/dev/null 2>&1 || true
      sleep 0.2
      kill -9 "${sshd_pid}" >/dev/null 2>&1 || true
      wait "${sshd_pid}" >/dev/null 2>&1 || true
   fi

   for ns in "${master_ns}" "${target_ns}"
   do
      if ip netns list | rg -q "^${ns}\\b"
      then
         pids="$(ip netns pids "${ns}" 2>/dev/null || true)"
         if [[ -n "${pids}" ]]
         then
            for pid in ${pids}
            do
               kill -9 "${pid}" >/dev/null 2>&1 || true
            done
         fi
      fi
   done

   ip netns del "${master_ns}" >/dev/null 2>&1 || true
   ip netns del "${target_ns}" >/dev/null 2>&1 || true
   rm -rf "${scratch}" "${bootstrap_seed_root}"
}
trap cleanup EXIT

remote_root="${scratch}/remote-root"
state_dir="${scratch}/var-lib-prodigy"
state_db_dir="${state_dir}/state"
systemd_dir="${scratch}/systemd"
systemctl_log="${scratch}/systemctl.log"
fake_systemctl="${scratch}/fake-systemctl"
authorized_keys="${scratch}/authorized_keys"
client_key="${scratch}/client_key"
bootstrap_seed_root="/tmp/prodigy-bootstrap-seed-$$"
bootstrap_seed_key="${bootstrap_seed_root}/id_ed25519"
host_key="${scratch}/host_key"
sshd_config="${scratch}/sshd_config"
sshd_log="${scratch}/sshd.log"
remote_seed_key_mount="${bootstrap_seed_root}"
remote_seed_key_dir="${scratch}/remote-seed-ssh"

mkdir -p "${remote_root}" "${state_dir}" "${systemd_dir}" "${remote_seed_key_dir}" "${bootstrap_seed_root}"
: > "${systemctl_log}"

cp "${ASSETS_DIR}/client_ed25519" "${client_key}"
cp "${ASSETS_DIR}/client_ed25519.pub" "${client_key}.pub"
cp "${ASSETS_DIR}/bootstrap_seed_ed25519" "${bootstrap_seed_key}"
cp "${ASSETS_DIR}/bootstrap_seed_ed25519.pub" "${bootstrap_seed_key}.pub"
cp "${ASSETS_DIR}/sshd_host_ed25519" "${host_key}"
chmod 600 "${client_key}" "${bootstrap_seed_key}" "${host_key}"
chmod 644 "${client_key}.pub" "${bootstrap_seed_key}.pub"
cat "${client_key}.pub" > "${authorized_keys}"

cat > "${fake_systemctl}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
echo "\$*" >> "${systemctl_log}"
exit 0
EOF
chmod 755 "${fake_systemctl}"

cat > "${sshd_config}" <<EOF
Port 2222
ListenAddress ${target_ip}
AddressFamily inet
HostKey ${host_key}
PidFile ${scratch}/sshd.pid
AuthorizedKeysFile ${authorized_keys}
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin yes
PermitEmptyPasswords no
UsePAM no
StrictModes no
PermitUserEnvironment no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
UseDNS no
Subsystem sftp internal-sftp
LogLevel VERBOSE
EOF

ip netns add "${master_ns}"
ip netns add "${target_ns}"
ip netns exec "${master_ns}" ip link set lo up
ip netns exec "${target_ns}" ip link set lo up

ip link add "${master_if}" type veth peer name "${target_if}"
ip link set "${master_if}" netns "${master_ns}"
ip link set "${target_if}" netns "${target_ns}"
ip netns exec "${master_ns}" ip addr add "${master_ip}/30" dev "${master_if}"
ip netns exec "${master_ns}" ip link set "${master_if}" up
ip netns exec "${target_ns}" ip addr add "${target_ip}/30" dev "${target_if}"
ip netns exec "${target_ns}" ip link set "${target_if}" up

ip netns exec "${target_ns}" \
   unshare -m --fork --pid --mount-proc \
   env \
      STATE_DIR="${state_dir}" \
      SYSTEMD_DIR="${systemd_dir}" \
      FAKE_SYSTEMCTL="${fake_systemctl}" \
      SSHD_CONFIG="${sshd_config}" \
      SSHD_BIN="${SSHD_BIN}" \
      SSHD_LOG="${sshd_log}" \
   bash -euo pipefail -c '
      mkdir -p /run/sshd /var/lib/prodigy /etc/systemd/system
      mkdir -p "'"${remote_seed_key_mount}"'"
      mount --bind "${STATE_DIR}" /var/lib/prodigy
      mount --bind "${SYSTEMD_DIR}" /etc/systemd/system
      mount --bind "'"${remote_seed_key_dir}"'" "'"${remote_seed_key_mount}"'"

      if [[ -e /usr/bin/systemctl ]]
      then
         mount --bind "${FAKE_SYSTEMCTL}" /usr/bin/systemctl
      fi

      if [[ -e /bin/systemctl ]]
      then
         mount --bind "${FAKE_SYSTEMCTL}" /bin/systemctl
      fi

      exec "${SSHD_BIN}" -D -e -f "${SSHD_CONFIG}" -E "${SSHD_LOG}"
   ' &
sshd_pid="$!"

ready=0
for _ in $(seq 1 40)
do
   if ip netns exec "${master_ns}" timeout 1 bash -lc "</dev/tcp/${target_ip}/2222" >/dev/null 2>&1
   then
      ready=1
      break
   fi

   sleep 0.5
done

if [[ "${ready}" != 1 ]]
then
   echo "FAIL: sshd did not become reachable in isolated target namespace"
   [[ -f "${sshd_log}" ]] && cat "${sshd_log}"
   exit 1
fi

ip netns exec "${master_ns}" \
   env \
      PRODIGY_REMOTE_BOOTSTRAP_MASTER_IP="${master_ip}" \
      PRODIGY_REMOTE_BOOTSTRAP_TARGET_IP="${target_ip}" \
      PRODIGY_REMOTE_BOOTSTRAP_SSH_KEY="${client_key}" \
      PRODIGY_REMOTE_BOOTSTRAP_SEED_KEY="${bootstrap_seed_key}" \
      PRODIGY_REMOTE_BOOTSTRAP_REMOTE_SEED_KEY="${remote_seed_key_mount}/id_ed25519" \
      PRODIGY_REMOTE_BOOTSTRAP_REMOTE_ROOT="${remote_root}" \
      PRODIGY_REMOTE_BOOTSTRAP_STATE_DIR="${state_db_dir}" \
      PRODIGY_REMOTE_BOOTSTRAP_SYSTEMD_DIR="${systemd_dir}" \
      PRODIGY_REMOTE_BOOTSTRAP_SYSTEMCTL_LOG="${systemctl_log}" \
      "${SMOKE_BIN}"

echo "PASS: isolated fake-machine SSH bootstrap smoke completed"
