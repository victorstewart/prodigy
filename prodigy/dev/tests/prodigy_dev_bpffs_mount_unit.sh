#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

if [[ -z "${PRODIGY_BIN}" || ! -x "${PRODIGY_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy"
   exit 2
fi

if [[ "${EUID}" -ne 0 ]]
then
   echo "SKIP: requires root for isolated netns harness"
   exit 77
fi

deps=(mktemp ps stat timeout)
for cmd in "${deps[@]}"
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}"
      exit 77
   fi
done

tmpdir="$(mktemp -d "${REPO_ROOT}/.run/prodigy-dev-bpffs-mount-unit.XXXXXX")"
workspace_root="${tmpdir}/workspace"
manifest_path="${workspace_root}/test-cluster-manifest.json"
harness_pid=""

cleanup()
{
   set +e

   if [[ -n "${harness_pid}" ]] && kill -0 "${harness_pid}" >/dev/null 2>&1
   then
      kill -TERM "${harness_pid}" >/dev/null 2>&1 || true
      timeout 10s bash -lc "while kill -0 ${harness_pid} >/dev/null 2>&1; do sleep 0.1; done" >/dev/null 2>&1 || true
      kill -KILL "${harness_pid}" >/dev/null 2>&1 || true
   fi

   rm -rf "${tmpdir}"
}
trap cleanup EXIT

export PRODIGY_DEV_ALLOW_BPF_ATTACH=1
"${SCRIPT_DIR}/prodigy_dev_netns_harness.sh" \
   "${PRODIGY_BIN}" \
   --runner-mode=persistent \
   --workspace-root="${workspace_root}" \
   --manifest-path="${manifest_path}" \
   --machines=1 \
   --brains=1 \
   >/dev/null 2>&1 &
harness_pid="$!"
runner_pid="${harness_pid}"

brain_pid=""
timeout 30s bash -lc '
   while true
   do
      candidate="$(ps -eo pid=,ppid=,cmd= | awk -v parent="'"${runner_pid}"'" '\''$2 == parent && $0 ~ /--isolated/ { print $1; exit }'\'' )"
      if [[ -n "${candidate}" ]]
      then
         printf "%s" "${candidate}"
         exit 0
      fi
      sleep 0.1
   done
' >"${tmpdir}/brain.pid"
brain_pid="$(cat "${tmpdir}/brain.pid")"

fstype="$(nsenter -t "${brain_pid}" -m -- stat -f -c '%T' /sys/fs/bpf)"
if [[ "${fstype}" != "bpf_fs" ]]
then
   echo "FAIL: expected /sys/fs/bpf to be bpffs inside brain mount namespace, saw ${fstype}"
   exit 1
fi

echo "PASS: prodigy dev harness mounts bpffs inside brain mount namespaces"
