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

if [[ "${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}" != "1" ]]
then
   echo "SKIP: bpffs mount unit requires PRODIGY_DEV_ALLOW_BPF_ATTACH=1"
   exit 77
fi

deps=(cut grep mktemp nsenter seq stat timeout)
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
harness_log="${tmpdir}/harness.log"
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

"${SCRIPT_DIR}/prodigy_dev_netns_harness.sh" \
   "${PRODIGY_BIN}" \
   --runner-mode=persistent \
   --workspace-root="${workspace_root}" \
   --manifest-path="${manifest_path}" \
   --machines=1 \
   --brains=1 \
   >"${harness_log}" 2>&1 &
harness_pid="$!"

timeout 180s bash -lc '
   while [[ ! -s "'"${manifest_path}"'" ]] || ! grep -Fq "MOTHERSHIP_BOOTSTRAP success" "'"${harness_log}"'"
   do
      kill -0 "'"${harness_pid}"'" >/dev/null 2>&1 || exit 1
      sleep 0.1
   done
'
fstype=""
for _ in $(seq 1 300)
do
   brain_pid="$(grep -m1 -o '"pid":[0-9]*' "${manifest_path}" | cut -d: -f2)"
   if [[ "${brain_pid}" =~ ^[1-9][0-9]*$ ]] && kill -0 "${brain_pid}" >/dev/null 2>&1
   then
      fstype="$(nsenter -t "${brain_pid}" -m -- stat -f -c '%T' /sys/fs/bpf 2>/dev/null || true)"
      [[ "${fstype}" != "bpf_fs" ]] || break
   fi
   sleep 0.1
done
if [[ "${fstype}" != "bpf_fs" ]]
then
   echo "FAIL: expected /sys/fs/bpf to be bpffs inside brain mount namespace, saw ${fstype}"
   exit 1
fi

echo "PASS: prodigy dev harness mounts bpffs inside brain mount namespaces"
