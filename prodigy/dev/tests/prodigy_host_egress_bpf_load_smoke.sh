#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]
then
   echo "usage: $0 <host.egress.router.ebpf.o>" >&2
   exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
obj_path="$1"
if [[ ! -f "${obj_path}" ]]
then
   echo "missing BPF object: ${obj_path}" >&2
   exit 1
fi

if [[ "${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}" != "1" ]]
then
   echo "SKIP: host egress BPF load smoke requires PRODIGY_DEV_ALLOW_BPF_ATTACH=1" >&2
   exit 77
fi

if [[ "${EUID}" -ne 0 ]]
then
   echo "SKIP: host egress BPF load smoke requires root" >&2
   exit 77
fi

for cmd in bpftool ip mktemp
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}" >&2
      exit 77
   fi
done

ns_name="prodigy-host-egress-smoke-$$"
mkdir -p "${REPO_ROOT}/.run"
pin_dir="$(mktemp -d "${REPO_ROOT}/.run/host-egress-bpf-load.XXXXXX")"

cleanup()
{
   ip netns del "${ns_name}" >/dev/null 2>&1 || true
   rm -rf "${pin_dir}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ip netns add "${ns_name}"
ip -n "${ns_name}" link set lo up
ip netns exec "${ns_name}" bpftool prog loadall "${obj_path}" "${pin_dir}" >/dev/null
