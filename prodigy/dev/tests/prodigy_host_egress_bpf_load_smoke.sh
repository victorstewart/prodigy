#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]
then
   echo "usage: $0 <host.egress.router.ebpf.o>" >&2
   exit 1
fi

obj_path="$1"
if [[ ! -f "${obj_path}" ]]
then
   echo "missing BPF object: ${obj_path}" >&2
   exit 1
fi

if ! command -v bpftool >/dev/null 2>&1
then
   echo "missing bpftool" >&2
   exit 1
fi

ns_name="prodigy-host-egress-smoke-$$"
pin_dir="$(mktemp -d /root/prodigy/.run/host-egress-bpf-load.XXXXXX)"

cleanup()
{
   ip netns del "${ns_name}" >/dev/null 2>&1 || true
   rm -rf "${pin_dir}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ip netns add "${ns_name}"
ip -n "${ns_name}" link set lo up
ip netns exec "${ns_name}" bpftool prog loadall "${obj_path}" "${pin_dir}" >/dev/null
