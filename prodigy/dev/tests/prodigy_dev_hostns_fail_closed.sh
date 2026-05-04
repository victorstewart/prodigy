#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"

if [[ -z "${PRODIGY_BIN}" || ! -x "${PRODIGY_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy"
   exit 2
fi

deps=(stat timeout mktemp strace rg)
for cmd in "${deps[@]}"
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}"
      exit 77
   fi
done

self_netns_ino="$(stat -Lc '%i' /proc/self/ns/net)"
pid1_netns_ino="$(stat -Lc '%i' /proc/1/ns/net)"
tmpdir="$(mktemp -d)"
stderr_log="${tmpdir}/stderr.log"
stdout_log="${tmpdir}/stdout.log"
state_db="${tmpdir}/state.tidesdb"
trap 'rm -rf "${tmpdir}"' EXIT
boot_json='{"bootstrapPeers":[{"isBrain":true,"addresses":[{"address":"127.0.0.1","cidr":0}]}],"nodeRole":"brain","controlSocketPath":"/run/prodigy/control.sock"}'

# Force the host-match guard path by explicitly setting PRODIGY_HOST_NETNS_INO to self.
run_prefix=(
   env
   "PRODIGY_HOST_NETNS_INO=${self_netns_ino}"
   "PRODIGY_DEV_MODE=1"
   "PRODIGY_BOOTSTRAP_BRAIN_COUNT=1"
   "PRODIGY_STATE_DB=${state_db}"
)

set +e
timeout --preserve-status -k 1s 8s \
   "${run_prefix[@]}" \
   strace -f -e bpf -qq \
   "${PRODIGY_BIN}" --isolated --netdev=lo "--boot-json=${boot_json}" \
   >"${stdout_log}" 2>"${stderr_log}"
status="$?"
set -e

if [[ "${status}" -eq 0 ]]
then
   echo "FAIL: prodigy succeeded in host/current netns safety test"
   sed -n '1,120p' "${stderr_log}"
   exit 1
fi

if [[ "${status}" -eq 124 ]]
then
   echo "FAIL: prodigy did not fail closed quickly (timed out)"
   sed -n '1,120p' "${stderr_log}"
   exit 1
fi

if rg -q "bpf\\(" "${stderr_log}"
then
   echo "FAIL: observed bpf() syscall before fail-closed exit"
   sed -n '1,120p' "${stderr_log}"
   exit 1
fi

if ! rg -q "refusing dev run:" "${stderr_log}"
then
   echo "FAIL: expected fail-closed refusal message was not emitted"
   sed -n '1,120p' "${stderr_log}"
   exit 1
fi

echo "PASS: fail-closed abort in host/current netns without bpf()"
