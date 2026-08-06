#!/usr/bin/env bash
set -euo pipefail

unit="${1:-}"

if [[ -z "${unit}" || ! -x "${unit}" ]]
then
   echo "usage: $0 /path/to/prodigy_switchboard_whitehole_unit" >&2
   exit 2
fi

if [[ "${EUID}" -ne 0 ]]
then
   echo "SKIP: switchboard whitehole unit isolation requires root"
   exit 77
fi

if [[ "${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}" != 1 ]]
then
   echo "SKIP: switchboard whitehole unit loads BPF programs; set PRODIGY_DEV_ALLOW_BPF_ATTACH=1 only inside an authorized isolated Linux guest"
   exit 77
fi

for command in find findmnt mount pgrep readlink umount unshare
do
   if ! command -v "${command}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${command}"
      exit 77
   fi
done

if pgrep -x 'mothership|prodigy|prodigy-dns-res' >/dev/null 2>&1
then
   echo "FAIL: switchboard whitehole unit requires exclusive guest ownership; stop Mothership and the VDC first" >&2
   exit 1
fi

if [[ "${PRODIGY_SWITCHBOARD_WHITEHOLE_UNIT_ISOLATED:-0}" != 1 ]]
then
   exec env \
      PRODIGY_SWITCHBOARD_WHITEHOLE_UNIT_ISOLATED=1 \
      PRODIGY_SWITCHBOARD_WHITEHOLE_UNIT_PARENT_NETNS="$(readlink /proc/self/ns/net)" \
      PRODIGY_SWITCHBOARD_WHITEHOLE_UNIT_PARENT_MNTNS="$(readlink /proc/self/ns/mnt)" \
      PRODIGY_SWITCHBOARD_WHITEHOLE_UNIT_PARENT_BPFFS="$(findmnt -n -o MAJ:MIN --target /sys/fs/bpf)" \
      unshare --mount --net --propagation private -- bash "$0" "${unit}"
fi

if [[ "$(readlink /proc/self/ns/net)" == "${PRODIGY_SWITCHBOARD_WHITEHOLE_UNIT_PARENT_NETNS:-}" ||
      "$(readlink /proc/self/ns/mnt)" == "${PRODIGY_SWITCHBOARD_WHITEHOLE_UNIT_PARENT_MNTNS:-}" ]]
then
   echo "FAIL: switchboard whitehole unit namespace isolation was not established" >&2
   exit 1
fi

mount -t bpf bpf /sys/fs/bpf
cleanup()
{
   umount /sys/fs/bpf >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "$(findmnt -n -o MAJ:MIN --target /sys/fs/bpf)" == "${PRODIGY_SWITCHBOARD_WHITEHOLE_UNIT_PARENT_BPFFS:-}" ]]
then
   echo "FAIL: switchboard whitehole unit did not receive a private bpffs" >&2
   exit 1
fi

if [[ -n "$(find /sys/fs/bpf -mindepth 1 -maxdepth 1 -print -quit)" ]]
then
   echo "FAIL: switchboard whitehole unit private bpffs is not empty" >&2
   exit 1
fi

"${unit}"
