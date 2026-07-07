#!/usr/bin/env bash
set -euo pipefail

usage()
{
   cat <<'USAGE'
Usage: prodigy/dev/apple-container-kernel/build.sh

Clone Apple's Containerization repository, check out the pinned kernel profile
ref, apply Prodigy's arm64 kernel config fragment, and build vmlinux-arm64.

Environment:
  PRODIGY_APPLE_CONTAINER_KERNEL_WORK_ROOT    Work root, defaults to .run/apple-container-kernel
  PRODIGY_APPLE_CONTAINERIZATION_REPO         Git remote, defaults to Apple's Containerization repo
  PRODIGY_APPLE_CONTAINER_KERNEL_TARGET_ARCH  Target architecture, only arm64 is supported
  PRODIGY_APPLE_CONTAINER_KERNEL_SKIP_BUILD=1 Patch config but skip make
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
   usage
   exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
work_root="${PRODIGY_APPLE_CONTAINER_KERNEL_WORK_ROOT:-${repo_root}/.run/apple-container-kernel}"
upstream="${PRODIGY_APPLE_CONTAINERIZATION_REPO:-https://github.com/apple/containerization.git}"
target_arch="${PRODIGY_APPLE_CONTAINER_KERNEL_TARGET_ARCH:-arm64}"
skip_build="${PRODIGY_APPLE_CONTAINER_KERNEL_SKIP_BUILD:-0}"
ref="$(tr -d '[:space:]' < "${script_dir}/apple-containerization.ref")"
checkout="${work_root}/containerization"
fragment="${script_dir}/prodigy-arm64.config.fragment"

require_cmd()
{
   if ! command -v "$1" >/dev/null 2>&1; then
      echo "error: required command not found: $1" >&2
      exit 1
   fi
}

if [[ "${target_arch}" != "arm64" ]]; then
   echo "error: this Prodigy Apple Containerization profile only supports arm64" >&2
   exit 1
fi

require_cmd git
require_cmd make

if [[ "${skip_build}" != "1" ]]; then
   require_cmd container
fi

mkdir -p "${work_root}"

if [[ ! -d "${checkout}/.git" ]]; then
   git clone "${upstream}" "${checkout}"
fi

git -C "${checkout}" fetch --tags origin
git -C "${checkout}" checkout --detach "${ref}"

config="${checkout}/kernel/config-${target_arch}"
if [[ ! -f "${config}" ]]; then
   echo "error: upstream kernel config not found: ${config}" >&2
   exit 1
fi

replace_config_line()
{
   local key="$1"
   local value="$2"
   local tmp

   tmp="$(mktemp "${TMPDIR:-/tmp}/prodigy-kernel-config.XXXXXX")"
   grep -Ev "^(# ${key} is not set|${key}=)" "${config}" > "${tmp}" || true
   printf '%s=%s\n' "${key}" "${value}" >> "${tmp}"
   mv "${tmp}" "${config}"
}

unset_config_line()
{
   local key="$1"
   local tmp

   tmp="$(mktemp "${TMPDIR:-/tmp}/prodigy-kernel-config.XXXXXX")"
   grep -Ev "^(# ${key} is not set|${key}=)" "${config}" > "${tmp}" || true
   printf '# %s is not set\n' "${key}" >> "${tmp}"
   mv "${tmp}" "${config}"
}

while IFS= read -r line || [[ -n "${line}" ]]; do
   [[ -z "${line}" ]] && continue

   if [[ "${line}" =~ ^(CONFIG_[A-Za-z0-9_]+)=(.*)$ ]]; then
      replace_config_line "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
   elif [[ "${line}" =~ ^#\ (CONFIG_[A-Za-z0-9_]+)\ is\ not\ set$ ]]; then
      unset_config_line "${BASH_REMATCH[1]}"
   else
      echo "error: unsupported config fragment line: ${line}" >&2
      exit 1
   fi
done < "${fragment}"

echo "applied ${fragment} to ${config}"

if [[ "${skip_build}" == "1" ]]; then
   echo "skipped kernel build because PRODIGY_APPLE_CONTAINER_KERNEL_SKIP_BUILD=1"
   exit 0
fi

make -C "${checkout}/kernel" TARGET_ARCH="${target_arch}"

output="${checkout}/bin/vmlinux-${target_arch}"
if [[ ! -f "${output}" ]]; then
   echo "error: expected kernel output was not produced: ${output}" >&2
   exit 1
fi

echo "built ${output}"
