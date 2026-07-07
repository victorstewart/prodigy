#!/usr/bin/env bash
set -euo pipefail

usage()
{
   cat <<'USAGE'
Usage: prodigy/dev/apple-container-kernel/verify.sh [kernel-config]

Verify that a kernel config has the Prodigy options required for the Apple
Containerization arm64 development profile. If no config is passed, the script
checks /proc/config.gz or /boot/config-$(uname -r).
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
   usage
   exit 0
fi

config_path="${1:-}"

if [[ -z "${config_path}" ]]; then
   if [[ -r /proc/config.gz ]]; then
      config_path=/proc/config.gz
   elif [[ -r "/boot/config-$(uname -r)" ]]; then
      config_path="/boot/config-$(uname -r)"
   else
      echo "error: pass a kernel config path, or run in a guest with /proc/config.gz or /boot/config-\$(uname -r)" >&2
      exit 1
   fi
fi

if [[ ! -r "${config_path}" ]]; then
   echo "error: kernel config is not readable: ${config_path}" >&2
   exit 1
fi

config_tmp="$(mktemp "${TMPDIR:-/tmp}/prodigy-kernel-verify.XXXXXX")"
trap 'rm -f "${config_tmp}"' EXIT

case "${config_path}" in
   *.gz)
      if ! command -v gzip >/dev/null 2>&1; then
         echo "error: gzip is required to read ${config_path}" >&2
         exit 1
      fi
      gzip -dc "${config_path}" > "${config_tmp}"
      ;;
   *)
      cp "${config_path}" "${config_tmp}"
      ;;
esac

missing=0

require_exact()
{
   if ! grep -qx "$1" "${config_tmp}"; then
      echo "missing: $1" >&2
      missing=1
   fi
}

require_lsm_landlock()
{
   if ! grep -Eq '^CONFIG_LSM=.*landlock' "${config_tmp}"; then
      echo "missing: CONFIG_LSM must include landlock" >&2
      missing=1
   fi
}

require_exact 'CONFIG_BPF_JIT=y'
require_exact 'CONFIG_NETKIT=y'
require_exact 'CONFIG_BTRFS_FS=y'
require_exact 'CONFIG_BTRFS_FS_POSIX_ACL=y'
require_exact '# CONFIG_BTRFS_FS_RUN_SANITY_TESTS is not set'
require_exact '# CONFIG_BTRFS_DEBUG is not set'
require_exact '# CONFIG_BTRFS_ASSERT is not set'
require_exact 'CONFIG_SECURITY=y'
require_exact 'CONFIG_SECURITY_LANDLOCK=y'
require_lsm_landlock
require_exact 'CONFIG_RAID6_PQ=y'
require_exact 'CONFIG_XOR_BLOCKS=y'
require_exact 'CONFIG_ZSTD_COMMON=y'
require_exact 'CONFIG_ZSTD_COMPRESS=y'
require_exact 'CONFIG_ZSTD_DECOMPRESS=y'

if [[ "${missing}" != "0" ]]; then
   echo "Prodigy Apple Containerization kernel config verification failed: ${config_path}" >&2
   exit 1
fi

echo "Prodigy Apple Containerization kernel config verification passed: ${config_path}"
