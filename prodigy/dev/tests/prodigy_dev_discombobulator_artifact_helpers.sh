#!/usr/bin/env bash

prodigy_dev_test_helpers_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRODIGY_DEV_TESTS_DIR="${PRODIGY_DEV_TESTS_DIR:-${prodigy_dev_test_helpers_dir}}"
PRODIGY_DEV_REPO_ROOT="${PRODIGY_DEV_REPO_ROOT:-$(cd "${PRODIGY_DEV_TESTS_DIR}/../../.." && pwd)}"
PRODIGY_DEV_DISCOMBOBULATOR_MANIFEST="${PRODIGY_DEV_DISCOMBOBULATOR_MANIFEST:-${PRODIGY_DEV_REPO_ROOT}/prodigy/discombobulator/Cargo.toml}"
PRODIGY_DEV_DISCOMBOBULATOR_BIN="${PRODIGY_DEV_DISCOMBOBULATOR_BIN:-${PRODIGY_DEV_REPO_ROOT}/prodigy/discombobulator/target/debug/discombobulator}"

prodigy_dev_detect_target_arch()
{
   local machine_arch=""

   machine_arch="$(uname -m)"
   case "${machine_arch}" in
      x86_64|amd64)
         echo "x86_64"
         ;;
      aarch64|arm64)
         echo "aarch64"
         ;;
      riscv64|riscv)
         echo "riscv64"
         ;;
      *)
         echo "FAIL: unsupported host architecture for discombobulator build: ${machine_arch}" >&2
         return 1
         ;;
   esac
}

prodigy_dev_ensure_discombobulator()
{
   if [[ ! -f "${PRODIGY_DEV_DISCOMBOBULATOR_MANIFEST}" ]]
   then
      echo "FAIL: discombobulator manifest not found: ${PRODIGY_DEV_DISCOMBOBULATOR_MANIFEST}" >&2
      return 1
   fi

   cargo build --quiet --manifest-path "${PRODIGY_DEV_DISCOMBOBULATOR_MANIFEST}" >&2

   if [[ ! -x "${PRODIGY_DEV_DISCOMBOBULATOR_BIN}" ]]
   then
      echo "FAIL: discombobulator binary is not executable: ${PRODIGY_DEV_DISCOMBOBULATOR_BIN}" >&2
      return 1
   fi

   echo "${PRODIGY_DEV_DISCOMBOBULATOR_BIN}"
}

prodigy_dev_containers_root_is_safely_overmountable()
{
   local containers_root="${1:-/containers}"
   local existing_name=""

   if [[ "${PRODIGY_DEV_PRIVATE_MOUNT_NS_READY:-0}" == "1" ]]
   then
      return 0
   fi

   if [[ ! -d "${containers_root}" ]]
   then
      return 0
   fi

   if [[ -z "$(ls -A "${containers_root}" 2>/dev/null)" ]]
   then
      return 0
   fi

   while IFS= read -r existing_path
   do
      existing_name="$(basename "${existing_path}")"
      case "${existing_name}" in
         .prodigy-dev-fs-*|store|storage)
            ;;
         *)
            return 1
            ;;
      esac
   done < <(find "${containers_root}" -mindepth 1 -maxdepth 1 -print 2>/dev/null)

   return 0
}

prodigy_dev_reexec_in_private_mount_namespace_once()
{
   local guard_name="$1"
   shift

   if [[ -z "${guard_name}" || "$#" -eq 0 ]]
   then
      echo "FAIL: private mount namespace reexec requires a guard name and command" >&2
      return 1
   fi

   if [[ "${!guard_name:-0}" == "1" ]]
   then
      mount --make-rprivate /
      if [[ "$(readlink /proc/self/ns/mnt 2>/dev/null || true)" == "$(readlink /proc/1/ns/mnt 2>/dev/null || true)" ]]
      then
         echo "FAIL: private mount namespace guard is set but mount namespace isolation is not proven" >&2
         exit 1
      fi
      return 0
   fi

   if ! command -v unshare >/dev/null 2>&1
   then
      echo "SKIP: missing required command: unshare"
      exit 77
   fi

   exec env "${guard_name}=1" PRODIGY_DEV_PRIVATE_MOUNT_NS_READY=1 unshare -m -- bash -lc '
      set -euo pipefail
      mount --make-rprivate /
      exec "$@"
   ' _ "$@"
}

prodigy_dev_write_common_prodigy_assets()
{
   local file="$1"
   local ebpf_context="${2:-ebpf}"

   cat >> "${file}" <<EOF
COPY {${ebpf_context}} ./container.egress.router.ebpf.o /root/prodigy/container.egress.router.ebpf.o
COPY {${ebpf_context}} ./container.ingress.router.ebpf.o /root/prodigy/container.ingress.router.ebpf.o
SURVIVE /root/prodigy
EOF
}

prodigy_dev_run_discombobulator_build()
{
   local project_dir="$1"
   local discombobulator_file="$2"
   local output_blob="$3"
   local build_log="${project_dir}/discombobulator-build.log"
   local discombobulator_bin=""
   shift 3

   discombobulator_bin="$(prodigy_dev_ensure_discombobulator)" || return 1

   local args=(build --file "${discombobulator_file}" --output "${output_blob}" --kind app)
   while [[ "$#" -gt 0 ]]
   do
      args+=(--context "$1")
      shift
   done

   if ! (
      cd "${project_dir}"
      "${discombobulator_bin}" "${args[@]}"
   ) >"${build_log}" 2>&1
   then
      sed -n '1,240p' "${build_log}" >&2 || true
      return 1
   fi
}
