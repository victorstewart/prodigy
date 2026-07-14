#!/usr/bin/env bash
set -euo pipefail

usage()
{
   cat <<'USAGE'
Usage: prodigy/dev/apple-container-kernel/build.sh

Build the pinned Linux kernel with Apple's Containerization toolchain and reuse
the result until one of its declared inputs changes.

Environment:
  PRODIGY_APPLE_CONTAINER_KERNEL_WORK_ROOT    Work root, defaults to .run/apple-container-kernel
  PRODIGY_APPLE_CONTAINERIZATION_REPO         Git remote, defaults to Apple's Containerization repo
  PRODIGY_APPLE_CONTAINER_KERNEL_TARGET_ARCH  Target architecture, only arm64 is supported
  PRODIGY_APPLE_CONTAINER_KERNEL_SKIP_BUILD=1 Patch config but skip the build
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
kernel_version="$(tr -d '[:space:]' < "${script_dir}/linux-kernel.version")"
kernel_sha256="$(tr -d '[:space:]' < "${script_dir}/linux-kernel.sha256")"
checkout="${work_root}/containerization"
fragment="${script_dir}/prodigy-arm64.config.fragment"
kernel_dir="${checkout}/kernel"
output="${checkout}/bin/vmlinux-${target_arch}"
stamp="${work_root}/inputs.sha256"
kernel_image=kernel-build:0.1

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
require_cmd shasum

if [[ "${skip_build}" != "1" ]]; then
   require_cmd container
fi

mkdir -p "${work_root}"

input_sha256="$({
   printf '%s\n' "${ref}" "${kernel_version}" "${kernel_sha256}" "${target_arch}"
   cat "${BASH_SOURCE[0]}" "${fragment}"
} | shasum -a 256 | awk '{print $1}')"

if [[ -s "${output}" && -s "${stamp}" ]]; then
   read -r cached_input_sha256 cached_output_sha256 < "${stamp}"
   if [[ "${cached_input_sha256}" == "${input_sha256}" ]] &&
      [[ "$(shasum -a 256 "${output}" | awk '{print $1}')" == "${cached_output_sha256}" ]]; then
      echo "reusing ${output}"
      exit 0
   fi
fi

if [[ ! -d "${checkout}/.git" ]]; then
   git clone "${upstream}" "${checkout}"
fi

if ! git -C "${checkout}" cat-file -e "${ref}^{commit}" 2>/dev/null; then
   git -C "${checkout}" fetch --tags origin
fi
git -C "${checkout}" checkout --detach "${ref}"
git -C "${checkout}" checkout "${ref}" -- "kernel/config-${target_arch}"

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

if ! container system status | grep -Eq '^status[[:space:]]+running$'; then
   echo "error: Apple Containers is not running" >&2
   exit 1
fi

source_tar="${kernel_dir}/source.tar.xz"
if [[ ! -s "${source_tar}" ]] ||
   [[ "$(shasum -a 256 "${source_tar}" | awk '{print $1}')" != "${kernel_sha256}" ]]; then
   require_cmd curl
   source_tmp="${source_tar}.tmp"
   curl --fail --location --proto '=https' --tlsv1.2 \
      --output "${source_tmp}" \
      "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-${kernel_version}.tar.xz"
   if [[ "$(shasum -a 256 "${source_tmp}" | awk '{print $1}')" != "${kernel_sha256}" ]]; then
      rm -f "${source_tmp}"
      echo "error: Linux ${kernel_version} source checksum mismatch" >&2
      exit 1
   fi
   mv "${source_tmp}" "${source_tar}"
fi

if ! container image inspect "${kernel_image}" >/dev/null 2>&1; then
   container build "${kernel_dir}/image" -f "${kernel_dir}/image/Dockerfile" -t "${kernel_image}"
fi

cpus="$(sysctl -n hw.ncpu)"
container run --cpus "${cpus}" --rm --memory 16g \
   --volume "${kernel_dir}:/kernel" \
   --env LOCALVERSION=-prodigy \
   --env TARGET_ARCH="${target_arch}" \
   --cwd /kernel \
   "${kernel_image}" \
   /bin/bash -c './build.sh'

mkdir -p "$(dirname "${output}")"
cp -L "${kernel_dir}/vmlinux-${target_arch}" "${output}"
if [[ ! -s "${output}" ]]; then
   echo "error: expected kernel output was not produced: ${output}" >&2
   exit 1
fi

output_sha256="$(shasum -a 256 "${output}" | awk '{print $1}')"
printf '%s %s\n' "${input_sha256}" "${output_sha256}" > "${stamp}.tmp"
mv "${stamp}.tmp" "${stamp}"
echo "built ${output} (${output_sha256})"
