#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-${repo_root}/.run/evaluation-build}"
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "build-evaluation: run this from the verified Apple Containers Linux guest; do not build evaluation artifacts on macOS." >&2
  exit 1
fi
for command in cmake cargo clang clang++ nproc; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "build-evaluation: missing required command '${command}'. Run this from the already-entered verified Linux development guest; prodigy_dev_test_cluster.sh launches test sessions and does not open a contributor shell." >&2
    exit 1
  fi
done
if [[ ! -f "${repo_root}/prodigy/dev/CMakeLists.txt" ]]; then
  echo "build-evaluation: this must run from a complete Prodigy checkout." >&2
  exit 1
fi
boundary_launcher="${repo_root}/prodigy/dev/tests/prodigy_dev_test_cluster.sh"
if ! bash "${boundary_launcher}" --check-boundary; then
  echo "build-evaluation: no verified Linux guest boundary is active. Use the documented Apple Containers development guest, then rerun this command there." >&2
  exit 1
fi
if [[ ! -f "${repo_root}/.depos.cmake" ]]; then
  command -v curl >/dev/null && command -v sha256sum >/dev/null || {
    echo "build-evaluation: curl and sha256sum are required to fetch the pinned Depos CMake module." >&2; exit 1;
  }
  bootstrap="$(mktemp "${repo_root}/.depos-bootstrap.XXXXXX")"
  trap 'rm -f "${bootstrap}"' EXIT
  curl --fail --location --silent --show-error --connect-timeout 15 --max-time 120 \
    https://raw.githubusercontent.com/victorstewart/depos/v0.5.0/.depos.cmake --output "${bootstrap}"
  [[ "$(sha256sum "${bootstrap}" | awk '{print $1}')" == 8d8ae162d8efbee29ad70773f42751d44124129a22563978c9208fde2cef1d02 ]] || {
    echo "build-evaluation: Depos CMake module checksum mismatch." >&2; exit 1;
  }
  mv "${bootstrap}" "${repo_root}/.depos.cmake"
  trap - EXIT
fi
jobs="${PRODIGY_EVALUATION_JOBS:-$(nproc)}"
[[ "${jobs}" =~ ^[1-9][0-9]*$ ]] || { echo "build-evaluation: PRODIGY_EVALUATION_JOBS must be a positive integer." >&2; exit 1; }
(( jobs > 4 )) && jobs=4
mkdir -p "${build_dir}"
if [[ -f "${build_dir}/CMakeCache.txt" ]]; then
  cmake -S "${repo_root}/prodigy/dev" -B "${build_dir}"
else
  cmake -S "${repo_root}/prodigy/dev" -B "${build_dir}" -DPRODIGY_DEV_BASICS_SOURCE_MODE=RELEASE -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="$(command -v clang)" -DCMAKE_CXX_COMPILER="$(command -v clang++)"
fi
cmake --build "${build_dir}" --parallel "${jobs}" --target prodigy_bundle hello_prodigy_artifacts
echo "evaluation build ready: ${build_dir}"
