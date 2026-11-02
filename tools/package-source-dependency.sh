#!/usr/bin/env bash
set -euo pipefail

# Produce the one source-dependency package consumed by Nametag.  This is a
# local release-candidate producer; publication is deliberately outside it.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${1:-${repo_root}/.run/source-dependency-release}"
mkdir -p "$(dirname "${output_root}")"
output_root="$(cd "$(dirname "${output_root}")" && pwd)/$(basename "${output_root}")"
version="${PRODIGY_SOURCE_DEPENDENCY_VERSION:-0.4.5-rc.1}"
basics_package="basics"
basics_version="0.4.14-rc.1"
basics_archive="${PRODIGY_SOURCE_DEPENDENCY_BASICS_ARCHIVE:-}"
basics_archive_sha256="${PRODIGY_SOURCE_DEPENDENCY_BASICS_ARCHIVE_SHA256:-}"
basics_release_url="${PRODIGY_SOURCE_DEPENDENCY_BASICS_RELEASE_URL:-}"
rust_toolchain_version="1.97.1"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "package-source-dependency: run in the verified Linux guest." >&2
  exit 1
fi
for command in gzip sha256sum tar; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "package-source-dependency: missing required command '${command}'." >&2
    exit 1
  }
done
cargo_bin="${PRODIGY_SOURCE_DEPENDENCY_CARGO:-$(command -v cargo || true)}"
rustc_bin="${PRODIGY_SOURCE_DEPENDENCY_RUSTC:-$(command -v rustc || true)}"
[[ -x "${cargo_bin}" && -x "${rustc_bin}" ]] || {
  echo "package-source-dependency: pinned Cargo and rustc executables are required." >&2
  exit 1
}
[[ "$("${cargo_bin}" --version)" == "cargo ${rust_toolchain_version} "* ]] || {
  echo "package-source-dependency: Cargo must be ${rust_toolchain_version}: ${cargo_bin}" >&2
  exit 1
}
[[ "$("${rustc_bin}" --version)" == "rustc ${rust_toolchain_version} "* ]] || {
  echo "package-source-dependency: rustc must be ${rust_toolchain_version}: ${rustc_bin}" >&2
  exit 1
}
[[ "${version}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
  echo "package-source-dependency: PRODIGY_SOURCE_DEPENDENCY_VERSION is invalid." >&2
  exit 1
}
[[ -n "${basics_archive}" && -f "${basics_archive}" ]] || {
  echo "package-source-dependency: PRODIGY_SOURCE_DEPENDENCY_BASICS_ARCHIVE must name the local Basics ${basics_version} release archive." >&2
  exit 1
}
[[ "${basics_archive_sha256}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "package-source-dependency: PRODIGY_SOURCE_DEPENDENCY_BASICS_ARCHIVE_SHA256 must be a lowercase SHA-256." >&2
  exit 1
}
[[ "$(sha256sum "${basics_archive}" | awk '{print $1}')" == "${basics_archive_sha256}" ]] || {
  echo "package-source-dependency: local Basics release archive checksum mismatch." >&2
  exit 1
}
[[ "${basics_release_url}" =~ ^https://github\.com/victorstewart/basics/releases/download/v${basics_version}/[^/]+$ ]] || {
  echo "package-source-dependency: PRODIGY_SOURCE_DEPENDENCY_BASICS_RELEASE_URL must be an immutable Basics ${basics_version} release asset URL." >&2
  exit 1
}
[[ "${basics_release_url##*/}" == "$(basename "${basics_archive}")" ]] || {
  echo "package-source-dependency: Basics release URL asset name must match the local archive." >&2
  exit 1
}

candidate_root="${output_root}/prodigy-${version}"
asset_name="prodigy-${version}.tar.gz"
archive="${output_root}/${asset_name}"
depofile="${output_root}/prodigy.DepoFile"
local_depofile="${output_root}/prodigy.local.DepoFile"
if [[ -e "${candidate_root}" || -e "${archive}" || -e "${depofile}" || -e "${local_depofile}" ]]; then
  echo "package-source-dependency: candidate output already exists; choose a new output root." >&2
  exit 1
fi

stage="$(mktemp -d "${output_root}.stage.XXXXXX")"
trap 'rm -rf "${stage}"' EXIT
source_root="${stage}/source-root"
mkdir -p "${source_root}"

for public_root in prodigy switchboard macros enums services; do
  while IFS= read -r -d '' source_file; do
    relative_path="${source_file#"${repo_root}/"}"
    destination="${source_root}/${relative_path}"
    mkdir -p "$(dirname "${destination}")"
    cp "${source_file}" "${destination}"
  done < <(find "${repo_root}/${public_root}" -type f \( -name '*.h' -o -name '*.hpp' -o -name '*.clang' \) -not -path '*/target/*' -print0)
done
cp "${repo_root}/pinger.h" "${source_root}/pinger.h"

noise_root="${repo_root}/prodigy/crypto/noise"
noise_stage="${source_root}/prodigy/crypto/noise"
mkdir -p "${noise_stage}"
cp "${noise_root}/Cargo.toml" "${noise_root}/Cargo.lock" "${noise_stage}/"
cp -R "${noise_root}/src" "${noise_root}/vendor" "${noise_stage}/"
if [[ -d "${noise_root}/.cargo" ]]; then
  cp -R "${noise_root}/.cargo" "${noise_stage}/"
fi
registry_stage="${noise_stage}/vendor/registry"
mkdir -p "${registry_stage}"
vendor_config="$(cd "${source_root}" && "${cargo_bin}" vendor --offline --locked --versioned-dirs --manifest-path prodigy/crypto/noise/Cargo.toml "${registry_stage}")"
mkdir -p "${source_root}/.cargo"
vendor_config="${vendor_config//${registry_stage}/prodigy/crypto/noise/vendor/registry}"
printf '%s\n' "${vendor_config}" > "${source_root}/.cargo/config.toml"
RUSTC="${rustc_bin}" "${cargo_bin}" build --offline --locked --release \
  --manifest-path "${source_root}/prodigy/crypto/noise/Cargo.toml" \
  --target-dir "${stage}/noise-target"
test -f "${stage}/noise-target/release/libprodigy_noise.a"

# The mounted detached worktree may have a host-only gitdir.  Keep the
# candidate reproducible without requiring Git metadata inside the guest.
source_date_epoch="${SOURCE_DATE_EPOCH:-0}"
[[ "${source_date_epoch}" =~ ^[0-9]+$ ]] || {
  echo "package-source-dependency: SOURCE_DATE_EPOCH must be an unsigned integer." >&2
  exit 1
}
mkdir -p "${output_root}"
tar --sort=name --mtime="@${source_date_epoch}" --owner=0 --group=0 --numeric-owner \
  -C "${stage}" -cf - source-root | gzip -n > "${archive}"
archive_members="${stage}/archive-members.txt"
tar -tzf "${archive}" > "${archive_members}"
if grep -q '^source-root/.run/' "${archive_members}"; then
  echo "package-source-dependency: archive contains task-local .run state." >&2
  exit 1
fi
if ! grep -q '^source-root/prodigy/crypto/noise/vendor/registry/' "${archive_members}"; then
  echo "package-source-dependency: archive is missing the locked Noise registry closure." >&2
  exit 1
fi
archive_sha256="$(sha256sum "${archive}" | awk '{print $1}')"

cat > "${depofile}" <<EOF
NAME prodigy
VERSION ${version}
DEPENDS ${basics_package} VERSION ${basics_version}
DEPENDS rust_toolchain VERSION ${rust_toolchain_version}
SOURCE URL https://github.com/victorstewart/prodigy/releases/download/v${version}/${asset_name}
SHA256 ${archive_sha256}
BUILD_SYSTEM CARGO
CARGO_BUILD_SH <<'CARGO_EOF'
export PATH="\${dep:rust_toolchain}/bin:\$PATH"
export RUSTC="\${dep:rust_toolchain}/bin/rustc"
cargo build --offline --locked --release --manifest-path prodigy/crypto/noise/Cargo.toml --target-dir "\${DEPO_BUILD_DIR}/noise-target"
CARGO_EOF
STAGE_FILE BUILD noise-target/release/libprodigy_noise.a lib/libprodigy_noise.a
STAGE_TREE SOURCE prodigy include/prodigy
STAGE_TREE SOURCE switchboard include/switchboard
STAGE_TREE SOURCE macros include/macros
STAGE_TREE SOURCE enums include/enums
STAGE_TREE SOURCE services include/services
STAGE_FILE SOURCE pinger.h include/pinger.h
TARGET prodigy::noise STATIC lib/libprodigy_noise.a
TARGET prodigy::prodigy INTERFACE include
LINK prodigy::prodigy prodigy::noise basics::basics dl
EOF
sed "s|https://github.com/victorstewart/prodigy/releases/download/v${version}/${asset_name}|file://${archive}|" \
  "${depofile}" > "${local_depofile}"

cp -a "${source_root}" "${candidate_root}"
sha256sum "${archive}" "${depofile}" "${local_depofile}" > "${output_root}/SHA256SUMS"
printf 'BASICS_VERSION=%s\nBASICS_ARCHIVE=%s\nBASICS_ARCHIVE_SHA256=%s\nBASICS_RELEASE_URL=%s\n' \
  "${basics_version}" "${basics_archive}" "${basics_archive_sha256}" "${basics_release_url}" \
  > "${output_root}/BASICS_RELEASE_INPUT"
printf 'source dependency candidate: %s\nPublishable DepoFile: %s\nLocal verification DepoFile: %s\n' \
  "${archive}" "${depofile}" "${local_depofile}"
