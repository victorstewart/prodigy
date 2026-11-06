#!/usr/bin/env bash
set -euo pipefail

# Produce the one source-dependency package consumed by Nametag.  This is a
# local release-candidate producer; publication is deliberately outside it.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${1:-${repo_root}/.run/source-dependency-release}"
mkdir -p "$(dirname "${output_root}")"
output_root="$(cd "$(dirname "${output_root}")" && pwd)/$(basename "${output_root}")"
version="${PRODIGY_SOURCE_DEPENDENCY_VERSION:-0.4.5-rc.3}"
basics_package="basics"
basics_version="0.4.14-rc.6"
basics_archive="${PRODIGY_SOURCE_DEPENDENCY_BASICS_ARCHIVE:-}"
basics_archive_sha256="${PRODIGY_SOURCE_DEPENDENCY_BASICS_ARCHIVE_SHA256:-}"
basics_release_url="${PRODIGY_SOURCE_DEPENDENCY_BASICS_RELEASE_URL:-}"
rust_toolchain_version="1.97.1"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "package-source-dependency: run in the verified Linux guest." >&2
  exit 1
fi
for command in awk basename cat find gzip paste readelf sha256sum sort stat tar xargs; do
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
receipt="${output_root}/RELEASE-RECEIPT.txt"
source_manifest="${output_root}/SOURCE-MANIFEST.sha256"
checksums="${output_root}/SHA256SUMS"
if [[ -e "${candidate_root}" || -e "${archive}" || -e "${depofile}" ||
      -e "${receipt}" || -e "${source_manifest}" || -e "${checksums}" ]]; then
  echo "package-source-dependency: candidate output already exists; choose a new output root." >&2
  exit 1
fi
mkdir -p "${output_root}"

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
noise_archive="${stage}/noise-target/release/libprodigy_noise.a"
noise_archive_sha256="$(sha256sum "${noise_archive}" | awk '{print $1}')"
noise_archive_bytes="$(stat -c %s "${noise_archive}")"
noise_elf_class="$(readelf -h "${noise_archive}" | awk -F: '/Class:/{gsub(/^[[:space:]]+/, "", $2); print $2}' | sort -u | paste -sd, -)"
noise_elf_machine="$(readelf -h "${noise_archive}" | awk -F: '/Machine:/{gsub(/^[[:space:]]+/, "", $2); print $2}' | sort -u | paste -sd, -)"
if [[ -z "${noise_elf_class}" || -z "${noise_elf_machine}" ]]; then
  echo "package-source-dependency: unable to inspect the preflight Noise archive's ELF members." >&2
  exit 1
fi

(cd "${source_root}" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "${source_manifest}"
source_manifest_sha256="$(sha256sum "${source_manifest}" | awk '{print $1}')"

# The mounted detached worktree may have a host-only gitdir.  Keep the
# candidate reproducible without requiring Git metadata inside the guest.
source_date_epoch="${SOURCE_DATE_EPOCH:-0}"
[[ "${source_date_epoch}" =~ ^[0-9]+$ ]] || {
  echo "package-source-dependency: SOURCE_DATE_EPOCH must be an unsigned integer." >&2
  exit 1
}
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
cp -a "${source_root}" "${candidate_root}"
depofile_sha256="$(sha256sum "${depofile}" | awk '{print $1}')"
cargo_version="$("${cargo_bin}" --version)"
rustc_version="$("${rustc_bin}" --version)"
rustc_verbose="$("${rustc_bin}" -vV)"
rustc_host="$(printf '%s\n' "${rustc_verbose}" | awk -F': ' '$1 == "host" {print $2}')"
rustc_commit="$(printf '%s\n' "${rustc_verbose}" | awk -F': ' '$1 == "commit-hash" {print $2}')"
rustc_llvm="$(printf '%s\n' "${rustc_verbose}" | awk -F': ' '$1 == "LLVM version" {print $2}')"
cat > "${receipt}" <<EOF
FORMAT=prodigy-source-dependency-release-v1
PRODIGY_VERSION=${version}
SOURCE_DATE_EPOCH=${source_date_epoch}
PRODIGY_ARCHIVE=${asset_name}
PRODIGY_ARCHIVE_SHA256=${archive_sha256}
PRODIGY_DEPOFILE=prodigy.DepoFile
PRODIGY_DEPOFILE_SHA256=${depofile_sha256}
SOURCE_MANIFEST=SOURCE-MANIFEST.sha256
SOURCE_MANIFEST_SHA256=${source_manifest_sha256}
NOISE_CARGO_LOCK_SHA256=$(sha256sum "${noise_stage}/Cargo.lock" | awk '{print $1}')
NOISE_PREFLIGHT_ARCHIVE_SHA256=${noise_archive_sha256}
NOISE_PREFLIGHT_ARCHIVE_BYTES=${noise_archive_bytes}
NOISE_PREFLIGHT_ELF_CLASS=${noise_elf_class}
NOISE_PREFLIGHT_ELF_MACHINE=${noise_elf_machine}
BASICS_VERSION=${basics_version}
BASICS_ARCHIVE_NAME=$(basename "${basics_archive}")
BASICS_ARCHIVE_SHA256=${basics_archive_sha256}
BASICS_RELEASE_URL=${basics_release_url}
RUST_TOOLCHAIN_VERSION=${rust_toolchain_version}
CARGO_VERSION=${cargo_version}
CARGO_EXECUTABLE_SHA256=$(sha256sum "${cargo_bin}" | awk '{print $1}')
RUSTC_VERSION=${rustc_version}
RUSTC_HOST=${rustc_host}
RUSTC_COMMIT_HASH=${rustc_commit}
RUSTC_LLVM_VERSION=${rustc_llvm}
RUSTC_EXECUTABLE_SHA256=$(sha256sum "${rustc_bin}" | awk '{print $1}')
EOF
(cd "${output_root}" && sha256sum \
  "${asset_name}" prodigy.DepoFile RELEASE-RECEIPT.txt SOURCE-MANIFEST.sha256 > SHA256SUMS)
printf 'source dependency candidate: %s\nPublishable DepoFile: %s\nRelease receipt: %s\n' \
  "${archive}" "${depofile}" "${receipt}"
