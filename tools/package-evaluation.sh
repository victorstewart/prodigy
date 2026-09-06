#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-${repo_root}/.run/evaluation-build}"
output_root="${2:-${repo_root}/.run/evaluation}"
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "package-evaluation: run this from the verified Apple Containers Linux guest so the archive matches its Linux artifacts." >&2
  exit 1
fi
for command in tar sha256sum readelf python3 gzip git zstd; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "package-evaluation: missing required command '${command}'. Build and package inside the verified Linux guest; this script never installs dependencies." >&2
    exit 1
  fi
done
for file in "${build_dir}/prodigy" "${build_dir}/mothership" "${build_dir}/discombobulator-target/debug/discombobulator"; do
  if [[ ! -f "${file}" ]]; then
    echo "package-evaluation: required build output is missing: ${file}. Run tools/build-evaluation.sh ${build_dir} first." >&2
    exit 1
  fi
done
arch="$(readelf -h "${build_dir}/prodigy" | awk -F: '/Machine:/{gsub(/^[[:space:]]+/, "", $2); print $2}')"
case "${arch}" in
  *AArch64*) arch="aarch64";; *X86-64*) arch="x86_64";;
  *) echo "package-evaluation: cannot derive a supported architecture from ${build_dir}/prodigy: ${arch}" >&2; exit 1;;
esac
bundle="${build_dir}/prodigy.${arch}.bundle.tar.zst"
for file in "${bundle}" "${bundle}.sha256" "${build_dir}/evaluation-assets/hello-prodigy-v1.${arch}.container.zst" "${build_dir}/evaluation-assets/hello-prodigy-v2.${arch}.container.zst" "${build_dir}/evaluation-assets/hello-prodigy-v1.deployment.plan.v1.json" "${build_dir}/evaluation-assets/hello-prodigy-v2.deployment.plan.v1.json"; do
  if [[ ! -f "${file}" ]]; then echo "package-evaluation: required evaluation asset is missing: ${file}. Run tools/build-evaluation.sh ${build_dir} first." >&2; exit 1; fi
done
commit="$(git -C "${repo_root}" rev-parse HEAD)"
short_commit="${commit:0:12}"
source_date_epoch="$(git -C "${repo_root}" show -s --format=%ct HEAD)"
dirty_digest="$(cd "${repo_root}"; { git diff --binary HEAD; git ls-files --others --exclude-standard -z | while IFS= read -r -d '' path; do sha256sum "${path}"; done; } | sha256sum | awk '{print $1}')"
version="0.1.0-eval.${short_commit}"
if [[ -n "$(git -C "${repo_root}" status --porcelain)" ]]; then version+=".dirty.${dirty_digest:0:12}"; fi
destination="${output_root}/prodigy-evaluation-${version}-${arch}"
release_dir="${repo_root}/.run/releases"
archive="${release_dir}/prodigy-evaluation-${version}-${arch}.tar.gz"
if [[ -e "${destination}" || -e "${archive}" ]]; then
  echo "package-evaluation: output already exists: ${destination} or ${archive}. Choose another output root or remove the reviewed local output explicitly." >&2
  exit 1
fi
mkdir -p "${output_root}" "${release_dir}"
stage="$(mktemp -d "${output_root}/.package-evaluation.XXXXXX")"
trap 'rm -rf "${stage}"' EXIT
root="${stage}/prodigy-evaluation-${version}-${arch}"
mkdir -p "${root}/bin" "${root}/examples/hello-prodigy" "${root}/tools/evaluation" "${root}/assets"
# The flat bundle supplies the deployed binaries' dependency closure. Keep its
# lib/ and tools/ layout, then expose the evaluation entrypoints under bin/.
tar --zstd -xf "${bundle}" -C "${root}"
cp "${root}/prodigy" "${root}/bin/prodigy"
cp "${root}/tools/mothership" "${root}/bin/mothership"
cp "${build_dir}/discombobulator-target/debug/discombobulator" "${root}/bin/discombobulator"
cp "${bundle}" "${bundle}.sha256" "${root}/bin/"
cp -a "${root}/lib" "${root}/bin/lib"
rm -f "${root}/prodigy"
mkdir -p "${root}/prodigy/dev/tests"
cp -R "${repo_root}/examples/hello-prodigy/." "${root}/examples/hello-prodigy/"
cp "${build_dir}/evaluation-assets/hello-prodigy-v1.${arch}.container.zst" "${build_dir}/evaluation-assets/hello-prodigy-v2.${arch}.container.zst" "${build_dir}/evaluation-assets/hello-prodigy-v1.deployment.plan.v1.json" "${build_dir}/evaluation-assets/hello-prodigy-v2.deployment.plan.v1.json" "${root}/examples/hello-prodigy/"
cp "${repo_root}/try-prodigy" "${root}/"
cp "${repo_root}/prodigy/dev/tests/prodigy_dev_test_cluster.sh" "${root}/prodigy/dev/tests/"
cp "${repo_root}/tools/evaluation/verify.py" "${repo_root}/tools/evaluation/session.py" "${root}/tools/evaluation/"
cp "${repo_root}/README.md" "${repo_root}/LICENSE" "${repo_root}/CONTRIBUTING.md" "${repo_root}/SUPPORT.md" "${repo_root}/SECURITY.md" "${root}/"
cp "${repo_root}/assets/prodigy-logo.avif" "${root}/assets/"
mkdir -p "${root}/prodigy/docs"
cp -R "${repo_root}/prodigy/docs/." "${root}/prodigy/docs/"
python3 "${repo_root}/tools/evaluation/copy-docs.py" "${repo_root}" "${root}"
export EVALUATION_ROOT="${root}" EVALUATION_VERSION="${version}" EVALUATION_ARCH="${arch}" EVALUATION_COMMIT="${commit}" EVALUATION_DIRTY_DIGEST="${dirty_digest}"
python3 - <<'PY'
import hashlib, json, os, pathlib
root = pathlib.Path(os.environ['EVALUATION_ROOT'])
files = {}
for path in sorted(p for p in root.rglob('*') if p.is_file()):
    rel = path.relative_to(root).as_posix()
    files[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
(root / 'evaluation.json').write_text(json.dumps({'formatVersion': 1, 'version': os.environ['EVALUATION_VERSION'], 'architecture': os.environ['EVALUATION_ARCH'], 'sourceCommit': os.environ['EVALUATION_COMMIT'], 'sourceDirtyDigest': os.environ['EVALUATION_DIRTY_DIGEST'], 'files': files}, indent=2, sort_keys=True) + '\n')
PY
(cd "${root}" && find . -type f ! -name evaluation.json ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
python3 "${repo_root}/tools/evaluation/verify.py" "${root}"
mv "${root}" "${destination}"
tar --sort=name --mtime="@${source_date_epoch}" --owner=0 --group=0 --numeric-owner --pax-option=delete=atime,delete=ctime -C "${output_root}" -cf - "$(basename "${destination}")" | gzip -n > "${archive}"
(cd "${release_dir}" && sha256sum "$(basename "${archive}")" > "$(basename "${archive}").sha256")
echo "evaluation archive: ${archive}"
