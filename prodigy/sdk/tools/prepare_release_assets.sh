#!/usr/bin/env bash
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SDK_DIR}/../.." && pwd)"
VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], "r", encoding="utf-8"))["sdkVersion"])' "${SDK_DIR}/versioning.json")"
RELEASE_TAG="v${VERSION}"
ASSET_BASE_URL="https://github.com/victorstewart/prodigy/releases/download/${RELEASE_TAG}"
OUTPUT_DIR="${REPO_ROOT}/.run/sdk-release-assets/${VERSION}"
BUILD_DIR="${OUTPUT_DIR}/build"
INSTALL_DIR="${OUTPUT_DIR}/install"
STAGING_DIR="${OUTPUT_DIR}/staging"

while [[ $# -gt 0 ]]
do
   case "$1" in
      --release-tag)
         RELEASE_TAG="$2"
         ASSET_BASE_URL="https://github.com/victorstewart/prodigy/releases/download/${RELEASE_TAG}"
         shift 2
         ;;
      --asset-base-url)
         ASSET_BASE_URL="$2"
         shift 2
         ;;
      --output-dir)
         OUTPUT_DIR="$2"
         BUILD_DIR="${OUTPUT_DIR}/build"
         INSTALL_DIR="${OUTPUT_DIR}/install"
         STAGING_DIR="${OUTPUT_DIR}/staging"
         shift 2
         ;;
      *)
         printf 'unknown argument: %s\n' "$1" >&2
         exit 1
         ;;
   esac
done

copy_file()
{
   local source_path="$1"
   local destination_path="$2"

   install -Dm644 "${source_path}" "${destination_path}"
}

copy_tree()
{
   local source_path="$1"
   local destination_path="$2"

   mkdir -p "$(dirname "${destination_path}")"
   cp -a "${source_path}" "${destination_path}"
}

reset_stage_dir()
{
   local destination_dir="$1"

   rm -rf "${destination_dir}"
   mkdir -p "${destination_dir}"
}

write_depofile()
{
   local output_path="$1"
   local package_name="$2"
   local package_version="$3"
   local source_url="$4"
   local source_sha256="$5"
   local dep_lines="$6"
   local target_lines="$7"
   local link_lines="$8"

   cat > "${output_path}" <<EOF
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0
NAME ${package_name}
VERSION ${package_version}
${dep_lines}
SOURCE URL ${source_url}
SHA256 ${source_sha256}
${target_lines}
${link_lines}
EOF
}

make_tarball()
{
   local stage_parent="$1"
   local stage_name="$2"
   local tarball_path="$3"

   tar \
      --sort=name \
      --mtime='UTC 1970-01-01' \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      -C "${stage_parent}" \
      -czf "${tarball_path}" \
      "${stage_name}"
}

mkdir -p "${OUTPUT_DIR}"
rm -rf "${BUILD_DIR}" "${INSTALL_DIR}" "${STAGING_DIR}"

cmake \
   -S "${SDK_DIR}" \
   -B "${BUILD_DIR}" \
   -G Ninja \
   -DPRODIGY_SDK_ENABLE_TESTS=ON \
   -DCMAKE_C_COMPILER=clang \
   -DCMAKE_CXX_COMPILER=clang++ \
   -DCMAKE_CXX_STANDARD=26
cmake --build "${BUILD_DIR}" -j"$(nproc)"
ctest --test-dir "${BUILD_DIR}" -R '^prodigy_sdk_' --output-on-failure
cmake --install "${BUILD_DIR}" --prefix "${INSTALL_DIR}"

C_STAGE_NAME="prodigy-sdk-c-${VERSION}"
CPP_STAGE_NAME="prodigy-sdk-cpp-${VERSION}"
C_STAGE_DIR="${STAGING_DIR}/${C_STAGE_NAME}"
CPP_STAGE_DIR="${STAGING_DIR}/${CPP_STAGE_NAME}"

reset_stage_dir "${C_STAGE_DIR}"
reset_stage_dir "${CPP_STAGE_DIR}"

copy_file "${SDK_DIR}/LICENSE" "${C_STAGE_DIR}/LICENSE"
copy_file "${SDK_DIR}/LICENSE" "${CPP_STAGE_DIR}/LICENSE"
copy_file "${SDK_DIR}/c/README.md" "${C_STAGE_DIR}/README.md"
copy_file "${SDK_DIR}/cpp/README.md" "${CPP_STAGE_DIR}/README.md"

for doc_name in AEGIS.md INTERFACES.md WIRE.md VERSIONING.md versioning.json
do
   copy_file "${SDK_DIR}/${doc_name}" "${C_STAGE_DIR}/docs/${doc_name}"
   copy_file "${SDK_DIR}/${doc_name}" "${CPP_STAGE_DIR}/docs/${doc_name}"
done

copy_file "${SDK_DIR}/c/README.md" "${C_STAGE_DIR}/docs/c/README.md"
copy_file "${SDK_DIR}/cpp/README.md" "${CPP_STAGE_DIR}/docs/cpp/README.md"
copy_tree "${SDK_DIR}/fixtures" "${C_STAGE_DIR}/fixtures"
copy_tree "${SDK_DIR}/fixtures" "${CPP_STAGE_DIR}/fixtures"

copy_file "${SDK_DIR}/c/examples/README.md" "${C_STAGE_DIR}/examples/README.md"
copy_file "${SDK_DIR}/c/examples/aegis_roundtrip.c" "${C_STAGE_DIR}/examples/aegis_roundtrip.c"
copy_file "${SDK_DIR}/c/examples/mesh_pingpong.c" "${C_STAGE_DIR}/examples/mesh_pingpong.c"
copy_file "${SDK_DIR}/c/examples/mesh_pingpong.advertiser.deployment.plan.v1.json" "${C_STAGE_DIR}/examples/mesh_pingpong.advertiser.deployment.plan.v1.json"
copy_file "${SDK_DIR}/c/examples/mesh_pingpong.subscriber.deployment.plan.v1.json" "${C_STAGE_DIR}/examples/mesh_pingpong.subscriber.deployment.plan.v1.json"

copy_file "${SDK_DIR}/cpp/examples/aegis_roundtrip.cpp" "${CPP_STAGE_DIR}/examples/aegis_roundtrip.cpp"
copy_file "${SDK_DIR}/cpp/examples/opinionated_aegis_roundtrip.cpp" "${CPP_STAGE_DIR}/examples/opinionated_aegis_roundtrip.cpp"
copy_file "${SDK_DIR}/cpp/examples/io_uring_mesh_pingpong.cpp" "${CPP_STAGE_DIR}/examples/io_uring_mesh_pingpong.cpp"
copy_file "${SDK_DIR}/cpp/examples/io_uring_mesh_pingpong.advertiser.deployment.plan.v1.json" "${CPP_STAGE_DIR}/examples/io_uring_mesh_pingpong.advertiser.deployment.plan.v1.json"
copy_file "${SDK_DIR}/cpp/examples/io_uring_mesh_pingpong.subscriber.deployment.plan.v1.json" "${CPP_STAGE_DIR}/examples/io_uring_mesh_pingpong.subscriber.deployment.plan.v1.json"

copy_tree "${INSTALL_DIR}/include/prodigy/c" "${C_STAGE_DIR}/include/prodigy/c"
copy_file "${INSTALL_DIR}/lib/libprodigy-sdk-c.a" "${C_STAGE_DIR}/lib/libprodigy-sdk-c.a"
copy_tree "${INSTALL_DIR}/lib/cmake/ProdigySDKC" "${C_STAGE_DIR}/lib/cmake/ProdigySDKC"
copy_file "${INSTALL_DIR}/share/prodigy-sdk/cmake/ProdigySDKDepos.cmake" "${C_STAGE_DIR}/share/prodigy-sdk/cmake/ProdigySDKDepos.cmake"

copy_file "${INSTALL_DIR}/include/prodigy/neuron_hub.h" "${CPP_STAGE_DIR}/include/prodigy/neuron_hub.h"
copy_file "${INSTALL_DIR}/include/prodigy/aegis_session.h" "${CPP_STAGE_DIR}/include/prodigy/aegis_session.h"
copy_tree "${INSTALL_DIR}/include/prodigy/opinionated" "${CPP_STAGE_DIR}/include/prodigy/opinionated"
copy_tree "${INSTALL_DIR}/lib/cmake/ProdigySDK" "${CPP_STAGE_DIR}/lib/cmake/ProdigySDK"
copy_file "${INSTALL_DIR}/share/prodigy-sdk/cmake/ProdigySDKDepos.cmake" "${CPP_STAGE_DIR}/share/prodigy-sdk/cmake/ProdigySDKDepos.cmake"

for depofile_name in aegis.DepoFile gxhash.DepoFile
do
   copy_file "${INSTALL_DIR}/share/prodigy-sdk/depofiles/${depofile_name}" "${C_STAGE_DIR}/depofiles/${depofile_name}"
   copy_file "${INSTALL_DIR}/share/prodigy-sdk/depofiles/${depofile_name}" "${C_STAGE_DIR}/share/prodigy-sdk/depofiles/${depofile_name}"
   copy_file "${INSTALL_DIR}/share/prodigy-sdk/depofiles/${depofile_name}" "${CPP_STAGE_DIR}/depofiles/${depofile_name}"
   copy_file "${INSTALL_DIR}/share/prodigy-sdk/depofiles/${depofile_name}" "${CPP_STAGE_DIR}/share/prodigy-sdk/depofiles/${depofile_name}"
done

copy_file "${INSTALL_DIR}/share/prodigy-sdk/depofiles/basics.DepoFile" "${CPP_STAGE_DIR}/depofiles/basics.DepoFile"
copy_file "${INSTALL_DIR}/share/prodigy-sdk/depofiles/basics.DepoFile" "${CPP_STAGE_DIR}/share/prodigy-sdk/depofiles/basics.DepoFile"

C_TARBALL="${OUTPUT_DIR}/${C_STAGE_NAME}.tar.gz"
CPP_TARBALL="${OUTPUT_DIR}/${CPP_STAGE_NAME}.tar.gz"
make_tarball "${STAGING_DIR}" "${C_STAGE_NAME}" "${C_TARBALL}"
make_tarball "${STAGING_DIR}" "${CPP_STAGE_NAME}" "${CPP_TARBALL}"

C_SHA256="$(sha256sum "${C_TARBALL}" | awk '{print $1}')"
CPP_SHA256="$(sha256sum "${CPP_TARBALL}" | awk '{print $1}')"
BASICS_VERSION="$(awk '/^VERSION / { print $2; exit }' "${INSTALL_DIR}/share/prodigy-sdk/depofiles/basics.DepoFile")"

write_depofile \
   "${OUTPUT_DIR}/prodigy-sdk-c.DepoFile" \
   "prodigy_sdk_c" \
   "${VERSION}" \
   "${ASSET_BASE_URL}/${C_STAGE_NAME}.tar.gz" \
   "${C_SHA256}" \
   $'DEPENDS aegis VERSION 0.3.0\nDEPENDS gxhash VERSION 3.4.1' \
   'TARGET Prodigy::SdkC STATIC lib/libprodigy-sdk-c.a INTERFACE include' \
   'LINK Prodigy::SdkC aegis::aegis gxhash::gxhash'

write_depofile \
   "${OUTPUT_DIR}/prodigy-sdk-cpp.DepoFile" \
   "prodigy_sdk_cpp" \
   "${VERSION}" \
   "${ASSET_BASE_URL}/${CPP_STAGE_NAME}.tar.gz" \
   "${CPP_SHA256}" \
   $'DEPENDS aegis VERSION 0.3.0\nDEPENDS gxhash VERSION 3.4.1\nDEPENDS basics VERSION '"${BASICS_VERSION}" \
   $'TARGET Prodigy::SdkCpp INTERFACE include\nTARGET Prodigy::SdkCppOpinionated INTERFACE include' \
   $'LINK Prodigy::SdkCpp aegis::aegis gxhash::gxhash\nLINK Prodigy::SdkCppOpinionated Prodigy::SdkCpp basics::basics'

printf 'Wrote release assets under %s\n' "${OUTPUT_DIR}"
printf '  %s\n' "${C_TARBALL}"
printf '  %s\n' "${CPP_TARBALL}"
printf '  %s\n' "${OUTPUT_DIR}/prodigy-sdk-c.DepoFile"
printf '  %s\n' "${OUTPUT_DIR}/prodigy-sdk-cpp.DepoFile"
