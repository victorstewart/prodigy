#!/usr/bin/env bash
# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SDK_DIR}/../.." && pwd)"
BUILD_DIR="${1:-${ROOT_DIR}/.run/prodigy-sdk-compat-build}"
mkdir -p "${ROOT_DIR}/.run"
TMP_DIR="$(mktemp -d "${ROOT_DIR}/.run/prodigy-sdk-compat-tmp.XXXXXX")"
TYPESCRIPT_NODE_MODULES_CREATED=0
PYTHON_VENV_DIR="${TMP_DIR}/python-venv"
INSTALL_PREFIX="${TMP_DIR}/prodigy-sdk-install"

cleanup()
{
   if [[ "${TYPESCRIPT_NODE_MODULES_CREATED}" == 1 ]]
   then
      rm -rf "${SDK_DIR}/typescript/node_modules"
   fi

   rm -rf "${TMP_DIR}"
}

trap cleanup EXIT

find_go()
{
   if [[ -n "${GO_BIN:-}" && -x "${GO_BIN}" ]]
   then
      printf '%s\n' "${GO_BIN}"
      return 0
   fi

   if command -v go >/dev/null 2>&1
   then
      command -v go
      return 0
   fi

   if [[ -x "${HOME}/.local/toolchains/go1.26.1/bin/go" ]]
   then
      printf '%s\n' "${HOME}/.local/toolchains/go1.26.1/bin/go"
      return 0
   fi

   return 1
}

require_tool()
{
   local tool_name="$1"

   if ! command -v "${tool_name}" >/dev/null 2>&1
   then
      printf 'FAIL: required tool not found: %s\n' "${tool_name}" >&2
      exit 1
   fi
}

run_check()
{
   local label="$1"
   shift

   printf 'RUN  %-18s %s\n' "${label}" "$*"
   "$@"
   printf 'PASS %-18s\n' "${label}"
}

run_check_in_dir()
{
   local label="$1"
   local dir="$2"
   shift 2

   printf 'RUN  %-18s (cd %s && %s)\n' "${label}" "${dir}" "$*"
   (
      cd "${dir}"
      "$@"
   )
   printf 'PASS %-18s\n' "${label}"
}

require_tool cmake
require_tool clang
require_tool clang++
require_tool npm
require_tool node
require_tool python3
require_tool rustc

GO_BIN="$(find_go || true)"
if [[ -z "${GO_BIN}" ]]
then
   printf 'FAIL: required tool not found: go\n' >&2
   exit 1
fi

mkdir -p "$(dirname "${BUILD_DIR}")"

run_check configure-sdk \
   cmake \
   -S "${SDK_DIR}" \
   -B "${BUILD_DIR}" \
   -G Ninja \
   -DPRODIGY_SDK_ENABLE_TESTS=ON \
   -DCMAKE_C_COMPILER=clang \
   -DCMAKE_CXX_COMPILER=clang++ \
   -DCMAKE_CXX_STANDARD=26

run_check build-sdk \
   cmake \
   --build "${BUILD_DIR}" \
   -j"$(nproc)"

run_check test-sdk \
   ctest \
   --test-dir "${BUILD_DIR}" \
   -R '^prodigy_sdk_' \
   --output-on-failure

run_check install-sdk \
   cmake \
   --install "${BUILD_DIR}" \
   --prefix "${INSTALL_PREFIX}"

run_check install-boundary \
   bash \
   -lc \
   "boundary_dir='${TMP_DIR}/install-boundary' && mkdir -p \"\${boundary_dir}\" && printf '%s\n' 'cmake_minimum_required(VERSION 3.18)' 'project(ProdigySDKInstallBoundary LANGUAGES CXX)' 'find_package(ProdigySDK REQUIRED CONFIG)' 'if(TARGET Prodigy::SdkC)' '   message(FATAL_ERROR \"unexpected C target in C++ package\")' 'endif()' 'if(NOT TARGET Prodigy::SdkCpp)' '   message(FATAL_ERROR \"missing installed target Prodigy::SdkCpp\")' 'endif()' 'if(NOT TARGET Prodigy::SdkCppOpinionated)' '   message(FATAL_ERROR \"missing installed target Prodigy::SdkCppOpinionated\")' 'endif()' 'if(NOT ProdigySDK_EXPORTED_TARGETS STREQUAL \"Prodigy::SdkCpp;Prodigy::SdkCppOpinionated\")' '   message(FATAL_ERROR \"unexpected ProdigySDK_EXPORTED_TARGETS=\${ProdigySDK_EXPORTED_TARGETS}\")' 'endif()' 'if(NOT ProdigySDK_HAS_CPP_OPINIONATED)' '   message(FATAL_ERROR \"installed config incorrectly reports missing C++ opinionated availability\")' 'endif()' > \"\${boundary_dir}/CMakeLists.txt\" && cmake -S \"\${boundary_dir}\" -B \"\${boundary_dir}/build\" -G Ninja -DCMAKE_PREFIX_PATH='${INSTALL_PREFIX}' -DCMAKE_CXX_COMPILER=clang++ -DDEPOS_ROOT='${ROOT_DIR}/.depos/.root'"

run_check install-boundary-c \
   bash \
   -lc \
   "boundary_dir='${TMP_DIR}/install-boundary-c' && mkdir -p \"\${boundary_dir}\" && printf '%s\n' 'cmake_minimum_required(VERSION 3.18)' 'project(ProdigySDKCInstallBoundary LANGUAGES C)' 'find_package(ProdigySDKC REQUIRED CONFIG)' 'if(NOT TARGET Prodigy::SdkC)' '   message(FATAL_ERROR \"missing installed target Prodigy::SdkC\")' 'endif()' 'if(NOT ProdigySDKC_EXPORTED_TARGETS STREQUAL \"Prodigy::SdkC\")' '   message(FATAL_ERROR \"unexpected ProdigySDKC_EXPORTED_TARGETS=\${ProdigySDKC_EXPORTED_TARGETS}\")' 'endif()' > \"\${boundary_dir}/CMakeLists.txt\" && cmake -S \"\${boundary_dir}\" -B \"\${boundary_dir}/build\" -G Ninja -DCMAKE_PREFIX_PATH='${INSTALL_PREFIX}' -DCMAKE_C_COMPILER=clang"

check_metadata_consistency()
{
   python3 - "${SDK_DIR}" <<'PY'
import json
import pathlib
import re
import sys
import tomllib

sdk = pathlib.Path(sys.argv[1])
versioning = json.loads((sdk / "versioning.json").read_text(encoding="utf-8"))
sdk_version = versioning["sdkVersion"]
wire_series = versioning["wireSeries"]
wire_protocol_version = str(versioning["wireProtocolVersion"])

def expect_equal(label: str, actual: str, expected: str) -> None:
   if actual != expected:
      raise SystemExit(f"{label}: expected {expected!r}, got {actual!r}")

def capture(label: str, path: pathlib.Path, pattern: str) -> str:
   text = path.read_text(encoding="utf-8")
   match = re.search(pattern, text, re.MULTILINE)
   if not match:
      raise SystemExit(f"{label}: pattern not found in {path}")
   return match.group(1)

expect_equal(
   "Cargo.toml sdkVersion",
   tomllib.loads((sdk / "rust" / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"],
   sdk_version,
)
expect_equal(
   "pyproject.toml sdkVersion",
   tomllib.loads((sdk / "python" / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"],
   sdk_version,
)
expect_equal(
   "package.json sdkVersion",
   json.loads((sdk / "typescript" / "package.json").read_text(encoding="utf-8"))["version"],
   sdk_version,
)

expect_equal(
   "c header sdkVersion",
   capture(
      "c header sdkVersion",
      sdk / "c" / "prodigy_neuron_hub.h",
      r'^#define PRODIGY_NEURON_HUB_SDK_VERSION_STRING "([^"]+)"$',
   ),
   sdk_version,
)
expect_equal(
   "c header wireSeries",
   capture(
      "c header wireSeries",
      sdk / "c" / "prodigy_neuron_hub.h",
      r'^#define PRODIGY_NEURON_HUB_WIRE_SERIES "([^"]+)"$',
   ),
   wire_series,
)
expect_equal(
   "c header wireProtocolVersion",
   capture(
      "c header wireProtocolVersion",
      sdk / "c" / "prodigy_neuron_hub.h",
      r'^#define PRODIGY_NEURON_HUB_WIRE_PROTOCOL_VERSION ([0-9]+)u$',
   ),
   wire_protocol_version,
)

expect_equal(
   "cpp header sdkVersion",
   capture(
      "cpp header sdkVersion",
      sdk / "cpp" / "neuron_hub.h",
      r'^   inline constexpr char SDKVersion\[\] = "([^"]+)";$',
   ),
   sdk_version,
)
expect_equal(
   "cpp header wireSeries",
   capture(
      "cpp header wireSeries",
      sdk / "cpp" / "neuron_hub.h",
      r'^   inline constexpr char WireSeries\[\] = "([^"]+)";$',
   ),
   wire_series,
)
expect_equal(
   "cpp header wireProtocolVersion",
   capture(
      "cpp header wireProtocolVersion",
      sdk / "cpp" / "neuron_hub.h",
      r'^   inline constexpr std::uint32_t WireProtocolVersion = ([0-9]+);$',
   ),
   wire_protocol_version,
)

expect_equal(
   "go source sdkVersion",
   capture("go source sdkVersion", sdk / "go" / "neuron_hub.go", r'^\s*SDKVersion\s*=\s*"([^"]+)"$'),
   sdk_version,
)
expect_equal(
   "go source wireSeries",
   capture("go source wireSeries", sdk / "go" / "neuron_hub.go", r'^\s*WireSeries\s*=\s*"([^"]+)"$'),
   wire_series,
)
expect_equal(
   "go source wireProtocolVersion",
   capture("go source wireProtocolVersion", sdk / "go" / "neuron_hub.go", r'^\s*WireProtocolVersion\s*=\s*uint32\(([0-9]+)\)$'),
   wire_protocol_version,
)

expect_equal(
   "typescript source sdkVersion",
   capture("typescript source sdkVersion", sdk / "typescript" / "neuron_hub.ts", r'^export const SDK_VERSION = "([^"]+)"$'),
   sdk_version,
)
expect_equal(
   "typescript source wireSeries",
   capture("typescript source wireSeries", sdk / "typescript" / "neuron_hub.ts", r'^export const WIRE_SERIES = "([^"]+)"$'),
   wire_series,
)
expect_equal(
   "typescript source wireProtocolVersion",
   capture("typescript source wireProtocolVersion", sdk / "typescript" / "neuron_hub.ts", r'^export const WIRE_PROTOCOL_VERSION = ([0-9]+)$'),
   wire_protocol_version,
)

for readme in [
   sdk / "go" / "README.md",
   sdk / "python" / "README.md",
   sdk / "rust" / "README.md",
   sdk / "typescript" / "README.md",
]:
   expect_equal(f"{readme.name} sdkVersion", capture(f"{readme.name} sdkVersion", readme, r'- SDK version: `([^`]+)`'), sdk_version)
   expect_equal(f"{readme.name} wireSeries", capture(f"{readme.name} wireSeries", readme, r'- Wire series: `([^`]+)`'), wire_series)
   expect_equal(f"{readme.name} wireProtocolVersion", capture(f"{readme.name} wireProtocolVersion", readme, r'- Wire protocol version: `([^`]+)`'), wire_protocol_version)

expect_equal(
   "fixtures manifest wireSeries",
   json.loads((sdk / "fixtures" / "manifest.json").read_text(encoding="utf-8"))["wireSeries"],
   wire_series,
)
expect_equal(
   "fixtures manifest wireProtocolVersion",
   str(json.loads((sdk / "fixtures" / "manifest.json").read_text(encoding="utf-8"))["wireProtocolVersion"]),
   wire_protocol_version,
)

print("sdk metadata versions are aligned")
PY
}

run_check manifest-version \
   python3 \
   -c \
   'import json, sys
versioning_path, manifest_path = sys.argv[1:3]
with open(versioning_path, "r", encoding="utf-8") as handle:
   versioning = json.load(handle)
with open(manifest_path, "r", encoding="utf-8") as handle:
   manifest = json.load(handle)
assert manifest["manifestVersion"] == versioning["fixtureManifestVersion"]
assert manifest["wireSeries"] == versioning["wireSeries"]
assert manifest["wireProtocolVersion"] == versioning["wireProtocolVersion"]
assert manifest["fixtureCorpusVersion"] == versioning["fixtureCorpusVersion"]
assert manifest["containerParametersMagic"] == versioning["containerParametersMagic"]
assert manifest["credentialBundleMagic"] == versioning["credentialBundleMagic"]
assert manifest["credentialDeltaMagic"] == versioning["credentialDeltaMagic"]
assert manifest["policy"] == versioning["policy"]
assert isinstance(manifest.get("fixtures"), list) and manifest["fixtures"]
' \
   "${SDK_DIR}/versioning.json" \
   "${SDK_DIR}/fixtures/manifest.json"

run_check metadata-consistency \
   check_metadata_consistency

run_check consumer-cmake \
   bash \
   -lc \
   "consumer_dir='${TMP_DIR}/cmake-consumer' && mkdir -p \"\${consumer_dir}\" && printf '%s\n' 'cmake_minimum_required(VERSION 3.18)' 'project(ProdigySDKConsumer LANGUAGES CXX)' 'find_package(ProdigySDK REQUIRED CONFIG)' 'add_executable(consumer main.cpp)' 'target_link_libraries(consumer PRIVATE Prodigy::SdkCpp)' > \"\${consumer_dir}/CMakeLists.txt\" && printf '%s\n' '#include <prodigy/aegis_session.h>' '#include <prodigy/neuron_hub.h>' '#include <array>' '#include <cstdint>' 'int main()' '{' '   ProdigySDK::SubscriptionPairing pairing{};' '   pairing.secret = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};' '   pairing.service = 0x2233000000001001ULL;' '   auto session = ProdigySDK::AegisSession::fromSubscription(pairing);' '   ProdigySDK::Bytes frame;' '   const ProdigySDK::U128 nonce = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};' '   if (session.encryptWithNonceInto(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(\"frame-one\"), sizeof(\"frame-one\") - 1), nonce, frame) != ProdigySDK::Result::ok)' '   {' '      return 1;' '   }' '   return frame.empty() ? 1 : 0;' '}' > \"\${consumer_dir}/main.cpp\" && cmake -S \"\${consumer_dir}\" -B \"\${consumer_dir}/build\" -G Ninja -DCMAKE_PREFIX_PATH='${INSTALL_PREFIX}' -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_CXX_STANDARD=26 -DDEPOS_ROOT='${ROOT_DIR}/.depos/.root' && cmake --build \"\${consumer_dir}/build\" -j$(nproc) && \"\${consumer_dir}/build/consumer\""

run_check consumer-cmake-c \
   bash \
   -lc \
   "consumer_dir='${TMP_DIR}/cmake-consumer-c' && mkdir -p \"\${consumer_dir}\" && printf '%s\n' 'cmake_minimum_required(VERSION 3.18)' 'project(ProdigySDKCConsumer LANGUAGES C)' 'find_package(ProdigySDKC REQUIRED CONFIG)' 'add_executable(consumer main.c)' 'target_link_libraries(consumer PRIVATE Prodigy::SdkC)' > \"\${consumer_dir}/CMakeLists.txt\" && printf '%s\n' '#include <prodigy/c/neuron_hub.h>' '#include <string.h>' 'int main(void)' '{' '   static const uint8_t secret[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};' '   static const uint8_t nonce_bytes[16] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};' '   prodigy_subscription_pairing pairing = {0};' '   prodigy_aegis_session session;' '   prodigy_u128 nonce;' '   prodigy_bytes frame = {0};' '   memcpy(pairing.secret.bytes, secret, sizeof(secret));' '   pairing.service = 0x2233000000001001ULL;' '   session = prodigy_aegis_session_from_subscription(&pairing);' '   memcpy(nonce.bytes, nonce_bytes, sizeof(nonce_bytes));' '   if (prodigy_aegis_encrypt_with_nonce(&session, (const uint8_t *)\"frame-one\", sizeof(\"frame-one\") - 1, &nonce, &frame) != PRODIGY_RESULT_OK)' '   {' '      return 1;' '   }' '   prodigy_bytes_free(&frame);' '   return 0;' '}' > \"\${consumer_dir}/main.c\" && cmake -S \"\${consumer_dir}\" -B \"\${consumer_dir}/build\" -G Ninja -DCMAKE_PREFIX_PATH='${INSTALL_PREFIX}' -DCMAKE_C_COMPILER=clang -DDEPOS_ROOT='${ROOT_DIR}/.depos/.root' && cmake --build \"\${consumer_dir}/build\" -j$(nproc) && \"\${consumer_dir}/build/consumer\""

run_check consumer-cmake-opinionated \
   bash \
   -lc \
   "consumer_dir='${TMP_DIR}/cmake-consumer-opinionated' && mkdir -p \"\${consumer_dir}\" && printf '%s\n' 'cmake_minimum_required(VERSION 3.18)' 'project(ProdigySDKOpinionatedConsumer LANGUAGES CXX)' 'find_package(ProdigySDK REQUIRED CONFIG)' 'add_executable(consumer main.cpp)' 'target_link_libraries(consumer PRIVATE Prodigy::SdkCppOpinionated)' > \"\${consumer_dir}/CMakeLists.txt\" && printf '%s\n' '#include <prodigy/opinionated/aegis_stream.h>' '#include <prodigy/opinionated/pairings.h>' 'int main()' '{' '   ProdigySDK::ContainerParameters params{};' '   ProdigySDK::Opinionated::PairingBook book;' '   auto actions = book.seedFromParameters(params);' '   return actions.empty() ? 0 : 1;' '}' > \"\${consumer_dir}/main.cpp\" && cmake -S \"\${consumer_dir}\" -B \"\${consumer_dir}/build\" -G Ninja -DCMAKE_PREFIX_PATH='${INSTALL_PREFIX}' -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_CXX_STANDARD=26 -DDEPOS_ROOT='${ROOT_DIR}/.depos/.root' && cmake --build \"\${consumer_dir}/build\" -j$(nproc) && \"\${consumer_dir}/build/consumer\""

run_check rust-test \
   env \
   CARGO_TARGET_DIR="${TMP_DIR}/cargo-target" \
   RUSTFLAGS="-C target-cpu=native" \
   cargo \
   test \
   --manifest-path "${SDK_DIR}/rust/Cargo.toml"
run_check rust-example \
   env \
   CARGO_TARGET_DIR="${TMP_DIR}/cargo-target" \
   RUSTFLAGS="-C target-cpu=native" \
   cargo \
   run \
   --manifest-path "${SDK_DIR}/rust/Cargo.toml" \
   --example \
   aegis_roundtrip
run_check rust-opinionated-example \
   env \
   CARGO_TARGET_DIR="${TMP_DIR}/cargo-target" \
   RUSTFLAGS="-C target-cpu=native" \
   cargo \
   run \
   --manifest-path "${SDK_DIR}/rust/Cargo.toml" \
   --example \
   opinionated_aegis_roundtrip
run_check rust-package \
   env \
   CARGO_TARGET_DIR="${TMP_DIR}/cargo-target" \
   RUSTFLAGS="-C target-cpu=native" \
   cargo \
   package \
   --allow-dirty \
   --manifest-path "${SDK_DIR}/rust/Cargo.toml"

run_check go-test \
   bash \
   -lc \
   "cd '${SDK_DIR}/go' && GOTOOLCHAIN=local '${GO_BIN}' test ./..."
run_check go-example \
   bash \
   -lc \
   "cd '${SDK_DIR}/go' && GOTOOLCHAIN=local '${GO_BIN}' run ./examples/aegis_roundtrip"

run_check python-venv \
   python3 \
   -m \
   venv \
   "${PYTHON_VENV_DIR}"
run_check python-install \
   bash \
   -lc \
   "PIP_DISABLE_PIP_VERSION_CHECK=1 '${PYTHON_VENV_DIR}/bin/pip' install -q -e '${SDK_DIR}/python'"
run_check python-build-tool \
   bash \
   -lc \
   "PIP_DISABLE_PIP_VERSION_CHECK=1 '${PYTHON_VENV_DIR}/bin/pip' install -q build"
run_check python-neuron \
   bash \
   -lc \
   "cd '${SDK_DIR}/python' && '${PYTHON_VENV_DIR}/bin/python' tests/test_neuron_hub.py"
run_check python-aegis \
   bash \
   -lc \
   "cd '${SDK_DIR}/python' && '${PYTHON_VENV_DIR}/bin/python' tests/test_aegis.py"
run_check python-example \
   bash \
   -lc \
   "cd '${SDK_DIR}/python' && '${PYTHON_VENV_DIR}/bin/python' examples/aegis_roundtrip.py"
run_check python-package \
   bash \
   -lc \
   "cd '${SDK_DIR}/python' && '${PYTHON_VENV_DIR}/bin/python' -m build --sdist --wheel --outdir '${TMP_DIR}/python-dist'"

if [[ ! -d "${SDK_DIR}/typescript/node_modules" ]]
then
   TYPESCRIPT_NODE_MODULES_CREATED=1
   run_check typescript-install \
      bash \
      -lc \
      "cd '${SDK_DIR}/typescript' && npm install --no-package-lock --ignore-scripts --cache '${TMP_DIR}/npm-cache'"
fi

run_check fixture-regenerate \
   bash \
   -lc \
   "backup_dir='${TMP_DIR}/fixtures-before' && diff_path='${TMP_DIR}/fixtures.diff' && rm -rf \"\${backup_dir}\" && cp -a '${SDK_DIR}/fixtures' \"\${backup_dir}\" && restore() { rm -rf '${SDK_DIR}/fixtures'; cp -a \"\${backup_dir}\" '${SDK_DIR}/fixtures'; }; trap restore EXIT; cd '${SDK_DIR}' && node --experimental-strip-types fixtures/generate.ts >/dev/null && if ! diff -ru \"\${backup_dir}\" '${SDK_DIR}/fixtures' > \"\${diff_path}\"; then sed -n '1,200p' \"\${diff_path}\" >&2; exit 1; fi; trap - EXIT"

run_check typescript-build \
   bash \
   -lc \
   "cd '${SDK_DIR}/typescript' && npm run build"
run_check typescript-self-test \
   bash \
   -lc \
   "cd '${SDK_DIR}/typescript' && npm run self-test"
run_check typescript-example \
   bash \
   -lc \
   "cd '${SDK_DIR}/typescript' && node --experimental-strip-types examples/aegis_roundtrip.ts"
run_check typescript-pack \
   bash \
   -lc \
   "mkdir -p '${TMP_DIR}/npm-pack' && cd '${SDK_DIR}/typescript' && npm pack --pack-destination '${TMP_DIR}/npm-pack'"

printf 'PASS compatibility-matrix fixtures=%s\n' "${SDK_DIR}/fixtures"
