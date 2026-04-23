#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership [--languages=rust,python,typescript,cpp]"
   exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"
DISCOMBOBULATOR_MANIFEST="${REPO_ROOT}/prodigy/discombobulator/Cargo.toml"

languages="rust,python,typescript,cpp"
sdk_mesh_machine_count="${PRODIGY_DEV_SDK_MESH_MACHINE_COUNT:-3}"
mothership_cli_timeout="${PRODIGY_DEV_SDK_MESH_MOTHERSHIP_TIMEOUT:-20s}"
mothership_deploy_timeout="${PRODIGY_DEV_SDK_MESH_DEPLOY_TIMEOUT:-120s}"
RUST_BLOB=""
CPP_BLOB=""
PYTHON_BLOB=""
TYPESCRIPT_BLOB=""

for arg in "${@:3}"
do
   case "${arg}" in
      --languages=*)
         languages="${arg#*=}"
         ;;
      *)
         echo "FAIL: unknown argument: ${arg}"
         exit 1
         ;;
   esac
done

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for isolated netns SDK mesh E2E tests"
   exit 77
fi

deps=(awk btrfs cargo clang clang++ cmake cp install ip mkfs.btrfs mount node python3 rg stat timeout umount zstd)
for cmd in "${deps[@]}"
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}"
      exit 77
   fi
done

if [[ ! -f "${DISCOMBOBULATOR_MANIFEST}" ]]
then
   echo "FAIL: discombobulator manifest not found: ${DISCOMBOBULATOR_MANIFEST}"
   exit 1
fi

PRODIGY_BIN="$(readlink -f "${PRODIGY_BIN}" 2>/dev/null || printf '%s' "${PRODIGY_BIN}")"
MOTHERSHIP_BIN="$(readlink -f "${MOTHERSHIP_BIN}" 2>/dev/null || printf '%s' "${MOTHERSHIP_BIN}")"

if [[ ! -x "${PRODIGY_BIN}" ]]
then
   echo "FAIL: prodigy binary is not executable: ${PRODIGY_BIN}"
   exit 1
fi

if [[ ! -x "${MOTHERSHIP_BIN}" ]]
then
   echo "FAIL: mothership binary is not executable: ${MOTHERSHIP_BIN}"
   exit 1
fi

if [[ ! -x "${HARNESS}" ]]
then
   echo "FAIL: harness is not executable: ${HARNESS}"
   exit 1
fi

if [[ "${sdk_mesh_machine_count}" != "3" ]]
then
   echo "FAIL: PRODIGY_DEV_SDK_MESH_MACHINE_COUNT must be 3"
   exit 1
fi

tmpdir="$(mktemp -d)"
containers_dir_created=0
containers_mount_created=0
containers_loop_image=""

cleanup()
{
   set +e

   if [[ "${containers_mount_created}" -eq 1 ]]
   then
      umount /containers >/dev/null 2>&1 || true
   fi

   if [[ "${containers_dir_created}" -eq 1 ]]
   then
      rmdir /containers >/dev/null 2>&1 || true
   fi

   rm -rf "${tmpdir}"
}
trap cleanup EXIT

target_arch=""
bundle_arch=""
detect_arch()
{
   local machine_arch

   machine_arch="$(uname -m)"
   case "${machine_arch}" in
      x86_64|amd64)
         target_arch="x86_64"
         bundle_arch="x86_64"
         ;;
      aarch64|arm64)
         target_arch="arm64"
         bundle_arch="aarch64"
         ;;
      riscv64|riscv)
         target_arch="riscv64"
         bundle_arch="riscv64"
         ;;
      *)
         echo "FAIL: unsupported host architecture for sdk mesh smoke: ${machine_arch}" >&2
         exit 1
         ;;
   esac
}

detect_arch

ensure_prodigy_bundle()
{
   local prodigy_dir
   local bundle_path

   prodigy_dir="$(dirname "${PRODIGY_BIN}")"
   bundle_path="${prodigy_dir}/prodigy.${bundle_arch}.bundle.tar.zst"
   if [[ ! -f "${bundle_path}" ]]
   then
      if [[ -f "${prodigy_dir}/CMakeCache.txt" ]]
      then
         cmake --build "${prodigy_dir}" -j"$(nproc)" --target prodigy_bundle prodigy_bundle_sha256 >/dev/null
      fi
   fi

   if [[ ! -f "${bundle_path}" ]]
   then
      echo "FAIL: required bundled prodigy artifact is missing: ${bundle_path}"
      exit 1
   fi
}

ensure_prodigy_bundle

if [[ ! -d /containers ]]
then
   mkdir -p /containers
   containers_dir_created=1
fi

containers_fs_type="$(stat -f -c '%T' /containers 2>/dev/null || echo unknown)"
if [[ "${containers_fs_type}" != "btrfs" ]]
then
   if awk '$2 == "/containers" { found = 1 } END { exit(found ? 0 : 1) }' /proc/self/mounts
   then
      echo "FAIL: /containers is mounted but not btrfs (found ${containers_fs_type})"
      exit 1
   fi

   if [[ -n "$(ls -A /containers 2>/dev/null)" ]]
   then
      echo "FAIL: /containers exists on non-btrfs fs and is not empty"
      exit 1
   fi

   containers_loop_image="${tmpdir}/containers.loop.img"
   truncate -s 6G "${containers_loop_image}"
   mkfs.btrfs -f "${containers_loop_image}" >/dev/null
   mount -o loop "${containers_loop_image}" /containers
   containers_mount_created=1
fi

mkdir -p /containers/store /containers/storage

build_discombobulator_binary()
{
   cargo build --quiet --manifest-path "${DISCOMBOBULATOR_MANIFEST}"
   echo "${REPO_ROOT}/prodigy/discombobulator/target/debug/discombobulator"
}

build_rust_artifact()
{
   (cd "${REPO_ROOT}/prodigy/sdk/rust" && cargo build --example mesh_pingpong --features tokio >/dev/null)
   echo "${REPO_ROOT}/prodigy/sdk/rust/target/debug/examples/mesh_pingpong"
}

build_cpp_artifact()
{
   local output="${tmpdir}/io_uring_mesh_pingpong_cpp"

   clang++ -std=gnu++26 -Wall -Wextra -Werror \
      -I/root/nametag/libraries/include/liburing \
      "${REPO_ROOT}/prodigy/sdk/cpp/examples/io_uring_mesh_pingpong.cpp" \
      /root/nametag/libraries/lib/liburing.a \
      -pthread \
      -o "${output}"

   echo "${output}"
}

build_container_egress_router_ebpf()
{
   local output="${tmpdir}/container.egress.router.ebpf.o"

   clang -g -O2 -target bpf \
      -I"${REPO_ROOT}" \
      -I"${REPO_ROOT}/libraries/include" \
      -DPRODIGY_DEBUG=1 \
      -c "${REPO_ROOT}/switchboard/kernel/container.egress.router.ebpf.c" \
      -o "${output}"

   echo "${output}"
}

build_container_ingress_router_ebpf()
{
   local output="${tmpdir}/container.ingress.router.ebpf.o"

   clang -g -O2 -target bpf \
      -I"${REPO_ROOT}" \
      -I"${REPO_ROOT}/libraries/include" \
      -DPRODIGY_DEBUG=1 \
      -c "${REPO_ROOT}/switchboard/kernel/container.ingress.router.ebpf.c" \
      -o "${output}"

   echo "${output}"
}

run_discombobulator_build()
{
   local project_dir="$1"
   local discombobulator_file="$2"
   local output_blob="$3"
   local build_log="${project_dir}/discombobulator-build.log"
   shift 3

   local args=(build --file "${discombobulator_file}" --output "${output_blob}" --kind app)
   while [[ "$#" -gt 0 ]]
   do
      args+=(--context "$1")
      shift
   done

   if ! (
      cd "${project_dir}"
      "${DISCOMBOBULATOR_BIN}" "${args[@]}"
   ) >"${build_log}" 2>&1
   then
      sed -n '1,240p' "${build_log}" >&2 || true
      return 1
   fi
}

write_common_prodigy_assets()
{
   local file="$1"

   cat >> "${file}" <<EOF
COPY {ebpf} ./container.egress.router.ebpf.o /root/prodigy/container.egress.router.ebpf.o
COPY {ebpf} ./container.ingress.router.ebpf.o /root/prodigy/container.ingress.router.ebpf.o
SURVIVE /root/prodigy
EOF
}

build_rust_blob()
{
   local project_dir="${tmpdir}/rust-project"
   local discombobulator_file="${project_dir}/RustMeshPingPong.DiscombobuFile"
   local output_blob="${tmpdir}/rust-mesh.container.zst"
   mkdir -p "${project_dir}"

   cat > "${discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {bin} ./mesh_pingpong /root/mesh_pingpong
SURVIVE /root/mesh_pingpong
EOF
   write_common_prodigy_assets "${discombobulator_file}"
   cat >> "${discombobulator_file}" <<'EOF'
EXECUTE ["/root/mesh_pingpong"]
EOF

   run_discombobulator_build \
      "${project_dir}" \
      "${discombobulator_file}" \
      "${output_blob}" \
      "bin=$(dirname "${RUST_BIN}")" \
      "ebpf=$(dirname "${CONTAINER_EGRESS_ROUTER_EBPF_OBJ}")"

   echo "${output_blob}"
}

build_cpp_blob()
{
   local project_dir="${tmpdir}/cpp-project"
   local discombobulator_file="${project_dir}/CppMeshPingPong.DiscombobuFile"
   local output_blob="${tmpdir}/cpp-mesh.container.zst"
   mkdir -p "${project_dir}"

   cat > "${discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {bin} ./$(basename "${CPP_EXAMPLE_BIN}") /root/io_uring_mesh_pingpong_cpp
SURVIVE /root/io_uring_mesh_pingpong_cpp
EOF
   write_common_prodigy_assets "${discombobulator_file}"
   cat >> "${discombobulator_file}" <<'EOF'
EXECUTE ["/root/io_uring_mesh_pingpong_cpp"]
EOF

   run_discombobulator_build \
      "${project_dir}" \
      "${discombobulator_file}" \
      "${output_blob}" \
      "bin=$(dirname "${CPP_EXAMPLE_BIN}")" \
      "ebpf=$(dirname "${CONTAINER_EGRESS_ROUTER_EBPF_OBJ}")"

   echo "${output_blob}"
}

build_python_blob()
{
   local project_dir="${tmpdir}/python-project"
   local discombobulator_file="${project_dir}/PythonMeshPingPong.DiscombobuFile"
   local output_blob="${tmpdir}/python-mesh.container.zst"
   local staged_python_stdlib="${tmpdir}/python-stdlib-context"
   mkdir -p "${project_dir}"
   if [[ ! -d "${staged_python_stdlib}" ]]
   then
      mkdir -p "${staged_python_stdlib}"
      cp -aL "${PYTHON_STDLIB}/." "${staged_python_stdlib}/"
   fi

   cat > "${discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {pybin} ./$(basename "${PYTHON_BIN}") ${PYTHON_BIN}
COPY {pystdlib} ./* ${PYTHON_STDLIB}
COPY {sdk} ./* /root/sdk/python
ENV PYTHONPATH=/root/sdk/python
SURVIVE ${PYTHON_BIN}
SURVIVE ${PYTHON_STDLIB}
SURVIVE /root/sdk/python
EOF
   write_common_prodigy_assets "${discombobulator_file}"
   cat >> "${discombobulator_file}" <<EOF
EXECUTE ["${PYTHON_BIN}", "/root/sdk/python/examples/async_mesh_pingpong.py"]
EOF

   run_discombobulator_build \
      "${project_dir}" \
      "${discombobulator_file}" \
      "${output_blob}" \
      "pybin=$(dirname "${PYTHON_BIN}")" \
      "pystdlib=${staged_python_stdlib}" \
      "sdk=${REPO_ROOT}/prodigy/sdk/python" \
      "ebpf=$(dirname "${CONTAINER_EGRESS_ROUTER_EBPF_OBJ}")"

   echo "${output_blob}"
}

build_typescript_blob()
{
   local project_dir="${tmpdir}/typescript-project"
   local discombobulator_file="${project_dir}/TypeScriptMeshPingPong.DiscombobuFile"
   local output_blob="${tmpdir}/typescript-mesh.container.zst"
   mkdir -p "${project_dir}"

   cat > "${discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {nodebin} ./$(basename "${NODE_BIN}") ${NODE_BIN}
COPY {sdk} ./* /root/sdk/typescript
SURVIVE ${NODE_BIN}
SURVIVE /root/sdk/typescript
EOF
   write_common_prodigy_assets "${discombobulator_file}"
   cat >> "${discombobulator_file}" <<EOF
EXECUTE ["${NODE_BIN}", "--experimental-strip-types", "/root/sdk/typescript/examples/mesh_pingpong.ts"]
EOF

   run_discombobulator_build \
      "${project_dir}" \
      "${discombobulator_file}" \
      "${output_blob}" \
      "nodebin=$(dirname "${NODE_BIN}")" \
      "sdk=${REPO_ROOT}/prodigy/sdk/typescript" \
      "ebpf=$(dirname "${CONTAINER_EGRESS_ROUTER_EBPF_OBJ}")"

   echo "${output_blob}"
}

extract_application_name_for_plan_json()
{
   local plan_json="$1"
   local symbolic_app_line=""
   local symbolic_app_name=""

   if [[ ! -f "${plan_json}" ]]
   then
      return 1
   fi

   symbolic_app_line="$(rg -m 1 -o '"applicationID"[[:space:]]*:[[:space:]]*"\$\{(application|app):[^"]+\}"' "${plan_json}" 2>/dev/null || true)"
   if [[ -n "${symbolic_app_line}" ]]
   then
      symbolic_app_name="$(echo "${symbolic_app_line}" | sed -E 's/.*"\$\{(application|app):([^}]+)\}".*/\2/' || true)"
      if [[ -n "${symbolic_app_name}" ]]
      then
         echo "${symbolic_app_name}"
         return 0
      fi
   fi

   return 1
}

extract_service_kind_for_plan_json()
{
   local plan_json="$1"
   local stateful_line=""
   local stateful_value=""
   local config_type_line=""
   local config_type_value=""

   if [[ ! -f "${plan_json}" ]]
   then
      return 1
   fi

   stateful_line="$(rg -m 1 -o '"isStateful"[[:space:]]*:[[:space:]]*(true|false)' "${plan_json}" 2>/dev/null || true)"
   if [[ -n "${stateful_line}" ]]
   then
      stateful_value="$(echo "${stateful_line}" | sed -E 's/.*:[[:space:]]*(true|false).*/\1/' || true)"
      if [[ "${stateful_value}" == "true" ]]
      then
         echo "stateful"
         return 0
      fi
   fi

   config_type_line="$(rg -m 1 -o '"type"[[:space:]]*:[[:space:]]*"ApplicationType::[^"]+"' "${plan_json}" 2>/dev/null || true)"
   if [[ -n "${config_type_line}" ]]
   then
      config_type_value="$(echo "${config_type_line}" | sed -E 's/.*"type"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' || true)"
      if [[ "${config_type_value}" == "ApplicationType::stateful" ]]
      then
         echo "stateful"
         return 0
      fi
   fi

   echo "stateless"
   return 0
}

extract_symbolic_service_refs_from_plan_json()
{
   local plan_json="$1"

   if [[ ! -f "${plan_json}" ]]
   then
      return 1
   fi

   rg -o '"service"[[:space:]]*:[[:space:]]*"\$\{(service|svc):[^"]+\}"' "${plan_json}" 2>/dev/null \
      | sed -E 's/.*"\$\{(service|svc):([^}]+)\}".*/\2/' \
      | sort -u
}

materialize_plan_for_target_arch()
{
   local plan_json="$1"
   local suffix="$2"
   local resolved_plan_json="${tmpdir}/${suffix}.resolved.deployment.plan.v1.json"

   cp -f "${plan_json}" "${resolved_plan_json}"
   if rg -q '"architecture"[[:space:]]*:' "${resolved_plan_json}"
   then
      perl -0pi -e 's/("architecture"\s*:\s*)"[^"]+"/${1}"'"${bundle_arch}"'"/s' "${resolved_plan_json}"
   else
      perl -0pi -e 's/("applicationID"\s*:\s*[^,\n]+,\n)/$1      "architecture": "'"${bundle_arch}"'",\n/s' "${resolved_plan_json}"
   fi

   echo "${resolved_plan_json}"
}

reserve_application_id()
{
   local cluster_name="$1"
   local mothership_db_path="$2"
   local application_name="$3"
   local reserve_log="$4"
   local reserve_success=0
   local reserve_json=""

   reserve_json="$(printf '{"applicationName":"%s"}' "${application_name}")"
   for _ in $(seq 1 40)
   do
      if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         timeout "${mothership_cli_timeout}" "${MOTHERSHIP_BIN}" reserveApplicationID "${cluster_name}" "${reserve_json}" \
         >"${reserve_log}" 2>&1
      then
         if grep -q "reserveApplicationID success=1" "${reserve_log}"
         then
            reserve_success=1
            break
         fi
      fi

      sleep 0.25
   done

   if [[ "${reserve_success}" -ne 1 ]]
   then
      echo "FAIL: reserveApplicationID failed for cluster=${cluster_name} application=${application_name}"
      sed -n '1,200p' "${reserve_log}" || true
      return 1
   fi
}

reserve_service_id()
{
   local cluster_name="$1"
   local mothership_db_path="$2"
   local application_name="$3"
   local service_name="$4"
   local service_kind="$5"
   local reserve_log="$6"
   local reserve_success=0
   local reserve_json=""

   reserve_json="$(printf '{"applicationName":"%s","serviceName":"%s","kind":"%s"}' "${application_name}" "${service_name}" "${service_kind}")"
   for _ in $(seq 1 40)
   do
      if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         timeout "${mothership_cli_timeout}" "${MOTHERSHIP_BIN}" reserveServiceID "${cluster_name}" "${reserve_json}" \
         >"${reserve_log}" 2>&1
      then
         if grep -q "reserveServiceID success=1" "${reserve_log}"
         then
            reserve_success=1
            break
         fi
      fi

      sleep 0.25
   done

   if [[ "${reserve_success}" -ne 1 ]]
   then
      echo "FAIL: reserveServiceID failed for cluster=${cluster_name} service=${application_name}/${service_name}"
      sed -n '1,200p' "${reserve_log}" || true
      return 1
   fi
}

reserve_plan_resources()
{
   local cluster_name="$1"
   local mothership_db_path="$2"
   local advertiser_plan="$3"
   local subscriber_plan="$4"
   local language="$5"
   local plan_json=""
   local app_name=""
   local service_kind=""
   local ref_body=""
   local ref_application_name=""
   local service_spec=""
   local service_name=""
   local reserve_log=""
   declare -A reserved_apps=()
   declare -A reserved_services=()

   for plan_json in "${advertiser_plan}" "${subscriber_plan}"
   do
      app_name="$(extract_application_name_for_plan_json "${plan_json}" || true)"
      if [[ -n "${app_name}" && -z "${reserved_apps[${app_name}]:-}" ]]
      then
         reserve_log="${tmpdir}/${language}.$(echo "${app_name}" | tr -c 'A-Za-z0-9._-' '_').reserve_application.log"
         reserve_application_id "${cluster_name}" "${mothership_db_path}" "${app_name}" "${reserve_log}"
         reserved_apps["${app_name}"]=1
      fi
   done

   for plan_json in "${advertiser_plan}" "${subscriber_plan}"
   do
      service_kind="$(extract_service_kind_for_plan_json "${plan_json}" || true)"
      if [[ "${service_kind}" != "stateful" ]]
      then
         service_kind="stateless"
      fi

      while IFS= read -r ref_body
      do
         if [[ -z "${ref_body}" || -n "${reserved_services[${ref_body}]:-}" ]]
         then
            continue
         fi

         if [[ "${ref_body}" != */* ]]
         then
            echo "FAIL: invalid symbolic service reference in ${plan_json}: ${ref_body}"
            return 1
         fi

         ref_application_name="${ref_body%%/*}"
         service_spec="${ref_body#*/}"
         service_name="${service_spec}"
         if [[ "${service_spec}" =~ ^(.+)\.group[0-9]+$ ]]
         then
            service_name="${BASH_REMATCH[1]}"
         fi

         reserve_log="${tmpdir}/${language}.$(echo "${ref_application_name}.${service_name}" | tr -c 'A-Za-z0-9._-' '_').reserve_service.log"
         reserve_service_id "${cluster_name}" "${mothership_db_path}" "${ref_application_name}" "${service_name}" "${service_kind}" "${reserve_log}"
         reserved_services["${ref_body}"]=1
      done < <(extract_symbolic_service_refs_from_plan_json "${plan_json}" || true)
   done
}

deploy_plan_to_cluster()
{
   local cluster_name="$1"
   local mothership_db_path="$2"
   local plan_json="$3"
   local container_blob="$4"
   local deploy_log="$5"
   local deployed=0

   for _ in $(seq 1 120)
   do
      if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         timeout "${mothership_deploy_timeout}" "${MOTHERSHIP_BIN}" deploy "${cluster_name}" "$(cat "${plan_json}")" "${container_blob}" \
         >"${deploy_log}" 2>&1
      then
         deployed=1
         break
      fi

      if ! grep -Eq 'cluster can only fit 0 total instances|we would need to schedule' "${deploy_log}"
      then
         break
      fi

      sleep 0.5
   done

   if [[ "${deployed}" -ne 1 ]]
   then
      echo "FAIL: deploy failed for cluster=${cluster_name} plan=${plan_json}"
      sed -n '1,220p' "${deploy_log}" || true
      return 1
   fi
}

wait_for_application_healthy()
{
   local cluster_name="$1"
   local mothership_db_path="$2"
   local application_name="$3"
   local application_log="$4"
   local healthy=0

   for _ in $(seq 1 180)
   do
      if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         timeout "${mothership_cli_timeout}" "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" "${application_name}" \
         >"${application_log}" 2>&1
      then
         if grep -Eq '(^|[[:space:]])nHealthy:[[:space:]]*1($|[[:space:]])' "${application_log}" \
            && grep -Eq '(^|[[:space:]])nTarget:[[:space:]]*1($|[[:space:]])' "${application_log}"
         then
            healthy=1
            break
         fi
      fi

      sleep 0.5
   done

   if [[ "${healthy}" -ne 1 ]]
   then
      echo "FAIL: application did not become healthy for cluster=${cluster_name} application=${application_name}"
      sed -n '1,220p' "${application_log}" || true
      return 1
   fi
}

run_language_suite()
{
   local language="$1"
   local advertiser_plan=""
   local subscriber_plan=""
   local resolved_advertiser_plan=""
   local resolved_subscriber_plan=""
   local advertiser_app=""
   local subscriber_app=""
   local blob=""

   case "${language}" in
      rust)
         advertiser_plan="${REPO_ROOT}/prodigy/sdk/rust/examples/mesh_pingpong.advertiser.deployment.plan.v1.json"
         subscriber_plan="${REPO_ROOT}/prodigy/sdk/rust/examples/mesh_pingpong.subscriber.deployment.plan.v1.json"
         advertiser_app="RustMeshPingPongAdvertiser"
         subscriber_app="RustMeshPingPongSubscriber"
         if [[ -z "${RUST_BLOB}" ]]
         then
            RUST_BLOB="$(build_rust_blob)"
         fi
         blob="${RUST_BLOB}"
         ;;
      python)
         advertiser_plan="${REPO_ROOT}/prodigy/sdk/python/examples/async_mesh_pingpong.advertiser.deployment.plan.v1.json"
         subscriber_plan="${REPO_ROOT}/prodigy/sdk/python/examples/async_mesh_pingpong.subscriber.deployment.plan.v1.json"
         advertiser_app="PythonMeshPingPongAdvertiser"
         subscriber_app="PythonMeshPingPongSubscriber"
         if [[ -z "${PYTHON_BLOB}" ]]
         then
            PYTHON_BLOB="$(build_python_blob)"
         fi
         blob="${PYTHON_BLOB}"
         ;;
      typescript)
         advertiser_plan="${REPO_ROOT}/prodigy/sdk/typescript/examples/mesh_pingpong.advertiser.deployment.plan.v1.json"
         subscriber_plan="${REPO_ROOT}/prodigy/sdk/typescript/examples/mesh_pingpong.subscriber.deployment.plan.v1.json"
         advertiser_app="TypeScriptMeshPingPongAdvertiser"
         subscriber_app="TypeScriptMeshPingPongSubscriber"
         if [[ -z "${TYPESCRIPT_BLOB}" ]]
         then
            TYPESCRIPT_BLOB="$(build_typescript_blob)"
         fi
         blob="${TYPESCRIPT_BLOB}"
         ;;
      cpp)
         advertiser_plan="${REPO_ROOT}/prodigy/sdk/cpp/examples/io_uring_mesh_pingpong.advertiser.deployment.plan.v1.json"
         subscriber_plan="${REPO_ROOT}/prodigy/sdk/cpp/examples/io_uring_mesh_pingpong.subscriber.deployment.plan.v1.json"
         advertiser_app="CppMeshPingPongAdvertiser"
         subscriber_app="CppMeshPingPongSubscriber"
         if [[ -z "${CPP_BLOB}" ]]
         then
            CPP_BLOB="$(build_cpp_blob)"
         fi
         blob="${CPP_BLOB}"
         ;;
      *)
         echo "FAIL: unsupported language ${language}"
         exit 1
         ;;
   esac

   resolved_advertiser_plan="$(materialize_plan_for_target_arch "${advertiser_plan}" "${language}.advertiser")"
   resolved_subscriber_plan="$(materialize_plan_for_target_arch "${subscriber_plan}" "${language}.subscriber")"

   (
      set -euo pipefail

      local cluster_name="sdk-mesh-${language}-$(date -u +%Y%m%d-%H%M%S)-${RANDOM}"
      local workspace_root="${tmpdir}/workspace-${language}"
      local manifest_path="${workspace_root}/test-cluster-manifest.json"
      local mothership_db_path="${tmpdir}/mothership-${language}.tidesdb"
      local create_log="${tmpdir}/${language}.create_cluster.log"
      local deploy_advertiser_log="${tmpdir}/${language}.deploy_advertiser.log"
      local deploy_subscriber_log="${tmpdir}/${language}.deploy_subscriber.log"
      local advertiser_report_log="${tmpdir}/${language}.advertiser.application_report.log"
      local subscriber_report_log="${tmpdir}/${language}.subscriber.application_report.log"
      local cluster_report_log="${tmpdir}/${language}.cluster_report.log"
      local cluster_created=0
      local create_request=""

      cleanup_cluster()
      {
         set +e
         if [[ "${cluster_created}" -eq 1 ]]
         then
            env PRODIGY_MOTHERSHIP_TEST_HARNESS="${HARNESS}" \
               PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
               "${MOTHERSHIP_BIN}" removeCluster "${cluster_name}" >/dev/null 2>&1 || true
         fi
      }
      trap cleanup_cluster EXIT

      mkdir -p "${workspace_root}"
      read -r -d '' create_request <<EOF || true
{
  "name": "${cluster_name}",
  "deploymentMode": "test",
  "nBrains": 1,
  "machineSchemas": [
    {
      "schema": "test-brain",
      "kind": "vm",
      "vmImageURI": "test://netns-local"
    }
  ],
  "test": {
    "workspaceRoot": "${workspace_root}",
    "machineCount": ${sdk_mesh_machine_count},
    "brainBootstrapFamily": "ipv4",
    "enableFakeIpv4Boundary": true,
    "host": {
      "mode": "local"
    }
  }
}
EOF

      echo "=== SDK_MESH_E2E ${language} cluster=${cluster_name} ==="

      if ! env PRODIGY_MOTHERSHIP_TEST_HARNESS="${HARNESS}" \
         PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" createCluster "${create_request}" \
         >"${create_log}" 2>&1
      then
         echo "FAIL: createCluster failed for ${language}"
         sed -n '1,240p' "${create_log}" || true
         exit 1
      fi
      cluster_created=1

      for _ in $(seq 1 300)
      do
         if [[ -s "${manifest_path}" ]]
         then
            break
         fi

         sleep 0.2
      done

      if [[ ! -s "${manifest_path}" ]]
      then
         echo "FAIL: cluster manifest did not become ready for ${language}"
         sed -n '1,240p' "${create_log}" || true
         exit 1
      fi

      reserve_plan_resources "${cluster_name}" "${mothership_db_path}" "${resolved_advertiser_plan}" "${resolved_advertiser_plan}" "${language}"
      deploy_plan_to_cluster "${cluster_name}" "${mothership_db_path}" "${resolved_advertiser_plan}" "${blob}" "${deploy_advertiser_log}"
      wait_for_application_healthy "${cluster_name}" "${mothership_db_path}" "${advertiser_app}" "${advertiser_report_log}"

      if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         timeout "${mothership_cli_timeout}" "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" \
         >"${cluster_report_log}" 2>&1
      then
         echo "FAIL: clusterReport failed for ${language}"
         sed -n '1,240p' "${cluster_report_log}" || true
         exit 1
      fi

      echo "PASS: SDK_MESH_E2E ${language} advertiser=${advertiser_app}"
   )
}

DISCOMBOBULATOR_BIN="$(build_discombobulator_binary)"
RUST_BIN="$(build_rust_artifact)"
CPP_EXAMPLE_BIN="$(build_cpp_artifact)"
CONTAINER_EGRESS_ROUTER_EBPF_OBJ="$(build_container_egress_router_ebpf)"
CONTAINER_INGRESS_ROUTER_EBPF_OBJ="$(build_container_ingress_router_ebpf)"
PYTHON_BIN="$(python3 -c 'import os, sys; print(os.path.realpath(sys.executable))')"
PYTHON_STDLIB="$(python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')"
NODE_BIN="$(readlink -f "$(command -v node)" 2>/dev/null || command -v node)"

if [[ -z "${PYTHON_BIN}" || ! -x "${PYTHON_BIN}" ]]
then
   echo "FAIL: unable to locate Python executable"
   exit 1
fi

if [[ -z "${PYTHON_STDLIB}" || ! -d "${PYTHON_STDLIB}" ]]
then
   echo "FAIL: unable to locate Python stdlib"
   exit 1
fi

if [[ -z "${NODE_BIN}" || ! -x "${NODE_BIN}" ]]
then
   echo "FAIL: unable to locate Node executable"
   exit 1
fi

IFS=',' read -r -a requested_languages <<<"${languages}"
for language in "${requested_languages[@]}"
do
   language="${language//[[:space:]]/}"
   if [[ -z "${language}" ]]
   then
      continue
   fi

   run_language_suite "${language}"
done

echo "SDK_MESH_E2E success languages=${languages} machines=${sdk_mesh_machine_count}"
