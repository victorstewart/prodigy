#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
PINGPONG_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"
source "${SCRIPT_DIR}/prodigy_dev_discombobulator_artifact_helpers.sh"
SCRIPT_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_STATEFUL_TOPOLOGY_UPGRADE_MATRIX_MOUNT_NS_READY bash "${SCRIPT_SELF}" "$@"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${PINGPONG_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_pingpong_container"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for netns stateful topology upgrade matrix"
   exit 77
fi

for path in "${PRODIGY_BIN}" "${MOTHERSHIP_BIN}" "${PINGPONG_BIN}" "${HARNESS}"
do
   if [[ ! -x "${path}" ]]
   then
      echo "FAIL: required executable is not available: ${path}"
      exit 1
   fi
done

deps=(awk btrfs cargo mkfs.btrfs mount umount stat zstd timeout ip rg)
for cmd in "${deps[@]}"
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}"
      exit 77
   fi
done

PRODIGY_BIN="$(readlink -f "${PRODIGY_BIN}" 2>/dev/null || printf '%s' "${PRODIGY_BIN}")"
MOTHERSHIP_BIN="$(readlink -f "${MOTHERSHIP_BIN}" 2>/dev/null || printf '%s' "${MOTHERSHIP_BIN}")"
PINGPONG_BIN="$(readlink -f "${PINGPONG_BIN}" 2>/dev/null || printf '%s' "${PINGPONG_BIN}")"
target_arch="$(prodigy_dev_detect_target_arch)"

tmpdir="$(mktemp -d)"
export TMPDIR="${tmpdir}"
failed_cases=0
total_cases=0

cleanup()
{
   set +e

   if [[ "${failed_cases}" -ne 0 ]]
   then
      echo "DEBUG: preserved tmpdir ${tmpdir}"
   else
      rm -rf "${tmpdir}"
   fi
}
trap cleanup EXIT

next_version_id()
{
   local version_id=$(( ($(date +%s%N) & 281474976710655) ))
   if [[ "${version_id}" -le 0 ]]
   then
      version_id=1
   fi
   echo "${version_id}"
}

build_blob_with_binary()
{
   local out_blob="$1"
   local app_id="$2"
   local version_id="$3"
   local project_dir="${tmpdir}/artifact-${app_id}-${version_id}"
   local discombobulator_file="${project_dir}/PingPong.DiscombobuFile"

   rm -rf "${project_dir}" >/dev/null 2>&1 || true
   mkdir -p "${project_dir}"
   cat > "${discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {bin} ./$(basename "${PINGPONG_BIN}") /root/pingpong_container
SURVIVE /root/pingpong_container
EOF
   prodigy_dev_write_common_prodigy_assets "${discombobulator_file}"
   cat >> "${discombobulator_file}" <<'EOF'
ENV PINGPONG_PERIODIC_METRIC_INTERVAL_MS=1000
EXECUTE ["/root/pingpong_container"]
EOF

   prodigy_dev_run_discombobulator_build \
      "${project_dir}" \
      "${discombobulator_file}" \
      "${out_blob}" \
      "bin=$(dirname "${PINGPONG_BIN}")" \
      "ebpf=$(dirname "${PRODIGY_BIN}")"
}

write_stateful_topology_upgrade_plan()
{
   local out_json="$1"
   local version_id="$2"
   local app_id="${3:-6}"
   local n_logical_cores="${4:-2}"
   local increment="${5:-2}"
   local max_value="${6:-4}"
   local memory_mb="${7:-256}"
   local storage_mb="${8:-64}"

   local client_prefix=$((app_id * 100 + 1))
   local sibling_prefix=$((app_id * 100 + 2))
   local cousin_prefix=$((app_id * 100 + 3))
   local seeding_prefix=$((app_id * 100 + 4))
   local sharding_prefix=$((app_id * 100 + 5))

   cat > "${out_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateful",
    "applicationID": ${app_id},
    "versionID": ${version_id},
    "architecture": "${target_arch}",
    "filesystemMB": 64,
    "storageMB": ${storage_mb},
    "memoryMB": ${memory_mb},
    "nLogicalCores": ${n_logical_cores},
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
    "sTilKillable": 30
  },
  "useHostNetworkNamespace": true,
  "minimumSubscriberCapacity": 1024,
  "isStateful": true,
  "stateful": {
    "clientPrefix": ${client_prefix},
    "siblingPrefix": ${sibling_prefix},
    "cousinPrefix": ${cousin_prefix},
    "seedingPrefix": ${seeding_prefix},
    "shardingPrefix": ${sharding_prefix},
    "allowUpdateInPlace": true,
    "seedingAlways": false,
    "neverShard": false,
    "allMasters": false
  },
  "verticalScalers": [
    {
      "name": "pingpong.requests",
      "resource": "ScalingDimension::cpu",
      "increment": ${increment},
      "maxValue": ${max_value},
      "percentile": 90,
      "lookbackSeconds": 15,
      "threshold": 0.000001,
      "direction": "upscale"
   }
  ],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF
}

build_case_artifacts()
{
   local case_name="$1"
   local app_id="$2"
   local n_logical_cores="$3"
   local increment="$4"
   local max_value="$5"

   case_version_id="$(next_version_id)"
   case_plan_json="${tmpdir}/${case_name}.plan.json"
   case_container_blob="${tmpdir}/${case_name}.container.zst"
   write_stateful_topology_upgrade_plan "${case_plan_json}" "${case_version_id}" "${app_id}" "${n_logical_cores}" "${increment}" "${max_value}"
   build_blob_with_binary "${case_container_blob}" "${app_id}" "${case_version_id}"
}

run_case()
{
   local case_name="$1"
   shift

   total_cases=$((total_cases + 1))
   echo "=== STATEFUL_TOPOLOGY_CASE ${case_name} ==="

   if PRODIGY_AUTOSCALE_TRACE=1 \
      PRODIGY_STATEFUL_TOPOLOGY_ROLLBACK_WINDOW_SECONDS=0 \
      PRODIGY_DEV_REQUIRE_BRAIN_LOG_ATTEMPTS=240 \
      timeout --preserve-status -k 8s "${PRODIGY_DEV_STATEFUL_TOPOLOGY_CASE_TIMEOUT_SECONDS:-420}s" \
      "${HARNESS}" "${PRODIGY_BIN}" "$@"
   then
      echo "STATEFUL_TOPOLOGY_CASE_PASS ${case_name}"
      return
   fi

   echo "STATEFUL_TOPOLOGY_CASE_FAIL ${case_name}"
   failed_cases=$((failed_cases + 1))
}

build_case_artifacts "even_worker_raise" 6 2 2 4
run_case "stateful_vertical_core_raise_blue_green_cutover" \
   --brains=3 \
   --test-machine-logical-cores=32 \
   --duration=180 \
   --expect-full-brain-registration=1 \
   --mothership-bin="${MOTHERSHIP_BIN}" \
   --mothership-autoscale-interval-seconds=3 \
   --deploy-plan-json="${case_plan_json}" \
   --deploy-container-zstd="${case_container_blob}" \
   --deploy-report-application="Nametag" \
   --deploy-report-version-id="${case_version_id}" \
   --deploy-report-attempts=800 \
   --deploy-report-min-healthy=3 \
   --deploy-report-final-healthy-min=3 \
   --deploy-report-final-healthy-max=3 \
   --deploy-report-min-target=3 \
   --deploy-report-final-target-max=3 \
   --deploy-report-max-deployed-min=6 \
   --deploy-report-final-deployed-max=3 \
   --deploy-report-max-crashes-max=0 \
   --deploy-report-runtime-cores-min=2 \
   --deploy-report-runtime-cores-max-min=4 \
   --deploy-report-require-scaler="pingpong.requests" \
   --deploy-report-require-scaler-value-min=1 \
   --deploy-skip-probe=1 \
   --require-brain-log-substring="stateful topology upgrade arm" \
   --require-brain-log-substring="stateful topology cutover" \
   --require-brain-log-substring="cores=2->4 workers=1->2"

build_case_artifacts "odd_worker_raise" 6 3 2 5
run_case "stateful_odd_core_raise_blue_green_cutover" \
   --brains=3 \
   --test-machine-logical-cores=32 \
   --duration=180 \
   --expect-full-brain-registration=1 \
   --mothership-bin="${MOTHERSHIP_BIN}" \
   --mothership-autoscale-interval-seconds=3 \
   --deploy-plan-json="${case_plan_json}" \
   --deploy-container-zstd="${case_container_blob}" \
   --deploy-report-application="Nametag" \
   --deploy-report-version-id="${case_version_id}" \
   --deploy-report-attempts=800 \
   --deploy-report-min-healthy=3 \
   --deploy-report-final-healthy-min=3 \
   --deploy-report-final-healthy-max=3 \
   --deploy-report-min-target=3 \
   --deploy-report-final-target-max=3 \
   --deploy-report-max-deployed-min=6 \
   --deploy-report-final-deployed-max=3 \
   --deploy-report-max-crashes-max=0 \
   --deploy-report-runtime-cores-min=3 \
   --deploy-report-runtime-cores-max-min=5 \
   --deploy-report-require-scaler="pingpong.requests" \
   --deploy-report-require-scaler-value-min=1 \
   --deploy-skip-probe=1 \
   --require-brain-log-substring="stateful topology upgrade arm" \
   --require-brain-log-substring="stateful topology cutover" \
   --require-brain-log-substring="cores=3->5 workers=1->3"

build_case_artifacts "topology_crash_recovery" 6 2 2 4
run_case "stateful_topology_upgrade_crash_recovery" \
   --brains=3 \
   --test-machine-logical-cores=32 \
   --duration=210 \
   --expect-full-brain-registration=1 \
   --expect-master-available=1 \
   --expect-peer-recovery=1 \
   --fault-mode=crash \
   --fault-targets=deployed \
   --fault-start=10 \
   --fault-duration=4 \
   --post-fault-window=30 \
   --mothership-bin="${MOTHERSHIP_BIN}" \
   --mothership-autoscale-interval-seconds=3 \
   --deploy-plan-json="${case_plan_json}" \
   --deploy-container-zstd="${case_container_blob}" \
   --deploy-report-application="Nametag" \
   --deploy-report-version-id="${case_version_id}" \
   --deploy-report-attempts=900 \
   --deploy-report-min-healthy=3 \
   --deploy-report-final-healthy-min=3 \
   --deploy-report-final-healthy-max=3 \
   --deploy-report-min-target=3 \
   --deploy-report-final-target-max=3 \
   --deploy-report-max-deployed-min=6 \
   --deploy-report-final-deployed-max=3 \
   --deploy-report-runtime-cores-min=2 \
   --deploy-report-runtime-cores-max-min=4 \
   --deploy-report-require-scaler="pingpong.requests" \
   --deploy-report-require-scaler-value-min=1 \
   --deploy-skip-probe=1 \
   --require-brain-log-substring="stateful topology upgrade arm" \
   --require-brain-log-substring="stateful topology cutover"

build_case_artifacts "repeated_odd_soak" 6 1 2 5
run_case "stateful_repeated_topology_raise_soak" \
   --brains=3 \
   --test-machine-logical-cores=32 \
   --duration=300 \
   --expect-full-brain-registration=1 \
   --mothership-bin="${MOTHERSHIP_BIN}" \
   --mothership-autoscale-interval-seconds=3 \
   --deploy-plan-json="${case_plan_json}" \
   --deploy-container-zstd="${case_container_blob}" \
   --deploy-report-application="Nametag" \
   --deploy-report-version-id="${case_version_id}" \
   --deploy-report-attempts=1200 \
   --deploy-report-min-healthy=3 \
   --deploy-report-final-healthy-min=3 \
   --deploy-report-final-healthy-max=3 \
   --deploy-report-min-target=3 \
   --deploy-report-final-target-max=3 \
   --deploy-report-max-deployed-min=6 \
   --deploy-report-final-deployed-max=3 \
   --deploy-report-max-crashes-max=0 \
   --deploy-report-runtime-cores-min=1 \
   --deploy-report-runtime-cores-max-min=5 \
   --deploy-report-require-scaler="pingpong.requests" \
   --deploy-report-require-scaler-value-min=1 \
   --deploy-skip-probe=1 \
   --require-brain-log-substring="stateful topology upgrade arm" \
   --require-brain-log-substring="stateful topology cutover" \
   --require-brain-log-substring="cores=1->3 workers=1->1" \
   --require-brain-log-substring="cores=3->5 workers=1->3"

echo "STATEFUL_TOPOLOGY_RUNTIME_SUMMARY total=${total_cases} failed=${failed_cases}"

if [[ "${failed_cases}" -ne 0 ]]
then
   exit 1
fi

echo "STATEFUL_TOPOLOGY_RUNTIME_PASS"
