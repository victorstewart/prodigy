#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
PINGPONG_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"
source "${SCRIPT_DIR}/prodigy_dev_discombobulator_artifact_helpers.sh"
SCRIPT_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_AUTOSCALE_RUNTIME_MATRIX_MOUNT_NS_READY bash "${SCRIPT_SELF}" "$@"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${PINGPONG_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_pingpong_container"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for netns autoscale runtime matrix"
   exit 77
fi

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

if [[ ! -x "${PINGPONG_BIN}" ]]
then
   echo "FAIL: pingpong container binary is not executable: ${PINGPONG_BIN}"
   exit 1
fi

if [[ ! -x "${HARNESS}" ]]
then
   echo "FAIL: harness is not executable: ${HARNESS}"
   exit 1
fi

deps=(awk btrfs cargo mkfs.btrfs mount umount stat zstd timeout ip)
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

metric_name="pingpong.requests"
application_id=6 # MeshRegistry::Nametag::applicationID
ping_port=19090
total_cases=0
failed_cases=0
skipped_cases=0
case_filter="${PRODIGY_DEV_AUTOSCALE_CASE_FILTER:-}"

case_plan_json=""
case_container_blob=""
case_version_id=""
case_timeout_seconds="${PRODIGY_DEV_AUTOSCALE_CASE_TIMEOUT_SECONDS:-480}"
case_attempts="${PRODIGY_DEV_AUTOSCALE_CASE_ATTEMPTS:-3}"
case_duration_seconds="${PRODIGY_DEV_AUTOSCALE_CASE_DURATION_SECONDS:-90}"
repeated_case_duration_seconds="${PRODIGY_DEV_AUTOSCALE_REPEATED_CASE_DURATION_SECONDS:-150}"
repeated_case_report_attempts="${PRODIGY_DEV_AUTOSCALE_REPEATED_REPORT_ATTEMPTS:-90}"
repeated_case_traffic_burst="${PRODIGY_DEV_AUTOSCALE_REPEATED_TRAFFIC_BURST:-64}"
report_success_hold_ms="${PRODIGY_DEV_AUTOSCALE_REPORT_SUCCESS_HOLD_MS:-2500}"
report_floor_min_runtime_ms="${PRODIGY_DEV_AUTOSCALE_REPORT_FLOOR_MIN_RUNTIME_MS:-12000}"
report_poll_interval_ms="${PRODIGY_DEV_AUTOSCALE_REPORT_POLL_INTERVAL_MS:-300}"
common_hybrid_report_args=(
   "--deploy-report-success-hold-ms=${report_success_hold_ms}"
   "--deploy-report-floor-min-runtime-ms=${report_floor_min_runtime_ms}"
   "--deploy-report-poll-interval-ms=${report_poll_interval_ms}"
)

if ! [[ "${case_attempts}" =~ ^[0-9]+$ ]] || [[ "${case_attempts}" -le 0 ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_CASE_ATTEMPTS must be a positive integer"
   exit 1
fi

if ! [[ "${case_timeout_seconds}" =~ ^[0-9]+$ ]] || [[ "${case_timeout_seconds}" -le 0 ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_CASE_TIMEOUT_SECONDS must be a positive integer"
   exit 1
fi

if ! [[ "${case_duration_seconds}" =~ ^[0-9]+$ ]] || [[ "${case_duration_seconds}" -le 0 ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_CASE_DURATION_SECONDS must be a positive integer"
   exit 1
fi

if ! [[ "${repeated_case_duration_seconds}" =~ ^[0-9]+$ ]] || [[ "${repeated_case_duration_seconds}" -le 0 ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_REPEATED_CASE_DURATION_SECONDS must be a positive integer"
   exit 1
fi

build_case_artifacts()
{
   local case_name="$1"
   local n_base="$2"
   local percentile="$3"
   local threshold="$4"
   local direction="$5"
   local scaler_kind="${6:-horizontal}"   # horizontal|vertical
   local resource="${7:-ScalingDimension::cpu}"
   local increment="${8:-1}"
   local max_per_machine_ratio="${9:-0.5}"
   local n_logical_cores="${10:-1}"
   local memory_mb="${11:-256}"
   local storage_mb="${12:-64}"
   local scaler_min_value="${13:-}"
   local scaler_max_value="${14:-}"
   local s_til_killable="${15:-30}"
   local move_constructively="${16:-true}"
   local version_id=$(( ($(date +%s%N) & 281474976710655) ))
   if [[ "${version_id}" -le 0 ]]
   then
      version_id=1
   fi
   local deployment_id=$(( (application_id << 48) | version_id ))

   local scaler_min_json=""
   if [[ -n "${scaler_min_value}" ]]
   then
      scaler_min_json="      \"minValue\": ${scaler_min_value},"
   fi

   local scaler_max_json=""
   if [[ -n "${scaler_max_value}" ]]
   then
      scaler_max_json="      \"maxValue\": ${scaler_max_value},"
   fi

   local scaler_json=""
   if [[ "${scaler_kind}" == "vertical" ]]
   then
      scaler_json="$(cat <<EOF
  "verticalScalers": [
    {
      "name": "${metric_name}",
      "resource": "${resource}",
      "increment": ${increment},
      "percentile": ${percentile},
      "lookbackSeconds": 15,
      "threshold": ${threshold},
${scaler_min_json}
${scaler_max_json}
      "direction": "${direction}"
    }
  ],
EOF
)"
   else
      scaler_json="$(cat <<EOF
  "horizontalScalers": [
    {
      "name": "${metric_name}",
      "percentile": ${percentile},
      "lookbackSeconds": 15,
      "threshold": ${threshold},
${scaler_min_json}
${scaler_max_json}
      "direction": "${direction}",
      "lifetime": "ApplicationLifetime::base"
    }
  ],
EOF
)"
   fi

   case_plan_json="${tmpdir}/${case_name}.plan.json"
   case_version_id="${version_id}"
   cat > "${case_plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${application_id},
    "versionID": ${version_id},
    "architecture": "${target_arch}",
    "filesystemMB": 64,
    "storageMB": ${storage_mb},
    "memoryMB": ${memory_mb},
    "nLogicalCores": ${n_logical_cores},
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
    "sTilKillable": ${s_til_killable}
  },
  "useHostNetworkNamespace": true,
  "minimumSubscriberCapacity": 1024,
  "isStateful": false,
  "stateless": {
    "nBase": ${n_base},
    "maxPerRackRatio": 1.0,
    "maxPerMachineRatio": ${max_per_machine_ratio},
    "moveableDuringCompaction": true
  },
${scaler_json}
  "moveConstructively": ${move_constructively},
  "requiresDatacenterUniqueTag": false
}
EOF

   local build_attempt=0
   local build_ok=0

   case_container_blob="${tmpdir}/${case_name}.container.zst"
   rm -f "${case_container_blob}" >/dev/null 2>&1 || true

   for build_attempt in 1 2
   do
      local project_dir="${tmpdir}/${case_name}.artifact.${build_attempt}"
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
EXECUTE ["/root/pingpong_container"]
EOF

      if ! prodigy_dev_run_discombobulator_build \
         "${project_dir}" \
         "${discombobulator_file}" \
         "${case_container_blob}" \
         "bin=$(dirname "${PINGPONG_BIN}")" \
         "ebpf=$(dirname "${PRODIGY_BIN}")"
      then
         echo "WARN: ${case_name}: failed to build discombobulator artifact (attempt ${build_attempt}/2)" >&2
      else
         build_ok=1
         break
      fi

      rm -f "${case_container_blob}" >/dev/null 2>&1 || true
      sleep 1
   done

   if [[ "${build_ok}" -ne 1 ]]
   then
      echo "FAIL: ${case_name}: unable to build case artifacts after retries"
      exit 1
   fi
}

run_case()
{
   local case_name="$1"
   shift

   if [[ -n "${case_filter}" ]] && [[ ! "${case_name}" =~ ${case_filter} ]]
   then
      skipped_cases=$((skipped_cases + 1))
      echo "AUTOSCALE_CASE_SKIP ${case_name} filter=${case_filter}"
      return
   fi

   total_cases=$((total_cases + 1))
   local max_attempts="${case_attempts}"

   echo "=== AUTOSCALE_CASE ${case_name} ==="
   for attempt in $(seq 1 "${max_attempts}")
   do
      if timeout --preserve-status -k 8s "${case_timeout_seconds}s" "${HARNESS}" "${PRODIGY_BIN}" "$@"
      then
         echo "AUTOSCALE_CASE_PASS ${case_name}"
         return
      fi

      local rc=$?
      if [[ "${rc}" -eq 124 || "${rc}" -eq 137 || "${rc}" -eq 143 ]]
      then
         echo "AUTOSCALE_CASE_TIMEOUT ${case_name} attempt=${attempt}/${max_attempts} timeout_seconds=${case_timeout_seconds}"
      fi

      if [[ "${attempt}" -lt "${max_attempts}" ]]
      then
         echo "AUTOSCALE_CASE_RETRY ${case_name} attempt=${attempt}/${max_attempts}"
      fi
   done

   echo "AUTOSCALE_CASE_FAIL ${case_name}"
   failed_cases=$((failed_cases + 1))
}

# Case 1: prove stateless horizontal downscale direction works in runtime.
build_case_artifacts "horizontal_downscale_stateless" 2 90 100.0 "downscale" "horizontal" "ScalingDimension::cpu" 1 0.5 1 256 64 1
run_case "horizontal_downscale_stateless" \
   --brains=3 \
   --duration="${case_duration_seconds}" \
   --mothership-bin="${MOTHERSHIP_BIN}" \
   --mothership-autoscale-interval-seconds=8 \
   --deploy-plan-json="${case_plan_json}" \
   --deploy-container-zstd="${case_container_blob}" \
   --deploy-report-application="Nametag" \
   --deploy-report-version-id="${case_version_id}" \
   --deploy-report-min-healthy=1 \
   --deploy-report-max-healthy-min=2 \
   --deploy-report-final-target-max=1 \
   "${common_hybrid_report_args[@]}" \
   --deploy-ping-port="${ping_port}" \
   --deploy-ping-payload="ping" \
   --deploy-ping-expect="pong"

# Case 2: prove stateless horizontal upscale direction works in runtime.
build_case_artifacts "horizontal_upscale_stateless" 1 90 0.5 "upscale" "horizontal" "ScalingDimension::cpu" 1 0.5 1 256 64
run_case "horizontal_upscale_stateless" \
   --brains=3 \
   --duration="${case_duration_seconds}" \
   --mothership-bin="${MOTHERSHIP_BIN}" \
   --mothership-autoscale-interval-seconds=3 \
   --deploy-plan-json="${case_plan_json}" \
   --deploy-container-zstd="${case_container_blob}" \
   --deploy-report-application="Nametag" \
   --deploy-report-version-id="${case_version_id}" \
   --deploy-report-min-healthy=1 \
   --deploy-report-max-target-min=2 \
   --deploy-report-traffic-burst=24 \
   "${common_hybrid_report_args[@]}" \
   --deploy-ping-port="${ping_port}" \
   --deploy-ping-payload="ping" \
   --deploy-ping-expect="pong"

# Case 3: vertical CPU upscale honors base floor and still scales above it.
build_case_artifacts "vertical_upscale_floor_cpu_stateless" 1 90 0.000001 "upscale" "vertical" "ScalingDimension::cpu" 1 0.5 2 384 64 2 4
run_case "vertical_upscale_floor_cpu_stateless" \
   --brains=3 \
   --duration="${case_duration_seconds}" \
   --mothership-bin="${MOTHERSHIP_BIN}" \
   --mothership-autoscale-interval-seconds=3 \
   --deploy-plan-json="${case_plan_json}" \
   --deploy-container-zstd="${case_container_blob}" \
   --deploy-report-application="Nametag" \
   --deploy-report-version-id="${case_version_id}" \
   --deploy-report-version-min=1 \
   --deploy-report-min-healthy=1 \
   --deploy-report-max-target-min=1 \
   --deploy-report-final-target-max=1 \
   --deploy-report-runtime-cores-min=2 \
   --deploy-report-runtime-cores-max-min=3 \
   --deploy-report-traffic-burst=24 \
   "${common_hybrid_report_args[@]}" \
   --deploy-ping-port="${ping_port}" \
   --deploy-ping-payload="ping" \
   --deploy-ping-expect="pong"

# Case 4: vertical memory upscale honors memory floor and scales above it.
build_case_artifacts "vertical_upscale_floor_memory_stateless" 1 90 0.000001 "upscale" "vertical" "ScalingDimension::memory" 128 0.5 1 256 64 256 768
run_case "vertical_upscale_floor_memory_stateless" \
   --brains=3 \
   --duration="${case_duration_seconds}" \
   --mothership-bin="${MOTHERSHIP_BIN}" \
   --mothership-autoscale-interval-seconds=3 \
   --deploy-plan-json="${case_plan_json}" \
   --deploy-container-zstd="${case_container_blob}" \
   --deploy-report-application="Nametag" \
   --deploy-report-version-id="${case_version_id}" \
   --deploy-report-version-min=1 \
   --deploy-report-min-healthy=1 \
   --deploy-report-max-target-min=1 \
   --deploy-report-final-target-max=1 \
   --deploy-report-runtime-memory-min-mb=256 \
   --deploy-report-runtime-memory-max-min-mb=384 \
   --deploy-report-traffic-burst=24 \
   "${common_hybrid_report_args[@]}" \
   --deploy-ping-port="${ping_port}" \
   --deploy-ping-payload="ping" \
   --deploy-ping-expect="pong"

# Case 5: repeated vertical CPU up transitions under sustained load.
build_case_artifacts "vertical_repeated_upscale_cpu_stateless" 1 90 0.000001 "upscale" "vertical" "ScalingDimension::cpu" 1 0.5 1 256 64 1 3 6 false
run_case "vertical_repeated_upscale_cpu_stateless" \
   --brains=3 \
   --duration="${repeated_case_duration_seconds}" \
   --mothership-bin="${MOTHERSHIP_BIN}" \
   --mothership-autoscale-interval-seconds=3 \
   --deploy-plan-json="${case_plan_json}" \
   --deploy-container-zstd="${case_container_blob}" \
   --deploy-report-application="Nametag" \
   --deploy-report-version-id="${case_version_id}" \
   --deploy-report-version-min=1 \
   --deploy-report-attempts="${repeated_case_report_attempts}" \
   --deploy-report-min-healthy=1 \
   --deploy-report-max-target-min=1 \
   --deploy-report-final-target-max=1 \
   --deploy-report-runtime-cores-min=1 \
   --deploy-report-runtime-cores-max-min=3 \
   --deploy-report-traffic-burst="${repeated_case_traffic_burst}" \
   "${common_hybrid_report_args[@]}" \
   --deploy-ping-port="${ping_port}" \
   --deploy-ping-payload="ping" \
   --deploy-ping-expect="pong"

# Case 6: constrained vertical headroom caps growth without destabilizing runtime.
build_case_artifacts "vertical_constrained_headroom_cpu_stateless" 1 90 0.000001 "upscale" "vertical" "ScalingDimension::cpu" 1 0.5 1 256 64 1 2
run_case "vertical_constrained_headroom_cpu_stateless" \
   --brains=3 \
   --duration="${case_duration_seconds}" \
   --mothership-bin="${MOTHERSHIP_BIN}" \
   --mothership-autoscale-interval-seconds=3 \
   --deploy-plan-json="${case_plan_json}" \
   --deploy-container-zstd="${case_container_blob}" \
   --deploy-report-application="Nametag" \
   --deploy-report-version-id="${case_version_id}" \
   --deploy-report-version-min=1 \
   --deploy-report-min-healthy=1 \
   --deploy-report-max-target-min=1 \
   --deploy-report-final-target-max=1 \
   --deploy-report-runtime-cores-min=1 \
   --deploy-report-runtime-cores-max-min=2 \
   --deploy-report-traffic-burst=24 \
   "${common_hybrid_report_args[@]}" \
   --deploy-ping-port="${ping_port}" \
   --deploy-ping-payload="ping" \
   --deploy-ping-expect="pong"

echo "AUTOSCALE_RUNTIME_SUMMARY total=${total_cases} failed=${failed_cases} skipped=${skipped_cases}"

if [[ "${failed_cases}" -ne 0 ]]
then
   exit 1
fi

echo "AUTOSCALE_RUNTIME_PASS"
