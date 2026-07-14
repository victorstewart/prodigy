#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
PINGPONG_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"
source "${SCRIPT_DIR}/prodigy_dev_discombobulator_artifact_helpers.sh"
SCRIPT_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_AUTOSCALE_METRICS_SMOKE_MOUNT_NS_READY bash "${SCRIPT_SELF}" "$@"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${PINGPONG_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_pingpong_container"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for netns + autoscale metrics smoke"
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
case_failed=0

cleanup()
{
   set +e

   if [[ "${case_failed}" -ne 0 ]]
   then
      echo "DEBUG: preserved tmpdir ${tmpdir}"
   else
      rm -rf "${tmpdir}"
   fi
}
trap cleanup EXIT

# Use a named registry application so mothership applicationReport can resolve it.
application_id=6 # MeshRegistry::Nametag::applicationID
version_id=$(( ($(date +%s%N) & 281474976710655) ))
if [[ "${version_id}" -le 0 ]]
then
   version_id=1
fi
deployment_id=$(( (application_id << 48) | version_id ))
ping_port=19090
emit_metric_name="${PRODIGY_DEV_AUTOSCALE_METRICS_EMIT_METRIC_NAME:-pingpong.requests}"
scaler_metric_name="${PRODIGY_DEV_AUTOSCALE_METRICS_SCALER_METRIC_NAME:-${emit_metric_name}}"
scaler_percentile="${PRODIGY_DEV_AUTOSCALE_METRICS_SCALER_PERCENTILE:-90}"
scaler_lookback_seconds="${PRODIGY_DEV_AUTOSCALE_METRICS_SCALER_LOOKBACK_SECONDS:-15}"
scaler_threshold="${PRODIGY_DEV_AUTOSCALE_METRICS_SCALER_THRESHOLD:-0.5}"
report_attempts="${PRODIGY_DEV_AUTOSCALE_METRICS_REPORT_ATTEMPTS:-36}"
report_traffic_burst="${PRODIGY_DEV_AUTOSCALE_METRICS_REPORT_TRAFFIC_BURST:-2}"
case_attempts="${PRODIGY_DEV_AUTOSCALE_METRICS_CASE_ATTEMPTS:-1}"
deploy_ping_attempts="${PRODIGY_DEV_AUTOSCALE_METRICS_DEPLOY_PING_ATTEMPTS:-300}"
harness_attempt_timeout_s="${PRODIGY_DEV_AUTOSCALE_METRICS_HARNESS_ATTEMPT_TIMEOUT_S:-420}"
harness_brains="${PRODIGY_DEV_AUTOSCALE_METRICS_HARNESS_BRAINS:-3}"
harness_duration_s="${PRODIGY_DEV_AUTOSCALE_METRICS_HARNESS_DURATION_S:-55}"
enable_report_checks="${PRODIGY_DEV_AUTOSCALE_METRICS_ENABLE_REPORT_CHECKS:-1}"
require_brain_log_substring="${PRODIGY_DEV_AUTOSCALE_METRICS_REQUIRE_BRAIN_LOG_SUBSTRING:-}"
require_scaler_name="${PRODIGY_DEV_AUTOSCALE_METRICS_REQUIRE_SCALER_NAME:-}"
require_scaler_value_min="${PRODIGY_DEV_AUTOSCALE_METRICS_REQUIRE_SCALER_VALUE_MIN:-0}"
autoscale_trace="${PRODIGY_AUTOSCALE_TRACE:-}"
if [[ -n "${require_brain_log_substring}" ]]
then
   autoscale_trace=1
fi

if [[ -z "${emit_metric_name}" ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_METRICS_EMIT_METRIC_NAME must be non-empty"
   exit 1
fi

if [[ -z "${scaler_metric_name}" ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_METRICS_SCALER_METRIC_NAME must be non-empty"
   exit 1
fi

if ! [[ "${report_attempts}" =~ ^[0-9]+$ ]] || [[ "${report_attempts}" -le 0 ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_METRICS_REPORT_ATTEMPTS must be a positive integer"
   exit 1
fi

if ! [[ "${report_traffic_burst}" =~ ^[0-9]+$ ]] || [[ "${report_traffic_burst}" -le 0 ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_METRICS_REPORT_TRAFFIC_BURST must be a positive integer"
   exit 1
fi

if ! [[ "${case_attempts}" =~ ^[0-9]+$ ]] || [[ "${case_attempts}" -le 0 ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_METRICS_CASE_ATTEMPTS must be a positive integer"
   exit 1
fi

if ! [[ "${deploy_ping_attempts}" =~ ^[0-9]+$ ]] || [[ "${deploy_ping_attempts}" -le 0 ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_METRICS_DEPLOY_PING_ATTEMPTS must be a positive integer"
   exit 1
fi

if ! [[ "${harness_attempt_timeout_s}" =~ ^[0-9]+$ ]] || [[ "${harness_attempt_timeout_s}" -le 0 ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_METRICS_HARNESS_ATTEMPT_TIMEOUT_S must be a positive integer"
   exit 1
fi

if [[ "${harness_brains}" != "1" && "${harness_brains}" != "3" ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_METRICS_HARNESS_BRAINS must be 1 or 3"
   exit 1
fi

if ! [[ "${harness_duration_s}" =~ ^[0-9]+$ ]] || [[ "${harness_duration_s}" -le 0 ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_METRICS_HARNESS_DURATION_S must be a positive integer"
   exit 1
fi

if [[ "${enable_report_checks}" != "0" && "${enable_report_checks}" != "1" ]]
then
   echo "FAIL: PRODIGY_DEV_AUTOSCALE_METRICS_ENABLE_REPORT_CHECKS must be 0 or 1"
   exit 1
fi

artifact_project_dir="${tmpdir}/autoscale-metrics-artifact"
discombobulator_file="${artifact_project_dir}/PingPongAutoscaleMetrics.DiscombobuFile"
container_blob="${tmpdir}/autoscale_metrics.container.zst"
mkdir -p "${artifact_project_dir}"
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
   "${artifact_project_dir}" \
   "${discombobulator_file}" \
   "${container_blob}" \
   "bin=$(dirname "${PINGPONG_BIN}")" \
   "ebpf=$(dirname "${PRODIGY_BIN}")"
then
   echo "FAIL: unable to build autoscale metrics artifact"
   exit 1
fi

plan_json="${tmpdir}/autoscale_metrics.plan.json"
cat > "${plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${application_id},
    "versionID": ${version_id},
    "architecture": "${target_arch}",
    "filesystemMB": 64,
    "storageMB": 64,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
    "sTilKillable": 30
  },
  "useHostNetworkNamespace": true,
  "minimumSubscriberCapacity": 1024,
  "isStateful": false,
  "stateless": {
    "nBase": 1,
    "maxPerRackRatio": 1.0,
    "maxPerMachineRatio": 1.0,
    "moveableDuringCompaction": true
  },
  "horizontalScalers": [
    {
      "name": "${scaler_metric_name}",
      "percentile": ${scaler_percentile},
      "lookbackSeconds": ${scaler_lookback_seconds},
      "threshold": ${scaler_threshold},
      "direction": "upscale",
      "lifetime": "ApplicationLifetime::base"
    }
  ],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF

for attempt in $(seq 1 "${case_attempts}")
do
   harness_args=(
      "${PRODIGY_BIN}"
      "--brains=${harness_brains}"
      "--duration=${harness_duration_s}"
      "--mothership-bin=${MOTHERSHIP_BIN}"
      "--mothership-autoscale-interval-seconds=5"
      "--deploy-plan-json=${plan_json}"
      "--deploy-container-zstd=${container_blob}"
      "--deploy-report-traffic-burst=${report_traffic_burst}"
      "--deploy-ping-port=${ping_port}"
      "--deploy-ping-payload=ping"
      "--deploy-ping-expect=pong"
   )

   if [[ "${enable_report_checks}" == "1" ]]
   then
      harness_args+=(
         "--deploy-report-application=Nametag"
         "--deploy-report-attempts=${report_attempts}"
         "--deploy-report-max-target-min=2"
      )

      if [[ -n "${require_scaler_name}" ]]
      then
         harness_args+=(
            "--deploy-report-require-scaler=${require_scaler_name}"
            "--deploy-report-require-scaler-value-min=${require_scaler_value_min}"
         )
      fi
   fi

   if [[ -n "${require_brain_log_substring}" ]]
   then
      harness_args+=("--require-brain-log-substring=${require_brain_log_substring}")
   fi

   if PRODIGY_AUTOSCALE_TRACE="${autoscale_trace}" \
      PINGPONG_METRIC_NAME="${emit_metric_name}" \
      PRODIGY_DEV_DEPLOY_PING_ATTEMPTS="${deploy_ping_attempts}" \
      PRODIGY_DEV_DEPLOY_SKIP_FINAL_PING=1 \
      timeout --preserve-status -k 3s "${harness_attempt_timeout_s}"s \
      "${HARNESS}" \
      "${harness_args[@]}"
   then
      if [[ "${attempt}" -gt 1 ]]
      then
         echo "AUTOSCALE_METRICS_CASE_PASS attempt=${attempt}/${case_attempts}"
      fi
      exit 0
   fi

   if [[ "${attempt}" -lt "${case_attempts}" ]]
   then
      echo "AUTOSCALE_METRICS_CASE_RETRY attempt=${attempt}/${case_attempts}"
   fi
done

echo "AUTOSCALE_METRICS_CASE_FAIL"
case_failed=1
exit 1
