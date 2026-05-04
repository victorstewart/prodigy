#!/usr/bin/env bash
set -euo pipefail

MOTHERSHIP_BIN="${1:-}"

if [[ -z "${MOTHERSHIP_BIN}" || ! -x "${MOTHERSHIP_BIN}" ]]
then
   echo "usage: $0 /path/to/mothership"
   exit 2
fi

for cmd in timeout rg python3
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}"
      exit 77
   fi
done

MOTHERSHIP_BIN="$(readlink -f "${MOTHERSHIP_BIN}" 2>/dev/null || printf '%s' "${MOTHERSHIP_BIN}")"

tmpdir="$(mktemp -d)"
missing_blob="${tmpdir}/missing.container.zst"
dummy_socket_path="${tmpdir}/local-mothership.sock"
dummy_socket_pid=""

cleanup()
{
   if [[ -n "${dummy_socket_pid}" ]]
   then
      kill "${dummy_socket_pid}" >/dev/null 2>&1 || true
      wait "${dummy_socket_pid}" >/dev/null 2>&1 || true
   fi
   rm -rf "${tmpdir}"
}
trap cleanup EXIT

python3 - "${dummy_socket_path}" <<'PY' &
import os
import socket
import sys
import time

path = sys.argv[1]
try:
   os.unlink(path)
except FileNotFoundError:
   pass

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(4)

try:
   while True:
      conn, _ = server.accept()
      conn.close()
except KeyboardInterrupt:
   pass
finally:
   server.close()
   try:
      os.unlink(path)
   except FileNotFoundError:
      pass
PY
dummy_socket_pid=$!

for _ in $(seq 1 50)
do
   if [[ -S "${dummy_socket_path}" ]]
   then
      break
   fi

   sleep 0.05
done

if [[ ! -S "${dummy_socket_path}" ]]
then
   echo "FAIL: dummy local mothership socket did not become ready"
   exit 1
fi

write_stateless_horizontal_plan()
{
   local path="$1"
   local percentile="$2"
   local scaler_body="$3"
   local metric_name="${4:-pingpong.requests}"

   cat > "${path}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": 6,
    "versionID": 1001,
    "architecture": "x86_64",
    "filesystemMB": 64,
    "storageMB": 64,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
    "sTilKillable": 30
  },
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
      "name": "${metric_name}",
      "percentile": ${percentile},
$(printf "%b\n" "${scaler_body}")
      "lifetime": "ApplicationLifetime::base"
   }
  ],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF
}

write_stateless_vertical_plan()
{
   local path="$1"
   local resource="${2:-ScalingDimension::cpu}"

   cat > "${path}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": 9,
    "versionID": 1004,
    "architecture": "x86_64",
    "filesystemMB": 64,
    "storageMB": 64,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
    "sTilKillable": 30
  },
  "minimumSubscriberCapacity": 1024,
  "isStateful": false,
  "stateless": {
    "nBase": 1,
    "maxPerRackRatio": 1.0,
    "maxPerMachineRatio": 1.0,
    "moveableDuringCompaction": true
  },
  "verticalScalers": [
    {
      "name": "pingpong.requests",
      "resource": "${resource}",
      "increment": 1,
      "percentile": 90,
      "lookbackSeconds": 15,
      "threshold": 0.5,
      "direction": "upscale"
    }
  ],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF
}
write_stateful_horizontal_downscale_plan()
{
   local path="$1"

   cat > "${path}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateful",
    "applicationID": 7,
    "versionID": 1002,
    "architecture": "x86_64",
    "filesystemMB": 64,
    "storageMB": 1024,
    "memoryMB": 512,
    "nLogicalCores": 1,
    "msTilHealthy": 5000,
    "sTilHealthcheck": 5,
    "sTilKillable": 30
  },
  "minimumSubscriberCapacity": 1024,
  "isStateful": true,
  "stateful": {
    "clientPrefix": 1,
    "siblingPrefix": 2,
    "cousinPrefix": 3,
    "seedingPrefix": 4,
    "shardingPrefix": 5,
    "allowUpdateInPlace": true,
    "seedingAlways": false,
    "neverShard": false,
    "allMasters": false
  },
  "horizontalScalers": [
    {
      "name": "stateful.load",
      "percentile": 90,
      "lookbackSeconds": 30,
      "threshold": 0.3,
      "direction": "downscale",
      "lifetime": "ApplicationLifetime::base"
    }
  ],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF
}

write_stateful_vertical_downscale_plan()
{
   local path="$1"

   cat > "${path}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateful",
    "applicationID": 8,
    "versionID": 1003,
    "architecture": "x86_64",
    "filesystemMB": 64,
    "storageMB": 1024,
    "memoryMB": 512,
    "nLogicalCores": 1,
    "msTilHealthy": 5000,
    "sTilHealthcheck": 5,
    "sTilKillable": 30
  },
  "minimumSubscriberCapacity": 1024,
  "isStateful": true,
  "stateful": {
    "clientPrefix": 1,
    "siblingPrefix": 2,
    "cousinPrefix": 3,
    "seedingPrefix": 4,
    "shardingPrefix": 5,
    "allowUpdateInPlace": true,
    "seedingAlways": false,
    "neverShard": false,
    "allMasters": false
  },
  "verticalScalers": [
    {
      "name": "stateful.load",
      "resource": "ScalingDimension::cpu",
      "increment": 1,
      "percentile": 95,
      "lookbackSeconds": 30,
      "threshold": 0.3,
      "direction": "downscale"
    }
  ],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF
}

run_deploy_expect_failure_with()
{
   local case_name="$1"
   local plan_path="$2"
   local expected="$3"
   local log_path="${tmpdir}/${case_name}.log"
   local payload=""

   payload="$(tr '\n' ' ' < "${plan_path}")"

   set +e
   timeout --preserve-status -k 1s 4s \
      env PRODIGY_MOTHERSHIP_SOCKET="${dummy_socket_path}" \
      "${MOTHERSHIP_BIN}" deploy local "${payload}" "${missing_blob}" \
      >"${log_path}" 2>&1
   local rc=$?
   set -e

   if [[ "${rc}" -eq 0 ]]
   then
      echo "CASE_FAIL ${case_name}: expected non-zero exit"
      sed -n '1,220p' "${log_path}" || true
      return 1
   fi

   if ! rg -q --fixed-strings "${expected}" "${log_path}"
   then
      echo "CASE_FAIL ${case_name}: missing expected output: ${expected}"
      sed -n '1,220p' "${log_path}" || true
      return 1
   fi

   echo "CASE_PASS ${case_name}"
   return 0
}

total_cases=0
failed_cases=0

run_case()
{
   local case_name="$1"
   local plan_path="$2"
   local expected="$3"

   total_cases=$((total_cases + 1))
   if ! run_deploy_expect_failure_with "${case_name}" "${plan_path}" "${expected}"
   then
      failed_cases=$((failed_cases + 1))
   fi
}

plan_accept_90="${tmpdir}/plan.accept90.json"
write_stateless_horizontal_plan "${plan_accept_90}" "90" "      \"lookbackSeconds\": 15,\n      \"threshold\": 0.5,\n      \"direction\": \"upscale\","
run_case "accept_percentile_90" "${plan_accept_90}" "no file exists at containerPath provided"

plan_accept_95="${tmpdir}/plan.accept95.json"
write_stateless_horizontal_plan "${plan_accept_95}" "95" "      \"lookbackSeconds\": 15,\n      \"threshold\": 0.5,\n      \"direction\": \"upscale\","
run_case "accept_percentile_95" "${plan_accept_95}" "no file exists at containerPath provided"

plan_accept_9137="${tmpdir}/plan.accept9137.json"
write_stateless_horizontal_plan "${plan_accept_9137}" "91.37" "      \"lookbackSeconds\": 15,\n      \"threshold\": 0.5,\n      \"direction\": \"upscale\","
run_case "accept_percentile_91_37" "${plan_accept_9137}" "no file exists at containerPath provided"

plan_accept_ingress_queue_alias="${tmpdir}/plan.accept_ingress_queue_alias.json"
write_stateless_horizontal_plan "${plan_accept_ingress_queue_alias}" "90" "      \"lookbackSeconds\": 15,\n      \"threshold\": 0.5,\n      \"direction\": \"upscale\"," "ScalingDimension::runtimeIngressQueueWaitComposite"
run_case "accept_horizontal_scaling_dimension_queue_wait_alias" "${plan_accept_ingress_queue_alias}" "no file exists at containerPath provided"

plan_accept_ingress_handler_alias="${tmpdir}/plan.accept_ingress_handler_alias.json"
write_stateless_horizontal_plan "${plan_accept_ingress_handler_alias}" "90" "      \"lookbackSeconds\": 15,\n      \"threshold\": 0.5,\n      \"direction\": \"upscale\"," "ScalingDimension::runtimeIngressHandlerComposite"
run_case "accept_horizontal_scaling_dimension_handler_alias" "${plan_accept_ingress_handler_alias}" "no file exists at containerPath provided"

plan_accept_vertical_no_bounds="${tmpdir}/plan.accept_vertical_no_bounds.json"
write_stateless_vertical_plan "${plan_accept_vertical_no_bounds}"
run_case "accept_vertical_default_bounds" "${plan_accept_vertical_no_bounds}" "no file exists at containerPath provided"

plan_reject_vertical_ingress_resource="${tmpdir}/plan.reject_vertical_ingress_resource.json"
write_stateless_vertical_plan "${plan_reject_vertical_ingress_resource}" "ScalingDimension::runtimeIngressQueueWaitComposite"
run_case "reject_vertical_ingress_resource_dimension" "${plan_reject_vertical_ingress_resource}" "verticalScalers.resource only supports cpu/memory/storage dimensions"

plan_reject_nintervals="${tmpdir}/plan.reject_nintervals.json"
write_stateless_horizontal_plan "${plan_reject_nintervals}" "90" "      \"nIntervals\": 1,\n      \"threshold\": 0.5,\n      \"direction\": \"upscale\","
run_case "reject_nIntervals" "${plan_reject_nintervals}" "horizontalScalers.nIntervals is not supported; use lookbackSeconds"

plan_reject_missing_threshold="${tmpdir}/plan.reject_missing_threshold.json"
write_stateless_horizontal_plan "${plan_reject_missing_threshold}" "90" "      \"lookbackSeconds\": 15,\n      \"direction\": \"upscale\","
run_case "reject_missing_threshold" "${plan_reject_missing_threshold}" "config.horizontalScalers threshold field of HorizontalScaler required"

plan_reject_missing_direction="${tmpdir}/plan.reject_missing_direction.json"
write_stateless_horizontal_plan "${plan_reject_missing_direction}" "90" "      \"lookbackSeconds\": 15,\n      \"threshold\": 0.5,"
run_case "reject_missing_direction" "${plan_reject_missing_direction}" "config.horizontalScalers direction field of HorizontalScaler required"

plan_reject_invalid_percentile="${tmpdir}/plan.reject_invalid_percentile.json"
write_stateless_horizontal_plan "${plan_reject_invalid_percentile}" "101.0" "      \"lookbackSeconds\": 15,\n      \"threshold\": 0.5,\n      \"direction\": \"upscale\","
run_case "reject_invalid_percentile" "${plan_reject_invalid_percentile}" "horizontalScalers.percentile must be in (0, 100]"

plan_reject_zero_percentile="${tmpdir}/plan.reject_zero_percentile.json"
write_stateless_horizontal_plan "${plan_reject_zero_percentile}" "0.0" "      \"lookbackSeconds\": 15,\n      \"threshold\": 0.5,\n      \"direction\": \"upscale\","
run_case "reject_zero_percentile" "${plan_reject_zero_percentile}" "horizontalScalers.percentile must be in (0, 100]"

plan_reject_operation="${tmpdir}/plan.reject_operation.json"
write_stateless_horizontal_plan "${plan_reject_operation}" "90" "      \"operation\": \"PulseTopic::avg_matrix\",\n      \"lookbackSeconds\": 15,\n      \"threshold\": 0.5,\n      \"direction\": \"upscale\","
run_case "reject_operation" "${plan_reject_operation}" "horizontalScalers.operation is not supported; use percentile + threshold + direction"

plan_reject_legacy_threshold="${tmpdir}/plan.reject_legacy_threshold.json"
write_stateless_horizontal_plan "${plan_reject_legacy_threshold}" "90" "      \"lookbackSeconds\": 15,\n      \"upscaleThreshold\": 0.5,\n      \"direction\": \"upscale\","
run_case "reject_legacy_threshold" "${plan_reject_legacy_threshold}" "is not supported; use threshold + direction"

plan_stateful_h_down="${tmpdir}/plan.stateful_h_down.json"
write_stateful_horizontal_downscale_plan "${plan_stateful_h_down}"
run_case "reject_stateful_horizontal_downscale" "${plan_stateful_h_down}" "stateful deployments cannot set horizontalScalers.direction=downscale"

plan_stateful_v_down="${tmpdir}/plan.stateful_v_down.json"
write_stateful_vertical_downscale_plan "${plan_stateful_v_down}"
run_case "reject_stateful_vertical_downscale" "${plan_stateful_v_down}" "stateful deployments cannot set verticalScalers.direction=downscale"

echo "SCHEMA_CONTRACT_SUMMARY total=${total_cases} failed=${failed_cases}"

if [[ "${failed_cases}" -ne 0 ]]
then
   exit 1
fi

echo "SCHEMA_CONTRACT_PASS"
