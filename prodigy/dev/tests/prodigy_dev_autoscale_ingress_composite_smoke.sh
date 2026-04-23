#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
PINGPONG_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
METRICS_SMOKE="${SCRIPT_DIR}/prodigy_dev_autoscale_metrics_smoke.sh"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${PINGPONG_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_pingpong_container"
   exit 2
fi

if [[ ! -f "${METRICS_SMOKE}" ]]
then
   echo "FAIL: metrics smoke script is missing: ${METRICS_SMOKE}"
   exit 1
fi

run_case()
{
   local case_name="$1"
   local emit_metric_name="$2"
   local scaler_metric_name="$3"
   local scaler_threshold="$4"
   local rc=0

   echo "=== AUTOSCALE_INGRESS_COMPOSITE_CASE ${case_name} ==="

   set +e
   PRODIGY_AUTOSCALE_TRACE=1 \
      PINGPONG_METRIC_NAME="${emit_metric_name}" \
      PRODIGY_DEV_AUTOSCALE_METRICS_SCALER_METRIC_NAME="${scaler_metric_name}" \
      PRODIGY_DEV_AUTOSCALE_METRICS_SCALER_THRESHOLD="${scaler_threshold}" \
      PRODIGY_DEV_AUTOSCALE_METRICS_ENABLE_REPORT_CHECKS="${PRODIGY_DEV_AUTOSCALE_INGRESS_ENABLE_REPORT_CHECKS:-0}" \
      PRODIGY_DEV_AUTOSCALE_METRICS_REQUIRE_BRAIN_LOG_SUBSTRING="${PRODIGY_DEV_AUTOSCALE_INGRESS_REQUIRE_BRAIN_LOG_SUBSTRING:-autoscale ingressComposite deploymentID=}" \
      PRODIGY_DEV_AUTOSCALE_METRICS_REPORT_TRAFFIC_BURST="${PRODIGY_DEV_AUTOSCALE_INGRESS_REPORT_TRAFFIC_BURST:-8}" \
      PRODIGY_DEV_AUTOSCALE_METRICS_CASE_ATTEMPTS="${PRODIGY_DEV_AUTOSCALE_INGRESS_CASE_ATTEMPTS:-3}" \
      PRODIGY_DEV_AUTOSCALE_METRICS_HARNESS_BRAINS="${PRODIGY_DEV_AUTOSCALE_INGRESS_HARNESS_BRAINS:-3}" \
      PRODIGY_DEV_AUTOSCALE_METRICS_HARNESS_DURATION_S="${PRODIGY_DEV_AUTOSCALE_INGRESS_HARNESS_DURATION_S:-120}" \
      PRODIGY_DEV_AUTOSCALE_METRICS_HARNESS_ATTEMPT_TIMEOUT_S="${PRODIGY_DEV_AUTOSCALE_INGRESS_HARNESS_TIMEOUT_S:-420}" \
      "${METRICS_SMOKE}" "${PRODIGY_BIN}" "${MOTHERSHIP_BIN}" "${PINGPONG_BIN}"
   rc=$?
   set -e

   if [[ "${rc}" -eq 77 ]]
   then
      echo "AUTOSCALE_INGRESS_COMPOSITE_CASE_SKIP ${case_name}"
      exit 77
   fi

   if [[ "${rc}" -ne 0 ]]
   then
      echo "AUTOSCALE_INGRESS_COMPOSITE_CASE_FAIL ${case_name}"
      return 1
   fi

   echo "AUTOSCALE_INGRESS_COMPOSITE_CASE_PASS ${case_name}"
   return 0
}

run_case \
   "queue_wait_composite_alias" \
   "runtime.ingress.queue_wait_us.fine.bucket.10" \
   "ScalingDimension::runtimeIngressQueueWaitComposite" \
   "${PRODIGY_DEV_AUTOSCALE_INGRESS_QUEUE_WAIT_THRESHOLD:-100.0}"

run_case \
   "handler_composite_alias" \
   "runtime.ingress.handler_us.fine.bucket.9" \
   "ScalingDimension::runtimeIngressHandlerComposite" \
   "${PRODIGY_DEV_AUTOSCALE_INGRESS_HANDLER_THRESHOLD:-100.0}"

echo "AUTOSCALE_INGRESS_COMPOSITE_PASS"
