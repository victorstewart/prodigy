#!/usr/bin/env bash
set -Eeuo pipefail

source_prodigy="${1:-}"
source_mothership="${2:-}"
target_bundle="${3:-}"
source_bundle="${4:-}"
application_plan="${5:-}"
application_artifact="${6:-}"
operation_id="${7:-}"
case_name="${8:-serial-normal}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
launcher="${PRODIGY_DEV_SERIAL_UPGRADE_LAUNCHER:-${script_dir}/prodigy_dev_test_cluster.sh}"

if [[ -z "${source_prodigy}" || -z "${source_mothership}" || -z "${target_bundle}" ||
      -z "${source_bundle}" || -z "${application_plan}" || -z "${application_artifact}" || -z "${operation_id}" ]]
then
   echo "usage: $0 SOURCE_PRODIGY SOURCE_MOTHERSHIP TARGET_BUNDLE SOURCE_BUNDLE APP_PLAN APP_ARTIFACT OPERATION_ID [serial-normal|follower-link-reconnect]" >&2
   exit 2
fi

for path in "${source_prodigy}" "${source_mothership}" "${target_bundle}" "${source_bundle}" "${application_plan}" "${application_artifact}" "${launcher}"
do
   [[ -r "${path}" ]] || { echo "FAIL: required path is unreadable: ${path}" >&2; exit 2; }
done
[[ -x "${source_prodigy}" && -x "${source_mothership}" && -x "${launcher}" ]] ||
   { echo "FAIL: source executables and launcher must be executable" >&2; exit 2; }
[[ "$(readlink -f "$(dirname "${source_mothership}")/prodigy")" == "$(readlink -f "${source_prodigy}")" ]] ||
   { echo "FAIL: source Prodigy and Mothership must be a release pair" >&2; exit 2; }
# Mothership owns canonical encoding validation; the driver only checks shape.
[[ "${operation_id}" =~ ^0x[0-9a-f]{1,32}$ && ! "${operation_id}" =~ ^0x0+$ ]] ||
   { echo "FAIL: operation ID must be nonzero lower-case 0x hex" >&2; exit 2; }

case "${case_name}" in
   serial-normal)
      ;;
   follower-link-reconnect)
      # No typed per-member rollout receipt exists yet.  Calling the existing
      # fault command by a timing guess would not be a qualification result.
      echo "SKIP: follower-link-reconnect requires a typed per-member rollout receipt report" >&2
      exit 77
      ;;
   *)
      echo "FAIL: unsupported scenario: ${case_name}" >&2
      exit 2
      ;;
esac

exec "${launcher}" "${source_prodigy}" \
   "--mothership-bin=${source_mothership}" \
   --machines=3 --brains=3 \
   "--deploy-plan-json=${application_plan}" \
   "--deploy-container-zstd=${application_artifact}" \
   --deploy-report-application=SerialUpgradeApp \
   --deploy-report-min-healthy=1 --deploy-report-min-target=1 --deploy-report-min-deployed=1 \
   --deploy-ping-port=19090 --deploy-ping-payload=ping --deploy-ping-expect=pong \
   "--mothership-plan-upgrade-target-bundle=${target_bundle}" \
   "--mothership-plan-upgrade-source-bundle=${source_bundle}" \
   "--mothership-plan-upgrade-operation-id=${operation_id}" \
   "--mothership-update-prodigy-input=${target_bundle}" \
   --update-continuity-probe=1 --update-continuity-probe-interval-ms=250 \
   --update-continuity-max-failures=0 --update-command-timeout=240 \
   --expect-master-available=1 --expect-full-brain-registration=1
