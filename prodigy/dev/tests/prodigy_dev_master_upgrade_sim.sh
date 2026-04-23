#!/usr/bin/env bash
set -uo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership [--duration=SECONDS] [--post-fault-window=SECONDS]"
   exit 2
fi

if [[ ! -x "${PRODIGY_BIN}" ]]
then
   echo "FAIL: prodigy binary is not executable: ${PRODIGY_BIN}"
   exit 1
fi

PRODIGY_BIN="$(readlink -f "${PRODIGY_BIN}" 2>/dev/null || printf '%s' "${PRODIGY_BIN}")"

if [[ ! -x "${MOTHERSHIP_BIN}" ]]
then
   echo "FAIL: mothership binary is not executable: ${MOTHERSHIP_BIN}"
   exit 1
fi

MOTHERSHIP_BIN="$(readlink -f "${MOTHERSHIP_BIN}" 2>/dev/null || printf '%s' "${MOTHERSHIP_BIN}")"

if [[ ! -x "${HARNESS}" ]]
then
   echo "FAIL: harness is not executable: ${HARNESS}"
   exit 1
fi

duration_s=28
post_fault_window_s=10

shift 2 || true
while [[ $# -gt 0 ]]
do
   case "$1" in
      --duration=*)
         duration_s="${1#*=}"
         ;;
      --post-fault-window=*)
         post_fault_window_s="${1#*=}"
         ;;
      *)
         echo "unknown argument: $1"
         exit 2
         ;;
   esac
   shift
done

if ! [[ "${duration_s}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --duration must be an integer number of seconds"
   exit 1
fi

if ! [[ "${post_fault_window_s}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --post-fault-window must be an integer number of seconds"
   exit 1
fi

total_cases=0
failed_cases=0
failed_names=()
case_max_attempts="${PRODIGY_DEV_CASE_MAX_ATTEMPTS:-2}"

if ! [[ "${case_max_attempts}" =~ ^[0-9]+$ ]] || [[ "${case_max_attempts}" -le 0 ]]
then
   echo "FAIL: PRODIGY_DEV_CASE_MAX_ATTEMPTS must be an integer >= 1"
   exit 1
fi

run_case()
{
   local name="$1"
   shift
   total_cases=$((total_cases + 1))

   echo "=== UPGRADE_CASE ${name} ==="

   local attempt=1
   while [[ "${attempt}" -le "${case_max_attempts}" ]]
   do
      if "${HARNESS}" \
         "${PRODIGY_BIN}" \
         --brains=3 \
         --duration="${duration_s}" \
         --mothership-bin="${MOTHERSHIP_BIN}" \
         --post-fault-window="${post_fault_window_s}" \
         "$@"
      then
         if [[ "${attempt}" -gt 1 ]]
         then
            echo "UPGRADE_CASE_PASS ${name} attempt=${attempt}/${case_max_attempts}"
         else
            echo "UPGRADE_CASE_PASS ${name}"
         fi
         return 0
      fi

      if [[ "${attempt}" -lt "${case_max_attempts}" ]]
      then
         echo "UPGRADE_CASE_RETRY ${name} attempt=${attempt}/${case_max_attempts}"
      fi

      attempt=$((attempt + 1))
   done

   echo "UPGRADE_CASE_FAIL ${name}"
   failed_cases=$((failed_cases + 1))
   failed_names+=("${name}")
   return 1
}

# Mothership-driven Prodigy update flow:
# - mothership sends updateProdigy to the current master
# - master coordinates follower updates, then relinquishes and upgrades itself last
run_case "mothership_update_prodigy_handover_master1" \
   --mothership-update-prodigy-input="${PRODIGY_BIN}" \
   --mothership-update-start=2 \
   --expect-master-available=1 \
   --expect-master-change-during-fault=1 \
   --expect-master-change=1 \
   --expect-peer-recovery=1

echo "=== UPGRADE_SUMMARY ==="
echo "cases_total=${total_cases}"
echo "cases_failed=${failed_cases}"

if [[ "${failed_cases}" -ne 0 ]]
then
   for name in "${failed_names[@]}"
   do
      echo "FAILED_UPGRADE_CASE ${name}"
   done
   exit 1
fi

echo "ALL_UPGRADE_CASES_PASS"
