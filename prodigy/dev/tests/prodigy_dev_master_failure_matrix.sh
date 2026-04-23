#!/usr/bin/env bash
set -uo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership [--mode=smoke|full] [--duration=SECONDS] [--post-fault-window=SECONDS]"
   exit 2
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

if [[ ! -x "${HARNESS}" ]]
then
   echo "FAIL: harness is not executable: ${HARNESS}"
   exit 1
fi

mode="full"
duration_s=26
post_fault_window_s=10

shift 2 || true
while [[ $# -gt 0 ]]
do
   case "$1" in
      --mode=*)
         mode="${1#*=}"
         ;;
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

if [[ "${mode}" != "smoke" && "${mode}" != "full" ]]
then
   echo "FAIL: --mode must be smoke or full"
   exit 1
fi

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

   echo "=== CASE ${name} ==="

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
            echo "CASE_PASS ${name} attempt=${attempt}/${case_max_attempts}"
         else
            echo "CASE_PASS ${name}"
         fi
         return 0
      fi

      if [[ "${attempt}" -lt "${case_max_attempts}" ]]
      then
         echo "CASE_RETRY ${name} attempt=${attempt}/${case_max_attempts}"
      fi

      attempt=$((attempt + 1))
   done

   echo "CASE_FAIL ${name}"
   failed_cases=$((failed_cases + 1))
   failed_names+=("${name}")
   return 1
}

# Baseline and single-fault scenarios.
run_case "baseline_self_elected_master"

run_case "follower1_transient_partition_heals" \
   --fault-targets=follower1 \
   --fault-start=2 \
   --fault-duration=4 \
   --expect-master-available=1 \
   --expect-master-change=0 \
   --expect-master-change-during-fault=0 \
   --expect-peer-recovery=1

run_case "no_majority_partition_1_2" \
   --fault-targets=1,2 \
   --fault-start=2 \
   --fault-duration=0 \
   --expect-master-available=0

run_case "master_transient_partition_requires_failover" \
   --fault-targets=master \
   --fault-start=2 \
   --fault-duration=6 \
   --expect-master-available=1 \
   --expect-master-change-during-fault=1 \
   --expect-master-change=1 \
   --expect-peer-recovery=1

run_case "master_transient_crash_requires_failover" \
   --fault-mode=crash \
   --fault-targets=master \
   --fault-start=2 \
   --fault-duration=6 \
   --expect-master-available=1 \
   --expect-master-change-during-fault=1 \
   --expect-master-change=1 \
   --expect-peer-recovery=1

if [[ "${mode}" == "full" ]]
then
   run_case "follower2_transient_partition_heals" \
      --fault-targets=follower2 \
      --fault-start=2 \
      --fault-duration=4 \
      --expect-master-available=1 \
      --expect-master-change=0 \
      --expect-master-change-during-fault=0 \
      --expect-peer-recovery=1

   run_case "follower1_permanent_partition" \
      --fault-targets=follower1 \
      --fault-start=2 \
      --fault-duration=0 \
      --expect-master-available=1 \
      --expect-master-change=0

   run_case "master_permanent_partition_requires_failover" \
      --fault-targets=master \
      --fault-start=2 \
      --fault-duration=0 \
      --expect-master-available=1 \
      --expect-master-change=1 \
      --expect-master-change-during-fault=1

   run_case "follower1_transient_crash_recovers" \
      --fault-mode=crash \
      --fault-targets=follower1 \
      --fault-start=2 \
      --fault-duration=4 \
      --expect-master-available=1 \
      --expect-master-change=0 \
      --expect-master-change-during-fault=0 \
      --expect-peer-recovery=1

   run_case "follower2_transient_crash_recovers" \
      --fault-mode=crash \
      --fault-targets=follower2 \
      --fault-start=2 \
      --fault-duration=4 \
      --expect-master-available=1 \
      --expect-master-change=0 \
      --expect-master-change-during-fault=0 \
      --expect-peer-recovery=1

   run_case "master_permanent_crash_requires_failover" \
      --fault-mode=crash \
      --fault-targets=master \
      --fault-start=2 \
      --fault-duration=0 \
      --expect-master-available=1 \
      --expect-master-change-during-fault=1 \
      --expect-master-change=1

   run_case "no_majority_partition_1_3" \
      --fault-targets=1,3 \
      --fault-start=2 \
      --fault-duration=0 \
      --expect-master-available=0

   run_case "no_majority_partition_2_3" \
      --fault-targets=2,3 \
      --fault-start=2 \
      --fault-duration=0 \
      --expect-master-available=0

   run_case "no_majority_partition_1_2_then_heal" \
      --fault-targets=1,2 \
      --fault-start=2 \
      --fault-duration=6 \
      --expect-master-available=1 \
      --expect-peer-recovery=1

   run_case "no_majority_crash_1_2" \
      --fault-mode=crash \
      --fault-targets=1,2 \
      --fault-start=2 \
      --fault-duration=0 \
      --expect-master-available=0

   run_case "master_transient_partition_requires_failover_repeat_a" \
      --fault-targets=master \
      --fault-start=2 \
      --fault-duration=6 \
      --expect-master-available=1 \
      --expect-master-change-during-fault=1 \
      --expect-master-change=1 \
      --expect-peer-recovery=1

   run_case "master_transient_partition_requires_failover_repeat_b" \
      --fault-targets=master \
      --fault-start=2 \
      --fault-duration=6 \
      --expect-master-available=1 \
      --expect-master-change-during-fault=1 \
      --expect-master-change=1 \
      --expect-peer-recovery=1

   run_case "follower1_flap_heals" \
      --fault-mode=flap \
      --fault-targets=follower1 \
      --fault-start=2 \
      --fault-cycles=4 \
      --fault-down=1 \
      --fault-up=1 \
      --expect-master-available=1 \
      --expect-master-change=0 \
      --expect-peer-recovery=1

   run_case "master_flap_recovers_quorum" \
      --fault-mode=flap \
      --fault-targets=master \
      --fault-start=2 \
      --fault-cycles=4 \
      --fault-down=1 \
      --fault-up=1 \
      --expect-master-available=1 \
      --expect-peer-recovery=1
fi

echo "=== SUMMARY ==="
echo "cases_total=${total_cases}"
echo "cases_failed=${failed_cases}"

if [[ "${failed_cases}" -ne 0 ]]
then
   for name in "${failed_names[@]}"
   do
      echo "FAILED_CASE ${name}"
   done
   exit 1
fi

echo "ALL_CASES_PASS"
