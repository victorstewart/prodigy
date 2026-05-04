#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for netns OS update matrix"
   exit 77
fi

for path in "${PRODIGY_BIN}" "${MOTHERSHIP_BIN}" "${HARNESS}"
do
   if [[ ! -x "${path}" ]]
   then
      echo "FAIL: required executable is not available: ${path}"
      exit 1
   fi
done

deps=(awk btrfs mkfs.btrfs mount umount stat timeout ip rg)
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

tmpdir="$(mktemp -d)"
failed_cases=0
total_cases=0

cleanup()
{
   if [[ "${failed_cases}" -ne 0 ]]
   then
      echo "DEBUG: preserved tmpdir ${tmpdir}"
   else
      rm -rf "${tmpdir}"
   fi
}
trap cleanup EXIT

run_case()
{
   local case_name="$1"
   shift

   total_cases=$((total_cases + 1))
   local case_log="${tmpdir}/${case_name}.log"
   echo "=== OS_UPDATE_CASE ${case_name} ==="

   if "$@" >"${case_log}" 2>&1
   then
      echo "OS_UPDATE_CASE_PASS ${case_name}"
      return
   fi

   echo "OS_UPDATE_CASE_FAIL ${case_name}"
   sed -n '1,260p' "${case_log}"
   failed_cases=$((failed_cases + 1))
}

run_successful_reimage_case()
{
   local case_name="$1"
   shift

   local target_os_id="${PRODIGY_DEV_TEST_OS_RELEASE_ID:-portablelinux}"
   local target_version="${1:-2}"
   shift || true

   timeout --preserve-status -k 8s "${PRODIGY_DEV_OS_UPDATE_CASE_TIMEOUT_SECONDS:-260}s" \
   env \
      PRODIGY_DEV_ALLOW_BPF_ATTACH="${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}" \
      PRODIGY_DEV_TEST_OS_RELEASE_ID="${target_os_id}" \
      PRODIGY_DEV_TEST_OS_RELEASE_VERSION_ID="${PRODIGY_DEV_TEST_OS_RELEASE_VERSION_ID:-1}" \
      PRODIGY_DEV_CONFIGURE_TARGET_OS_ID="${target_os_id}" \
      PRODIGY_DEV_CONFIGURE_TARGET_OS_VERSION_ID="${target_version}" \
      PRODIGY_DEV_CONFIGURE_OS_UPDATE_COMMAND="${PRODIGY_DEV_CONFIGURE_OS_UPDATE_COMMAND:-printf 'ID=%s\nVERSION_ID=%s\n' \"\$PRODIGY_CURRENT_OS_ID\" \"\$PRODIGY_TARGET_OS_VERSION_ID\" > \"\$PRODIGY_DEV_OS_RELEASE_PATH\"}" \
      PRODIGY_DEV_CONFIGURE_OS_UPDATES_ENABLED="${PRODIGY_DEV_CONFIGURE_OS_UPDATES_ENABLED:-1}" \
      PRODIGY_DEV_CONFIGURE_MAX_OS_DRAINS="${PRODIGY_DEV_CONFIGURE_MAX_OS_DRAINS:-1}" \
      PRODIGY_DEV_CONFIGURE_MACHINE_UPDATE_CADENCE_MINS="${PRODIGY_DEV_CONFIGURE_MACHINE_UPDATE_CADENCE_MINS:-1}" \
      PRODIGY_DEV_OS_UPDATE_CADENCE_MS="${PRODIGY_DEV_OS_UPDATE_CADENCE_MS:-1000}" \
      "${HARNESS}" "${PRODIGY_BIN}" \
         --brains=3 \
         --machines=3 \
         --duration=180 \
         --mothership-bin="${MOTHERSHIP_BIN}" \
         --os-update-restart-on-command=1 \
         --os-update-command-timeout="${PRODIGY_DEV_OS_UPDATE_COMMAND_TIMEOUT_S:-80}" \
         --os-update-rollout-timeout="${PRODIGY_DEV_OS_UPDATE_ROLLOUT_TIMEOUT_S:-120}" \
         --expect-master-available=1 \
         --expect-peer-recovery=1 \
         --expect-full-brain-registration=1 \
         --require-brain-log-substring="neuron updateOS started" \
         --require-brain-log-substring="osVersionID=${target_version}" \
         "$@"
}

run_dead_command_case()
{
   timeout --preserve-status -k 8s "${PRODIGY_DEV_OS_UPDATE_CASE_TIMEOUT_SECONDS:-260}s" \
   env \
      PRODIGY_DEV_ALLOW_BPF_ATTACH="${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}" \
      PRODIGY_DEV_TEST_OS_RELEASE_ID="portablelinux" \
      PRODIGY_DEV_TEST_OS_RELEASE_VERSION_ID="1" \
      PRODIGY_DEV_CONFIGURE_TARGET_OS_ID="portablelinux" \
      PRODIGY_DEV_CONFIGURE_TARGET_OS_VERSION_ID="deadline" \
      PRODIGY_DEV_CONFIGURE_OS_UPDATE_COMMAND="true" \
      PRODIGY_DEV_CONFIGURE_OS_UPDATES_ENABLED=1 \
      PRODIGY_DEV_CONFIGURE_MAX_OS_DRAINS=1 \
      PRODIGY_DEV_CONFIGURE_MACHINE_UPDATE_CADENCE_MINS=1 \
      PRODIGY_DEV_OS_UPDATE_CADENCE_MS=1000 \
      PRODIGY_DEV_OS_UPDATE_COMMAND_REBOOT_DEADLINE_MS=2000 \
      "${HARNESS}" "${PRODIGY_BIN}" \
         --brains=3 \
         --machines=3 \
         --duration=70 \
         --mothership-bin="${MOTHERSHIP_BIN}" \
         --expect-master-available=1 \
         --require-brain-log-substring="neuron updateOS started" \
         --require-brain-log-substring="os update command deadline"
}

run_missing_policy_case()
{
   timeout --preserve-status -k 8s "${PRODIGY_DEV_OS_UPDATE_CASE_TIMEOUT_SECONDS:-260}s" \
   env \
      PRODIGY_DEV_ALLOW_BPF_ATTACH="${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}" \
      PRODIGY_DEV_TEST_OS_RELEASE_ID="portablelinux" \
      PRODIGY_DEV_TEST_OS_RELEASE_VERSION_ID="1" \
      PRODIGY_DEV_CONFIGURE_TARGET_OS_ID="ubuntu" \
      PRODIGY_DEV_CONFIGURE_TARGET_OS_VERSION_ID="24.04" \
      PRODIGY_DEV_CONFIGURE_OS_UPDATE_COMMAND="true" \
      PRODIGY_DEV_CONFIGURE_OS_UPDATES_ENABLED=1 \
      PRODIGY_DEV_CONFIGURE_MAX_OS_DRAINS=1 \
      PRODIGY_DEV_CONFIGURE_MACHINE_UPDATE_CADENCE_MINS=1 \
      PRODIGY_DEV_OS_UPDATE_CADENCE_MS=1000 \
      "${HARNESS}" "${PRODIGY_BIN}" \
         --brains=3 \
         --machines=3 \
         --duration=45 \
         --mothership-bin="${MOTHERSHIP_BIN}" \
         --expect-master-available=1 \
         --expect-peer-recovery=1 \
         --expect-full-brain-registration=1 \
         --require-brain-log-substring="coverage=0"
}

run_case "successful_reimage_rollout" run_successful_reimage_case "successful_reimage_rollout" "2"

run_case "successful_reimage_with_master_crash" run_successful_reimage_case "successful_reimage_with_master_crash" "3" \
   --fault-mode=crash \
   --fault-targets=master \
   --fault-start=6 \
   --fault-duration=4 \
   --post-fault-window=25 \
   --expect-master-change=1 \
   --expect-peer-recovery=1

run_case "dead_update_command_deadline_fail_closed" run_dead_command_case
run_case "missing_distro_policy_disables_all_updates" run_missing_policy_case

echo "OS_UPDATE_REIMAGE_RUNTIME_SUMMARY total=${total_cases} failed=${failed_cases}"

if [[ "${failed_cases}" -ne 0 ]]
then
   exit 1
fi

echo "OS_UPDATE_REIMAGE_MATRIX_PASS"
