#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
PINGPONG_BIN="${3:-}"
PINGPONG_ALT_BIN="${4:-}"
PINGPONG_NOPORT_BIN="${5:-}"
MODE="smoke"

if [[ -n "${PINGPONG_ALT_BIN}" && "${PINGPONG_ALT_BIN}" != --* ]]
then
   shift 4 || true
else
   PINGPONG_ALT_BIN="${PINGPONG_BIN}"
   shift 3 || true
fi

if [[ $# -gt 0 && "${1:-}" != --* ]]
then
   PINGPONG_NOPORT_BIN="$1"
   shift
else
   PINGPONG_NOPORT_BIN="${PINGPONG_ALT_BIN}"
fi

while [[ $# -gt 0 ]]
do
   case "$1" in
      --mode=*)
         MODE="${1#*=}"
         ;;
      *)
         echo "unknown argument: $1"
         exit 2
         ;;
   esac
   shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"

if [[ "${MODE}" != "smoke" && "${MODE}" != "ci" ]]
then
   echo "FAIL: --mode must be smoke or ci"
   exit 1
fi

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${PINGPONG_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_pingpong_container [/path/to/prodigy_pingpong_container_alt] [/path/to/prodigy_pingpong_container_noport] [--mode=smoke|ci]"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for netns deployments matrix"
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

if [[ ! -x "${PINGPONG_ALT_BIN}" ]]
then
   echo "FAIL: pingpong alt container binary is not executable: ${PINGPONG_ALT_BIN}"
   exit 1
fi

if [[ ! -x "${PINGPONG_NOPORT_BIN}" ]]
then
   echo "FAIL: pingpong noport container binary is not executable: ${PINGPONG_NOPORT_BIN}"
   exit 1
fi

if [[ ! -x "${HARNESS}" ]]
then
   echo "FAIL: harness is not executable: ${HARNESS}"
   exit 1
fi

deps=(awk btrfs mkfs.btrfs mount umount stat zstd ldd install timeout ip rg)
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
PINGPONG_ALT_BIN="$(readlink -f "${PINGPONG_ALT_BIN}" 2>/dev/null || printf '%s' "${PINGPONG_ALT_BIN}")"
PINGPONG_NOPORT_BIN="$(readlink -f "${PINGPONG_NOPORT_BIN}" 2>/dev/null || printf '%s' "${PINGPONG_NOPORT_BIN}")"

tmpdir="$(mktemp -d)"
export TMPDIR="${tmpdir}"
containers_dir_created=0
containers_mount_created=0
containers_loop_image=""
host_pingpong_path="/root/pingpong_container"
host_pingpong_backup=""
active_subvol=""
failed_cases=0
total_cases=0

cleanup()
{
   set +e

   if [[ -n "${active_subvol}" && -e "${active_subvol}" ]]
   then
      btrfs property set -f "${active_subvol}" ro false >/dev/null 2>&1 || true
      btrfs subvolume delete "${active_subvol}" >/dev/null 2>&1 || true
   fi

   if [[ -n "${host_pingpong_backup}" && -f "${host_pingpong_backup}" ]]
   then
      install -m 0755 "${host_pingpong_backup}" "${host_pingpong_path}" >/dev/null 2>&1 || true
   else
      rm -f "${host_pingpong_path}" >/dev/null 2>&1 || true
   fi

   if [[ "${containers_mount_created}" -eq 1 ]]
   then
      umount /containers >/dev/null 2>&1 || true
   fi

   if [[ "${containers_dir_created}" -eq 1 ]]
   then
      rmdir /containers >/dev/null 2>&1 || true
   fi

   if [[ "${failed_cases}" -ne 0 ]]
   then
      echo "DEBUG: preserved tmpdir ${tmpdir}"
   else
      rm -rf "${tmpdir}"
   fi
}
trap cleanup EXIT

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
   truncate -s 2G "${containers_loop_image}"
   mkfs.btrfs -f "${containers_loop_image}" >/dev/null
   mount -o loop "${containers_loop_image}" /containers
   containers_mount_created=1
fi

mkdir -p /containers/store /containers/storage

if [[ -e "${host_pingpong_path}" ]]
then
   host_pingpong_backup="${tmpdir}/pingpong_container.host.backup"
   cp -f "${host_pingpong_path}" "${host_pingpong_backup}"
fi
install -m 0755 "${PINGPONG_BIN}" "${host_pingpong_path}"

next_version_id()
{
   local version_id=$(( ($(date +%s%N) & 281474976710655) ))
   if [[ "${version_id}" -le 0 ]]
   then
      version_id=1
   fi
   echo "${version_id}"
}

subvol_id_for()
{
   local app_id="$1"
   local version_id="$2"
   local deployment_id=$(( (app_id << 48) | version_id ))
   echo "${deployment_id}"
}

copy_binary_and_libs_into_subvol()
{
   local binary_path="$1"
   local subvol_root="$2"
   local install_path="${3:-/root/pingpong_container}"

   mkdir -p "${subvol_root}$(dirname "${install_path}")" "${subvol_root}/etc"
   install -m 0755 "${binary_path}" "${subvol_root}${install_path}"

   while IFS= read -r libpath
   do
      if [[ -z "${libpath}" ]]
      then
         continue
      fi

      if [[ -e "${libpath}" ]]
      then
         cp -aL --parents "${libpath}" "${subvol_root}"
      fi
   done < <(
      ldd "${binary_path}" | awk '
         /=>/ {
            if ($3 ~ /^\//) print $3;
         }
         /^[[:space:]]*\// {
            print $1;
         }
      ' | sort -u
   )
}

build_blob_with_binary()
{
   local out_blob="$1"
   local app_id="$2"
   local version_id="$3"
   local binary_path="$4"

   local deployment_id
   deployment_id="$(subvol_id_for "${app_id}" "${version_id}")"
   active_subvol="/containers/${deployment_id}"

   btrfs subvolume create "${active_subvol}" >/dev/null
   copy_binary_and_libs_into_subvol "${binary_path}" "${active_subvol}" "/root/pingpong_container"
   btrfs property set -f "${active_subvol}" ro true >/dev/null
   btrfs send "${active_subvol}" | zstd -19 -T0 -q -o "${out_blob}"
   btrfs property set -f "${active_subvol}" ro false >/dev/null
   btrfs subvolume delete "${active_subvol}" >/dev/null
   active_subvol=""
}

build_blob_missing_binary()
{
   local out_blob="$1"
   local app_id="$2"
   local version_id="$3"

   local deployment_id
   deployment_id="$(subvol_id_for "${app_id}" "${version_id}")"
   active_subvol="/containers/${deployment_id}"

   btrfs subvolume create "${active_subvol}" >/dev/null
   mkdir -p "${active_subvol}/root" "${active_subvol}/etc"
   btrfs property set -f "${active_subvol}" ro true >/dev/null
   btrfs send "${active_subvol}" | zstd -19 -T0 -q -o "${out_blob}"
   btrfs property set -f "${active_subvol}" ro false >/dev/null
   btrfs subvolume delete "${active_subvol}" >/dev/null
   active_subvol=""
}

write_stateless_plan()
{
   local out_plan="$1"
   local app_id="$2"
   local version_id="$3"
   local nbase="$4"
   local cores="$5"
   local memory_mb="$6"
   local storage_mb="$7"
   local max_per_rack="$8"
   local max_per_machine="$9"
   local canary_count="${10}"
   local canary_minutes="${11}"
   local use_host_ns="${12}"
   local moveable="${13}"

   cat > "${out_plan}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${app_id},
    "versionID": ${version_id},
    "filesystemMB": 64,
    "storageMB": ${storage_mb},
    "memoryMB": ${memory_mb},
    "nLogicalCores": ${cores},
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
    "sTilKillable": 30
  },
  "minimumSubscriberCapacity": 1024,
  "isStateful": false,
  "canaryCount": ${canary_count},
  "canariesMustLiveForMinutes": ${canary_minutes},
  "stateless": {
    "nBase": ${nbase},
    "maxPerRackRatio": ${max_per_rack},
    "maxPerMachineRatio": ${max_per_machine},
    "moveableDuringCompaction": ${moveable}
  },
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF
}

write_stateful_plan()
{
   local out_plan="$1"
   local app_id="$2"
   local version_id="$3"
   local cores="$4"
   local memory_mb="$5"
   local storage_mb="$6"
   local canary_count="$7"
   local canary_minutes="$8"
   local use_host_ns="$9"
   local allow_update="${10}"

   local client_prefix=$((app_id * 100 + 1))
   local sibling_prefix=$((app_id * 100 + 2))
   local cousin_prefix=$((app_id * 100 + 3))
   local seeding_prefix=$((app_id * 100 + 4))
   local sharding_prefix=$((app_id * 100 + 5))

   cat > "${out_plan}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateful",
    "applicationID": ${app_id},
    "versionID": ${version_id},
    "filesystemMB": 64,
    "storageMB": ${storage_mb},
    "memoryMB": ${memory_mb},
    "nLogicalCores": ${cores},
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
    "sTilKillable": 30
  },
  "minimumSubscriberCapacity": 1024,
  "isStateful": true,
  "canaryCount": ${canary_count},
  "canariesMustLiveForMinutes": ${canary_minutes},
  "stateful": {
    "clientPrefix": ${client_prefix},
    "siblingPrefix": ${sibling_prefix},
    "cousinPrefix": ${cousin_prefix},
    "seedingPrefix": ${seeding_prefix},
    "shardingPrefix": ${sharding_prefix},
    "allowUpdateInPlace": ${allow_update},
    "seedingAlways": false,
    "neverShard": false,
    "allMasters": false
  },
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF
}

run_harness_case()
{
   local case_name="$1"
   local duration_s="$2"
   shift 2

   total_cases=$((total_cases + 1))

   local case_log="${tmpdir}/${case_name}.harness.log"
   echo "=== DEPLOYMENTS_CASE ${case_name} ==="

   if "${HARNESS}" "${PRODIGY_BIN}" \
      --brains=3 \
      --duration="${duration_s}" \
      --mothership-bin="${MOTHERSHIP_BIN}" \
      "$@" \
      >"${case_log}" 2>&1
   then
      echo "CASE_PASS ${case_name}"
   else
      failed_cases=$((failed_cases + 1))
      echo "CASE_FAIL ${case_name}"
      sed -n '1,260p' "${case_log}"
   fi
}

# Case 1: stateless baseline deploy + communication smoke.
case1_version="$(next_version_id)"
case1_plan="${tmpdir}/case1.stateless_baseline.plan.json"
case1_blob="${tmpdir}/case1.stateless_baseline.container.zst"
write_stateless_plan "${case1_plan}" 6 "${case1_version}" 2 1 256 64 "1.0" "0.5" 0 1 true true
build_blob_with_binary "${case1_blob}" 6 "${case1_version}" "${PINGPONG_BIN}"
run_harness_case "stateless_baseline_smoke" 65 \
   --deploy-plan-json="${case1_plan}" \
   --deploy-container-zstd="${case1_blob}" \
   --deploy-ping-port=19090 \
   --deploy-ping-payload=ping \
   --deploy-ping-expect=pong \
   --deploy-report-application="Nametag" \
   --deploy-report-min-healthy=1 \
   --deploy-report-min-target=2 \
   --deploy-report-max-target-min=2

# Case 2: stateful baseline deploy + communication smoke.
case2_version="$(next_version_id)"
case2_plan="${tmpdir}/case2.stateful_baseline.plan.json"
case2_blob="${tmpdir}/case2.stateful_baseline.container.zst"
write_stateful_plan "${case2_plan}" 3 "${case2_version}" 1 256 64 0 1 true true
build_blob_with_binary "${case2_blob}" 3 "${case2_version}" "${PINGPONG_BIN}"
run_harness_case "stateful_baseline_smoke" 80 \
   --deploy-plan-json="${case2_plan}" \
   --deploy-container-zstd="${case2_blob}" \
   --deploy-ping-port=19090 \
   --deploy-ping-payload=ping \
   --deploy-ping-expect=pong \
   --deploy-report-application="Hot" \
   --deploy-report-min-healthy=3 \
   --deploy-report-min-target=3 \
   --deploy-report-max-target-min=3

# Case 3: stateless good upgrade rollout.
case3_v1="$(next_version_id)"
case3_v2="$(next_version_id)"
case3_plan_v1="${tmpdir}/case3.stateless_upgrade_good.v1.plan.json"
case3_plan_v2="${tmpdir}/case3.stateless_upgrade_good.v2.plan.json"
case3_blob_v1="${tmpdir}/case3.stateless_upgrade_good.v1.container.zst"
case3_blob_v2="${tmpdir}/case3.stateless_upgrade_good.v2.container.zst"
write_stateless_plan "${case3_plan_v1}" 6 "${case3_v1}" 1 1 256 64 "1.0" "1.0" 0 1 true true
write_stateless_plan "${case3_plan_v2}" 6 "${case3_v2}" 1 1 256 64 "1.0" "1.0" 1 1 true true
build_blob_with_binary "${case3_blob_v1}" 6 "${case3_v1}" "${PINGPONG_BIN}"
build_blob_with_binary "${case3_blob_v2}" 6 "${case3_v2}" "${PINGPONG_ALT_BIN}"
run_harness_case "stateless_upgrade_rollout_good" 120 \
   --deploy-plan-json="${case3_plan_v1}" \
   --deploy-container-zstd="${case3_blob_v1}" \
   --deploy-second-plan-json="${case3_plan_v2}" \
   --deploy-second-container-zstd="${case3_blob_v2}" \
   --deploy-second-start=3 \
   --deploy-skip-probe=1 \
   --deploy-report-application="Nametag" \
   --deploy-report-min-healthy=1 \
   --deploy-report-min-target=1 \
   --deploy-report-max-target-min=2 \
   --deploy-report-final-healthy-max=1 \
   --deploy-report-final-target-max=1

# Case 4: stateful good upgrade rollout.
case4_v1="$(next_version_id)"
case4_v2="$(next_version_id)"
case4_plan_v1="${tmpdir}/case4.stateful_upgrade_good.v1.plan.json"
case4_plan_v2="${tmpdir}/case4.stateful_upgrade_good.v2.plan.json"
case4_blob_v1="${tmpdir}/case4.stateful_upgrade_good.v1.container.zst"
case4_blob_v2="${tmpdir}/case4.stateful_upgrade_good.v2.container.zst"
write_stateful_plan "${case4_plan_v1}" 3 "${case4_v1}" 1 256 64 0 1 true true
write_stateful_plan "${case4_plan_v2}" 3 "${case4_v2}" 1 256 64 0 1 true true
build_blob_with_binary "${case4_blob_v1}" 3 "${case4_v1}" "${PINGPONG_BIN}"
build_blob_with_binary "${case4_blob_v2}" 3 "${case4_v2}" "${PINGPONG_ALT_BIN}"
run_harness_case "stateful_upgrade_rollout_good" 140 \
   --deploy-plan-json="${case4_plan_v1}" \
   --deploy-container-zstd="${case4_blob_v1}" \
   --deploy-second-plan-json="${case4_plan_v2}" \
   --deploy-second-container-zstd="${case4_blob_v2}" \
   --deploy-second-start=25 \
   --deploy-skip-probe=1 \
   --deploy-report-application="Hot" \
   --deploy-report-min-healthy=3 \
   --deploy-report-min-target=3 \
   --deploy-report-max-target-min=3

# Case 5: stateless bad upgrade rollback (second deploy accepted, canary fails, previous remains).
case5_v1="$(next_version_id)"
case5_v2="$(next_version_id)"
case5_plan_v1="${tmpdir}/case5.stateless_upgrade_bad.v1.plan.json"
case5_plan_v2="${tmpdir}/case5.stateless_upgrade_bad.v2.plan.json"
case5_blob_v1="${tmpdir}/case5.stateless_upgrade_bad.v1.container.zst"
case5_blob_v2_bad="${tmpdir}/case5.stateless_upgrade_bad.v2.bad.container.zst"
write_stateless_plan "${case5_plan_v1}" 6 "${case5_v1}" 1 1 256 64 "1.0" "1.0" 0 1 true true
write_stateless_plan "${case5_plan_v2}" 6 "${case5_v2}" 1 1 256 64 "1.0" "1.0" 1 1 true true
build_blob_with_binary "${case5_blob_v1}" 6 "${case5_v1}" "${PINGPONG_BIN}"
build_blob_missing_binary "${case5_blob_v2_bad}" 6 "${case5_v2}"
run_harness_case "stateless_upgrade_rollback_bad" 150 \
   --deploy-plan-json="${case5_plan_v1}" \
   --deploy-container-zstd="${case5_blob_v1}" \
   --deploy-second-plan-json="${case5_plan_v2}" \
   --deploy-second-container-zstd="${case5_blob_v2_bad}" \
   --deploy-second-start=25 \
   --deploy-skip-probe=1 \
   --deploy-report-application="Nametag" \
   --deploy-report-min-healthy=1 \
   --deploy-report-min-target=1 \
   --deploy-report-max-target-min=2 \
   --deploy-report-final-healthy-max=1 \
   --deploy-report-final-target-max=1

# Case 6: stateful bad upgrade rollback.
case6_v1="$(next_version_id)"
case6_v2="$(next_version_id)"
case6_plan_v1="${tmpdir}/case6.stateful_upgrade_bad.v1.plan.json"
case6_plan_v2="${tmpdir}/case6.stateful_upgrade_bad.v2.plan.json"
case6_blob_v1="${tmpdir}/case6.stateful_upgrade_bad.v1.container.zst"
case6_blob_v2_bad="${tmpdir}/case6.stateful_upgrade_bad.v2.bad.container.zst"
write_stateful_plan "${case6_plan_v1}" 3 "${case6_v1}" 1 256 64 0 1 true true
write_stateful_plan "${case6_plan_v2}" 3 "${case6_v2}" 1 256 64 1 1 true true
build_blob_with_binary "${case6_blob_v1}" 3 "${case6_v1}" "${PINGPONG_BIN}"
build_blob_missing_binary "${case6_blob_v2_bad}" 3 "${case6_v2}"
run_harness_case "stateful_upgrade_rollback_bad" 170 \
   --deploy-plan-json="${case6_plan_v1}" \
   --deploy-container-zstd="${case6_blob_v1}" \
   --deploy-second-plan-json="${case6_plan_v2}" \
   --deploy-second-container-zstd="${case6_blob_v2_bad}" \
   --deploy-second-start=25 \
   --deploy-second-expect-accept=0 \
   --deploy-skip-probe=1

# Case 7: stateless scarcity forces machine-request path.
case7_version="$(next_version_id)"
case7_plan="${tmpdir}/case7.stateless_scarcity.plan.json"
case7_blob="${tmpdir}/case7.stateless_scarcity.container.zst"
write_stateless_plan "${case7_plan}" 6 "${case7_version}" 8 16 256 64 "1.0" "1.0" 0 1 false true
build_blob_with_binary "${case7_blob}" 6 "${case7_version}" "${PINGPONG_BIN}"
run_harness_case "stateless_scarcity_requests_machines" 70 \
   --deploy-plan-json="${case7_plan}" \
   --deploy-container-zstd="${case7_blob}" \
   --deploy-expect-accept=0 \
   --deploy-expect-text="can only fit" \
   --deploy-skip-probe=1

# Case 8: stateful scarcity forces machine-request path.
case8_version="$(next_version_id)"
case8_plan="${tmpdir}/case8.stateful_scarcity.plan.json"
case8_blob="${tmpdir}/case8.stateful_scarcity.container.zst"
write_stateful_plan "${case8_plan}" 3 "${case8_version}" 16 256 64 0 1 false true
build_blob_with_binary "${case8_blob}" 3 "${case8_version}" "${PINGPONG_BIN}"
run_harness_case "stateful_scarcity_requests_machines" 90 \
   --deploy-plan-json="${case8_plan}" \
   --deploy-container-zstd="${case8_blob}" \
   --deploy-expect-accept=0 \
   --deploy-expect-text="can only fit" \
   --deploy-skip-probe=1

if [[ "${MODE}" == "ci" ]]
then
   # Case 9: compaction path for a stateless target.
   case9_a_version="$(next_version_id)"
   case9_b_version="$(next_version_id)"
   case9_plan_a="${tmpdir}/case9.compaction_stateless.a.plan.json"
   case9_plan_b="${tmpdir}/case9.compaction_stateless.b.plan.json"
   case9_blob_a="${tmpdir}/case9.compaction_stateless.a.container.zst"
   case9_blob_b="${tmpdir}/case9.compaction_stateless.b.container.zst"
   write_stateless_plan "${case9_plan_a}" 6 "${case9_a_version}" 3 2 256 64 "1.0" "0.66" 0 1 true true
   write_stateless_plan "${case9_plan_b}" 5 "${case9_b_version}" 1 2 256 64 "1.0" "1.0" 0 1 true true
   build_blob_with_binary "${case9_blob_a}" 6 "${case9_a_version}" "${PINGPONG_NOPORT_BIN}"
   build_blob_with_binary "${case9_blob_b}" 5 "${case9_b_version}" "${PINGPONG_NOPORT_BIN}"
   run_harness_case "stateless_compaction_path" 110 \
      --deploy-plan-json="${case9_plan_a}" \
      --deploy-container-zstd="${case9_blob_a}" \
      --deploy-second-plan-json="${case9_plan_b}" \
      --deploy-second-container-zstd="${case9_blob_b}" \
      --deploy-second-start=3 \
      --deploy-skip-probe=1 \
      --deploy-report-application="Radar" \
      --deploy-report-min-healthy=1 \
      --deploy-report-min-target=1 \
      --deploy-report-max-target-min=1

   # Case 10: compaction path for a stateful target.
   case10_a_version="$(next_version_id)"
   case10_b_version="$(next_version_id)"
   case10_plan_a="${tmpdir}/case10.compaction_stateful.a.plan.json"
   case10_plan_b="${tmpdir}/case10.compaction_stateful.b.plan.json"
   case10_blob_a="${tmpdir}/case10.compaction_stateful.a.container.zst"
   case10_blob_b="${tmpdir}/case10.compaction_stateful.b.container.zst"
   write_stateless_plan "${case10_plan_a}" 6 "${case10_a_version}" 3 2 256 64 "1.0" "0.66" 0 1 true true
   write_stateful_plan "${case10_plan_b}" 3 "${case10_b_version}" 2 256 64 0 1 true true
   build_blob_with_binary "${case10_blob_a}" 6 "${case10_a_version}" "${PINGPONG_NOPORT_BIN}"
   build_blob_with_binary "${case10_blob_b}" 3 "${case10_b_version}" "${PINGPONG_NOPORT_BIN}"
   run_harness_case "stateful_compaction_path" 130 \
      --deploy-plan-json="${case10_plan_a}" \
      --deploy-container-zstd="${case10_blob_a}" \
      --deploy-second-plan-json="${case10_plan_b}" \
      --deploy-second-container-zstd="${case10_blob_b}" \
      --deploy-second-start=3 \
      --deploy-skip-probe=1 \
      --deploy-report-application="Hot" \
      --deploy-report-min-healthy=1 \
      --deploy-report-min-target=3 \
      --deploy-report-max-target-min=3

   # Case 11: stateful good upgrade with update-in-place disabled.
   case11_v1="$(next_version_id)"
   case11_v2="$(next_version_id)"
   case11_plan_v1="${tmpdir}/case11.stateful_upgrade_no_inplace.v1.plan.json"
   case11_plan_v2="${tmpdir}/case11.stateful_upgrade_no_inplace.v2.plan.json"
   case11_blob_v1="${tmpdir}/case11.stateful_upgrade_no_inplace.v1.container.zst"
   case11_blob_v2="${tmpdir}/case11.stateful_upgrade_no_inplace.v2.container.zst"
   write_stateful_plan "${case11_plan_v1}" 3 "${case11_v1}" 1 256 64 0 1 true true
   write_stateful_plan "${case11_plan_v2}" 3 "${case11_v2}" 1 256 64 0 1 true false
   build_blob_with_binary "${case11_blob_v1}" 3 "${case11_v1}" "${PINGPONG_BIN}"
   build_blob_with_binary "${case11_blob_v2}" 3 "${case11_v2}" "${PINGPONG_ALT_BIN}"
   run_harness_case "stateful_upgrade_rollout_no_inplace" 170 \
      --deploy-plan-json="${case11_plan_v1}" \
      --deploy-container-zstd="${case11_blob_v1}" \
      --deploy-second-plan-json="${case11_plan_v2}" \
      --deploy-second-container-zstd="${case11_blob_v2}" \
      --deploy-second-start=25 \
      --deploy-skip-probe=1 \
      --deploy-report-application="Hot" \
      --deploy-report-min-healthy=3 \
      --deploy-report-min-target=3 \
      --deploy-report-max-target-min=3

   # Case 12: stateless compaction disabled by moveableDuringCompaction=false.
   case12_a_version="$(next_version_id)"
   case12_b_version="$(next_version_id)"
   case12_plan_a="${tmpdir}/case12.compaction_blocked_stateless.a.plan.json"
   case12_plan_b="${tmpdir}/case12.compaction_blocked_stateless.b.plan.json"
   case12_blob_a="${tmpdir}/case12.compaction_blocked_stateless.a.container.zst"
   case12_blob_b="${tmpdir}/case12.compaction_blocked_stateless.b.container.zst"
   write_stateless_plan "${case12_plan_a}" 6 "${case12_a_version}" 6 4 256 64 "1.0" "0.66" 0 1 true false
   write_stateless_plan "${case12_plan_b}" 5 "${case12_b_version}" 1 2 256 64 "1.0" "1.0" 0 1 true true
   build_blob_with_binary "${case12_blob_a}" 6 "${case12_a_version}" "${PINGPONG_NOPORT_BIN}"
   build_blob_with_binary "${case12_blob_b}" 5 "${case12_b_version}" "${PINGPONG_ALT_BIN}"
   run_harness_case "stateless_compaction_blocked_nonmoveable" 120 \
      --deploy-plan-json="${case12_plan_a}" \
      --deploy-container-zstd="${case12_blob_a}" \
      --deploy-second-plan-json="${case12_plan_b}" \
      --deploy-second-container-zstd="${case12_blob_b}" \
      --deploy-second-start=3 \
      --deploy-second-expect-accept=0 \
      --deploy-second-expect-text="can only fit" \
      --deploy-skip-probe=1

   # Case 13: stateless machine lifecycle (deployed host crash -> drain + reschedule).
   case13_version="$(next_version_id)"
   case13_plan="${tmpdir}/case13.lifecycle_stateless_host_crash.plan.json"
   case13_blob="${tmpdir}/case13.lifecycle_stateless_host_crash.container.zst"
write_stateless_plan "${case13_plan}" 6 "${case13_version}" 2 1 256 64 "1.0" "0.5" 0 1 true true
   build_blob_with_binary "${case13_blob}" 6 "${case13_version}" "${PINGPONG_BIN}"
run_harness_case "stateless_machine_lifecycle_host_crash" 100 \
   --fault-mode=crash \
   --fault-targets=deployed \
   --fault-start=2 \
      --fault-duration=0 \
      --post-fault-window=40 \
      --expect-peer-recovery=1 \
      --deploy-plan-json="${case13_plan}" \
      --deploy-container-zstd="${case13_blob}" \
      --deploy-ping-port=19090 \
      --deploy-ping-payload=ping \
      --deploy-ping-expect=pong \
      --deploy-ping-after-fault=1 \
   --deploy-report-application="Nametag" \
   --deploy-report-min-healthy=1 \
   --deploy-report-min-target=2 \
   --deploy-report-max-target-min=2

   # Case 14: stateful machine lifecycle (deployed host crash -> drain + reschedule).
   case14_version="$(next_version_id)"
   case14_plan="${tmpdir}/case14.lifecycle_stateful_host_crash.plan.json"
   case14_blob="${tmpdir}/case14.lifecycle_stateful_host_crash.container.zst"
   write_stateful_plan "${case14_plan}" 3 "${case14_version}" 1 256 64 0 1 true true
   build_blob_with_binary "${case14_blob}" 3 "${case14_version}" "${PINGPONG_BIN}"
   run_harness_case "stateful_machine_lifecycle_host_crash" 120 \
   --fault-mode=crash \
   --fault-targets=deployed \
   --fault-start=2 \
      --fault-duration=0 \
      --post-fault-window=40 \
      --expect-peer-recovery=1 \
      --deploy-plan-json="${case14_plan}" \
      --deploy-container-zstd="${case14_blob}" \
      --deploy-ping-port=19090 \
      --deploy-ping-payload=ping \
      --deploy-ping-expect=pong \
      --deploy-ping-after-fault=1 \
   --deploy-report-application="Hot" \
   --deploy-report-min-healthy=1 \
   --deploy-report-min-target=3 \
   --deploy-report-max-target-min=3

   # Case 15: cluster add-machine pressure path (scale-up request exceeds current cluster capacity).
   case15_v1="$(next_version_id)"
   case15_v2="$(next_version_id)"
   case15_plan_v1="${tmpdir}/case15.cluster_add_machine_request.v1.plan.json"
   case15_plan_v2="${tmpdir}/case15.cluster_add_machine_request.v2.plan.json"
   case15_blob_v1="${tmpdir}/case15.cluster_add_machine_request.v1.container.zst"
   case15_blob_v2="${tmpdir}/case15.cluster_add_machine_request.v2.container.zst"
   write_stateless_plan "${case15_plan_v1}" 6 "${case15_v1}" 1 1 256 64 "1.0" "1.0" 0 1 true true
   write_stateless_plan "${case15_plan_v2}" 6 "${case15_v2}" 8 16 256 64 "1.0" "1.0" 0 1 true true
   build_blob_with_binary "${case15_blob_v1}" 6 "${case15_v1}" "${PINGPONG_BIN}"
   build_blob_with_binary "${case15_blob_v2}" 6 "${case15_v2}" "${PINGPONG_ALT_BIN}"
   run_harness_case "cluster_add_machine_request_stateless" 140 \
      --deploy-plan-json="${case15_plan_v1}" \
      --deploy-container-zstd="${case15_blob_v1}" \
      --deploy-second-plan-json="${case15_plan_v2}" \
      --deploy-second-container-zstd="${case15_blob_v2}" \
      --deploy-second-start=10 \
      --deploy-second-expect-accept=0 \
      --deploy-second-expect-text="can only fit" \
      --deploy-ping-port=19090 \
      --deploy-ping-payload=ping \
      --deploy-ping-expect=pong \
      --deploy-report-application="Nametag" \
      --deploy-report-min-healthy=1 \
      --deploy-report-min-target=1 \
      --deploy-report-max-target-min=1 \
      --deploy-report-final-target-max=1

   # Case 16: cluster remove-machine path (deployed host crash drains and reschedules workload).
   case16_version="$(next_version_id)"
   case16_plan="${tmpdir}/case16.cluster_remove_machine_stateless.plan.json"
   case16_blob="${tmpdir}/case16.cluster_remove_machine_stateless.container.zst"
   write_stateless_plan "${case16_plan}" 6 "${case16_version}" 2 1 256 64 "1.0" "0.5" 0 1 true true
   build_blob_with_binary "${case16_blob}" 6 "${case16_version}" "${PINGPONG_BIN}"
   run_harness_case "cluster_remove_machine_stateless_host_crash" 110 \
      --fault-mode=crash \
      --fault-targets=deployed \
      --fault-start=2 \
      --fault-duration=0 \
      --post-fault-window=45 \
      --expect-peer-recovery=1 \
      --deploy-plan-json="${case16_plan}" \
      --deploy-container-zstd="${case16_blob}" \
      --deploy-ping-port=19090 \
      --deploy-ping-payload=ping \
      --deploy-ping-expect=pong \
      --deploy-ping-after-fault=1 \
      --deploy-report-application="Nametag" \
      --deploy-report-min-healthy=1 \
      --deploy-report-min-target=2 \
      --deploy-report-max-target-min=2
fi

if [[ "${failed_cases}" -ne 0 ]]
then
   echo "FAIL: deployments matrix had ${failed_cases}/${total_cases} failing cases"
   exit 1
fi

echo "PASS: deployments matrix succeeded (${total_cases} cases, mode=${MODE})"
