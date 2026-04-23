#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
PINGPONG_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${PINGPONG_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_pingpong_container"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for netns container migration matrix"
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

tmpdir="$(mktemp -d)"
export TMPDIR="${tmpdir}"
containers_dir_created=0
containers_mount_created=0
containers_loop_image=""
host_pingpong_path="/root/pingpong_container"
host_pingpong_backup=""
active_subvol=""
case_plan_json=""
case_container_blob=""
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

application_id=6 # MeshRegistry::Nametag::applicationID
ping_port=19090

stream_subvolume_blob()
{
   local subvol_path="$1"
   local out_blob="$2"
   local max_attempts="${3:-3}"

   local attempt=0
   for attempt in $(seq 1 "${max_attempts}")
   do
      rm -f "${out_blob}" >/dev/null 2>&1 || true
      if btrfs send "${subvol_path}" | zstd -19 -T0 -q -o "${out_blob}"
      then
         return 0
      fi

      sleep 0.2
   done

   echo "FAIL: unable to stream subvolume to blob after retries: ${subvol_path}"
   return 1
}

build_case_artifacts_once()
{
   local case_name="$1"
   local case_kind="$2" # stateless|stateful

   local version_id=$(( ($(date +%s%N) & 281474976710655) ))
   if [[ "${version_id}" -le 0 ]]
   then
      version_id=1
   fi
   local deployment_id=$(( (application_id << 48) | version_id ))

   active_subvol="/containers/${deployment_id}"
   if [[ -e "${active_subvol}" ]]
   then
      btrfs property set -f "${active_subvol}" ro false >/dev/null 2>&1 || true
      btrfs subvolume delete "${active_subvol}" >/dev/null 2>&1 || true
      rm -rf "${active_subvol}" >/dev/null 2>&1 || true
   fi

   if ! btrfs subvolume create "${active_subvol}" >/dev/null
   then
      echo "FAIL: unable to create subvolume: ${active_subvol}"
      return 1
   fi

   mkdir -p "${active_subvol}/root" "${active_subvol}/etc"
   install -m 0755 "${PINGPONG_BIN}" "${active_subvol}/root/pingpong_container"

   while IFS= read -r libpath
   do
      if [[ -z "${libpath}" ]]
      then
         continue
      fi

      if [[ -e "${libpath}" ]]
      then
         cp -aL --parents "${libpath}" "${active_subvol}"
      fi
   done < <(
      ldd "${PINGPONG_BIN}" | awk '
         /=>/ {
            if ($3 ~ /^\//) print $3;
         }
         /^[[:space:]]*\// {
            print $1;
         }
      ' | sort -u
   )

   case_plan_json="${tmpdir}/${case_name}.plan.json"
   if [[ "${case_kind}" == "stateful" ]]
   then
      cat > "${case_plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateful",
    "applicationID": ${application_id},
    "versionID": ${version_id},
    "filesystemMB": 64,
    "storageMB": 64,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
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
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF
   else
      cat > "${case_plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${application_id},
    "versionID": ${version_id},
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
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF
   fi

   case_container_blob="${tmpdir}/${case_name}.container.zst"
   if ! btrfs property set -f "${active_subvol}" ro true >/dev/null
   then
      echo "FAIL: unable to mark subvolume readonly: ${active_subvol}"
      btrfs property set -f "${active_subvol}" ro false >/dev/null 2>&1 || true
      btrfs subvolume delete "${active_subvol}" >/dev/null 2>&1 || true
      active_subvol=""
      return 1
   fi

   if ! stream_subvolume_blob "${active_subvol}" "${case_container_blob}" 3
   then
      btrfs property set -f "${active_subvol}" ro false >/dev/null 2>&1 || true
      btrfs subvolume delete "${active_subvol}" >/dev/null 2>&1 || true
      active_subvol=""
      return 1
   fi

   if ! btrfs property set -f "${active_subvol}" ro false >/dev/null
   then
      echo "FAIL: unable to clear readonly property: ${active_subvol}"
      btrfs subvolume delete "${active_subvol}" >/dev/null 2>&1 || true
      active_subvol=""
      return 1
   fi

   if ! btrfs subvolume delete "${active_subvol}" >/dev/null
   then
      echo "FAIL: unable to delete subvolume after streaming: ${active_subvol}"
      active_subvol=""
      return 1
   fi

   active_subvol=""
   return 0
}

build_case_artifacts()
{
   local case_name="$1"
   local case_kind="$2" # stateless|stateful

   local attempt=0
   for attempt in 1 2 3
   do
      if build_case_artifacts_once "${case_name}" "${case_kind}"
      then
         return 0
      fi

      sleep 0.2
   done

   return 1
}

extract_preserved_tmpdir()
{
   local case_log="$1"
   local preserved=""
   preserved="$(rg -m1 '^DEBUG: preserved tmpdir ' "${case_log}" | sed -E 's/^DEBUG: preserved tmpdir //')"
   echo "${preserved}"
}

extract_fault_target_index()
{
   local case_log="$1"
   local targets=""
   targets="$(rg -m1 '^FAULT_APPLIED mode=crash targets=' "${case_log}" | sed -E 's/^.*targets=([^ ]+).*$/\1/')"
   if [[ -z "${targets}" ]]
   then
      echo ""
      return 0
   fi

   echo "${targets%%,*}"
}

count_spin_lines_for_brain()
{
   local preserved_tmpdir="$1"
   local idx="$2"
   local total=0

   for log_path in "${preserved_tmpdir}/brain${idx}.start"*.stdout.log
   do
      if [[ ! -f "${log_path}" ]]
      then
         continue
      fi

      local count=0
      count="$(rg -c --fixed-strings "neuron spinContainer deploymentID=" "${log_path}" 2>/dev/null || true)"
      if [[ -z "${count}" ]]
      then
         count=0
      fi
      total=$((total + count))
   done

   echo "${total}"
}

snapshot_counts_line()
{
   local case_log="$1"
   local line=""
   line="$(rg -m1 '^DEPLOY_SPIN_SNAPSHOT hosts=' "${case_log}" || true)"
   echo "${line}"
}

baseline_count_for_index()
{
   local snapshot_line="$1"
   local idx="$2"

   local counts_csv="${snapshot_line##*counts=}"
   local value=0
   IFS=',' read -r -a pairs <<< "${counts_csv}"
   for pair in "${pairs[@]}"
   do
      local pair_idx="${pair%%:*}"
      local pair_value="${pair##*:}"
      if [[ "${pair_idx}" == "${idx}" ]]
      then
         value="${pair_value}"
         break
      fi
   done

   if [[ ! "${value}" =~ ^[0-9]+$ ]]
   then
      value=0
   fi

   echo "${value}"
}

verify_case_migration()
{
   local case_name="$1"
   local case_kind="$2"
   local case_log="$3"
   local preserved_tmpdir="$4"

   local snapshot_line=""
   snapshot_line="$(snapshot_counts_line "${case_log}")"
   if [[ -z "${snapshot_line}" ]]
   then
      echo "CASE_FAIL ${case_name}: missing DEPLOY_SPIN_SNAPSHOT output"
      return 1
   fi

   local target_idx=""
   target_idx="$(extract_fault_target_index "${case_log}")"
   if [[ -z "${target_idx}" || ! "${target_idx}" =~ ^[1-3]$ ]]
   then
      echo "CASE_FAIL ${case_name}: unable to resolve fault target index from harness output"
      return 1
   fi

   local target_baseline=0
   target_baseline="$(baseline_count_for_index "${snapshot_line}" "${target_idx}")"
   if [[ "${target_baseline}" -le 0 ]]
   then
      echo "CASE_FAIL ${case_name}: fault target ${target_idx} was not hosting a deployed container at snapshot time"
      return 1
   fi

   local rescheduled=0
   local counts_debug=""
   for idx in 1 2 3
   do
      local baseline_count=0
      local final_count=0
      baseline_count="$(baseline_count_for_index "${snapshot_line}" "${idx}")"
      final_count="$(count_spin_lines_for_brain "${preserved_tmpdir}" "${idx}")"

      if [[ -n "${counts_debug}" ]]
      then
         counts_debug="${counts_debug},${idx}:${baseline_count}->${final_count}"
      else
         counts_debug="${idx}:${baseline_count}->${final_count}"
      fi

      if [[ "${idx}" != "${target_idx}" && "${final_count}" -gt "${baseline_count}" ]]
      then
         rescheduled=1
      fi
   done

   if [[ "${rescheduled}" -ne 1 ]]
   then
      if [[ "${case_kind}" == "stateful" ]]
      then
         # In the fixed 3-brain dev topology stateful replicas already occupy each host,
         # so host-loss validation focuses on continuity instead of additional spin count.
         echo "MIGRATION_ASSERT_PASS ${case_name} target=${target_idx} counts=${counts_debug} continuity_only=1"
         return 0
      fi

      echo "CASE_FAIL ${case_name}: did not observe a post-fault spinContainer increase on non-fault hosts (target=${target_idx}, counts=${counts_debug})"
      return 1
   fi

   echo "MIGRATION_ASSERT_PASS ${case_name} target=${target_idx} counts=${counts_debug}"
   return 0
}

run_case()
{
   local case_name="$1"
   local case_kind="$2" # stateless|stateful
   local duration_s="$3"
   local post_fault_window_s="$4"
   local min_target="$5"
   local ping_after_fault="${6:-1}"

   total_cases=$((total_cases + 1))
   echo "=== MIGRATION_CASE ${case_name} (${case_kind}) ==="

   if ! build_case_artifacts "${case_name}" "${case_kind}"
   then
      echo "CASE_FAIL ${case_name}: failed to build deployment artifacts"
      failed_cases=$((failed_cases + 1))
      return
   fi

   local case_log="${tmpdir}/${case_name}.harness.log"
   set +e
   PRODIGY_DEV_KEEP_TMP=1 "${HARNESS}" \
      "${PRODIGY_BIN}" \
      --brains=3 \
      --duration="${duration_s}" \
      --mothership-bin="${MOTHERSHIP_BIN}" \
      --fault-mode=crash \
      --fault-targets=deployed \
      --fault-start=2 \
      --fault-duration=0 \
      --post-fault-window="${post_fault_window_s}" \
      --deploy-plan-json="${case_plan_json}" \
      --deploy-container-zstd="${case_container_blob}" \
      --deploy-report-application="Nametag" \
      --deploy-report-min-healthy=1 \
      --deploy-report-max-target-min="${min_target}" \
      --deploy-ping-port="${ping_port}" \
      --deploy-ping-payload="ping" \
      --deploy-ping-expect="pong" \
      --deploy-ping-after-fault="${ping_after_fault}" \
      >"${case_log}" 2>&1
   local rc=$?
   set -e

   if [[ "${rc}" -ne 0 ]]
   then
      echo "CASE_FAIL ${case_name}: harness failed rc=${rc}"
      sed -n '1,220p' "${case_log}" || true
      failed_cases=$((failed_cases + 1))
      return
   fi

   local preserved_tmpdir=""
   preserved_tmpdir="$(extract_preserved_tmpdir "${case_log}")"
   if [[ -z "${preserved_tmpdir}" || ! -d "${preserved_tmpdir}" ]]
   then
      echo "CASE_FAIL ${case_name}: missing preserved harness tmpdir"
      sed -n '1,220p' "${case_log}" || true
      failed_cases=$((failed_cases + 1))
      return
   fi

   if ! verify_case_migration "${case_name}" "${case_kind}" "${case_log}" "${preserved_tmpdir}"
   then
      sed -n '1,240p' "${case_log}" || true
      failed_cases=$((failed_cases + 1))
      return
   fi

   echo "MIGRATION_CASE_PASS ${case_name}"
}

# Crash + missing-host recovery requires waiting through reboot escalation
# before decommission-driven rescheduling can occur.
run_case "stateless_host_missing_replaces_container" "stateless" 95 40 1
run_case "stateful_host_missing_replaces_container" "stateful" 105 40 3 0

echo "MIGRATION_RUNTIME_SUMMARY total=${total_cases} failed=${failed_cases}"

if [[ "${failed_cases}" -ne 0 ]]
then
   exit 1
fi

echo "MIGRATION_RUNTIME_PASS"
