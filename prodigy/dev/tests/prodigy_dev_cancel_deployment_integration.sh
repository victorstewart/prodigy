#!/usr/bin/env bash
set -Eeuo pipefail

prodigy_bin="${1:-}"
mothership_bin="${2:-}"
container_artifact="${3:-}"
unready_container_artifact="${4:-}"
scenario="${5:-}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/../../.." && pwd -P)"

fail()
{
   echo "FAIL: $*" >&2
   exit 1
}

if [[ ! -x "${prodigy_bin}" || ! -x "${mothership_bin}" || ! -r "${container_artifact}" ||
   ! -r "${unready_container_artifact}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/healthy-container.zst /path/to/unready-container.zst" >&2
   exit 2
fi

if [[ "${EUID}" -ne 0 ]]
then
   echo "SKIP: cancelDeployment integration requires the verified Linux guest" >&2
   exit 77
fi

if [[ "${PRODIGY_DEV_TEST_BOUNDARY:-}" == apple-container ]]
then
   [[ -n "${PRODIGY_DEV_APPLE_CONTAINER_ID:-}" &&
      "${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}" == 1 &&
      "${PRODIGY_BPF_AUTHORIZATION:-}" == guest-only ]] ||
      fail "Apple Container boundary authorization is incomplete"
   command -v systemd-detect-virt >/dev/null 2>&1 &&
      [[ "$(systemd-detect-virt --container 2>/dev/null || true)" != none ]] ||
      fail "Apple Container boundary was declared outside a Linux container"
else
   marker="${PRODIGY_DEV_DISPOSABLE_LINUX_MARKER:-/run/prodigy-disposable-linux}"
   if [[ ! -f "${marker}" || "$(<"${marker}")" != prodigy-disposable-linux-v1 ||
      "$(stat -c %u "${marker}")" != 0 ]]
   then
      echo "SKIP: cancelDeployment integration requires a verified disposable Linux boundary" >&2
      exit 77
   fi
   marker_mode="$(stat -c %a "${marker}")"
   (( (8#${marker_mode} & 022) == 0 )) || fail "disposable marker is writable by group/other"
fi

for command in awk jq mktemp python3 rg sed timeout
do
   command -v "${command}" >/dev/null || {
      echo "SKIP: missing required command: ${command}" >&2
      exit 77
   }
done

prodigy_bin="$(realpath "${prodigy_bin}")"
mothership_bin="$(realpath "${mothership_bin}")"
container_artifact="$(realpath "${container_artifact}")"
unready_container_artifact="$(realpath "${unready_container_artifact}")"
[[ "$(dirname "${prodigy_bin}")" == "$(dirname "${mothership_bin}")" ]] ||
   fail "Prodigy and Mothership must come from one build"

case "$(uname -m)" in
   aarch64|arm64) architecture=aarch64 ;;
   x86_64|amd64) architecture=x86_64 ;;
   riscv64|riscv) architecture=riscv64 ;;
   *) echo "SKIP: unsupported architecture" >&2; exit 77 ;;
esac

bundle="$(dirname "${prodigy_bin}")/prodigy.${architecture}.bundle.tar.zst"
bundle_sha256="${bundle}.sha256"
[[ -r "${bundle}" && -r "${bundle_sha256}" ]] ||
   fail "the matching Prodigy bundle and checksum are required"

if [[ -z "${scenario}" ]]
then
   for scenario_name in noRestart accepted containersTerminated successorStarted completed
   do
      "${BASH_SOURCE[0]}" "${prodigy_bin}" "${mothership_bin}" \
         "${container_artifact}" "${unready_container_artifact}" "${scenario_name}"
   done
   echo "PASS: cancelDeployment independent lost-response, lost-ack, phase-restart, and exactly-once successor integrations"
   exit 0
fi
case "${scenario}" in
   noRestart|accepted|containersTerminated|successorStarted|completed) ;;
   *) fail "unknown cancellation integration scenario: ${scenario}" ;;
esac

mkdir -p "${repo_root}/.run"
task_root="$(mktemp -d "${repo_root}/.run/cancel-deployment-integration.XXXXXX")"
workspace="${task_root}/workspace"
evidence="${task_root}/evidence"
mothership_db="${task_root}/mothership.tidesdb"
cluster_name="cancel-deployment-$$-${RANDOM}"
cluster_created=0
preserve="${PRODIGY_DEV_KEEP_TMP:-0}"
declare -a deployment_client_pids=()

run_mothership()
{
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db}" "${mothership_bin}" "$@"
}

run_mothership_timeout()
{
   local duration="$1"
   shift
   timeout "${duration}" env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db}" \
      "${mothership_bin}" "$@"
}

cleanup()
{
   local status="$?"
   trap - EXIT HUP INT TERM
   set +e
   for client_pid in "${deployment_client_pids[@]}"
   do
      kill -TERM "${client_pid}" >/dev/null 2>&1 || true
      wait "${client_pid}" >/dev/null 2>&1 || true
   done
   if [[ "${status}" -ne 0 || "${preserve}" == 1 ]]
   then
      mkdir -p "${evidence}/guest-control" "${evidence}/guest-node-logs"
      if [[ -d "${workspace}/cancel-deployment-test" ]]
      then
         cp -a "${workspace}/cancel-deployment-test/." "${evidence}/guest-control/" 2>/dev/null || true
      fi
      if [[ -f "${workspace}/test-cluster-manifest.json" ]]
      then
         cp -p "${workspace}/test-cluster-manifest.json" "${evidence}/guest-manifest.json" 2>/dev/null || true
         while IFS= read -r log_path
         do
            [[ -n "${log_path}" && -f "${log_path}" ]] || continue
            cp -p "${log_path}" "${evidence}/guest-node-logs/$(basename "${log_path}")" 2>/dev/null || true
         done < <(jq -r '.nodes[] | .stdoutLog, .stderrLog' "${workspace}/test-cluster-manifest.json" 2>/dev/null)
      fi
   fi
   if [[ "${cluster_created}" == 1 ]]
   then
      run_mothership removeCluster "${cluster_name}" >"${evidence}/remove-cluster.log" 2>&1 || true
   fi
   if [[ "${status}" -ne 0 || "${preserve}" == 1 ]]
   then
      echo "EVIDENCE: ${task_root}" >&2
   else
      rm -rf "${task_root}"
   fi
   exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "${evidence}" "${task_root}/share/prodigy"
ln "${bundle}" "${task_root}/share/prodigy/prodigy.${architecture}.bundle.tar.zst"
ln "${bundle_sha256}" "${task_root}/share/prodigy/prodigy.${architecture}.bundle.tar.zst.sha256"
export XDG_DATA_HOME="${task_root}/share"
export PRODIGY_DEV_CANCEL_TEST_DIR=/mnt/prodigy-vdc-workspace/cancel-deployment-test

create_request="$(jq -nc \
   --arg name "${cluster_name}" \
   --arg workspace "${workspace}" \
   '{
      name:$name,
      deploymentMode:"test",
      nBrains:3,
      autoscaleIntervalSeconds:180,
      machineSchemas:[{schema:"test-machine",kind:"vm",vmImageURI:"test://virtual-datacenter"}],
      test:{
         workspaceRoot:$workspace,
         machineCount:4,
         machineLogicalCores:8,
         machineMemoryMB:16384,
         machineStorageMB:16384,
         brainBootstrapFamily:"ipv4",
         enableFakeIpv4Boundary:false,
         interContainerMTU:9000
      }
   }')"
run_mothership createCluster "${create_request}" >"${evidence}/create-cluster.log" 2>&1 || {
   sed -n '1,240p' "${evidence}/create-cluster.log" >&2
   fail "Mothership could not create the test cluster"
}
cluster_created=1

manifest="${workspace}/test-cluster-manifest.json"
for _ in $(seq 1 600)
do
   [[ -s "${manifest}" ]] && break
   sleep 0.1
done
[[ -s "${manifest}" ]] || fail "virtual datacenter manifest was not published"

cluster_report()
{
   run_mothership_timeout 10s clusterReport "${cluster_name}" >"$1" 2>&1
}

application_report()
{
   run_mothership_timeout 10s applicationReport "${cluster_name}" "$1" >"$2" 2>&1
}

master_index_from_report()
{
   awk '
      /^[[:space:]]*Machine:/ {
         machine = 0
         if (match($0, /10[.]0[.]0[.]([0-9]+)/, address)) machine = address[1] - 9
      }
      /^[[:space:]]*lifecycle / && /currentMaster=1/ && machine > 0 { print machine; exit }
   ' "$1"
}

wait_cluster_healthy()
{
   local output="${evidence}/cluster-health.log"
   local healthy=0
   local ready=0
   local master=""
   for _ in $(seq 1 600)
   do
      if cluster_report "${output}"
      then
         healthy="$(rg -c '^[[:space:]]*Machine: state=healthy ' "${output}" 2>/dev/null || true)"
         ready="$(rg -c '^[[:space:]]*lifecycle controlPlaneReachable=1 runtimeReady=1 ' "${output}" 2>/dev/null || true)"
         master="$(master_index_from_report "${output}")"
         if [[ "${healthy:-0}" -ge 4 && "${ready:-0}" -ge 4 && -n "${master}" ]]
         then
            return 0
         fi
      fi
      sleep 0.2
   done
   return 1
}

wait_cluster_healthy || fail "test cluster did not become healthy"
cp "${evidence}/cluster-health.log" "${evidence}/cluster-initial.log"

reserve_application()
{
   local application_name="$1"
   local output="$2"
   local request
   request="$(jq -nc --arg name "${application_name}" '{applicationName:$name}')"
   run_mothership reserveApplicationID "${cluster_name}" "${request}" >"${output}" 2>&1
   sed -nE 's/.*appID=([1-9][0-9]*).*/\1/p' "${output}" | head -1
}

write_plan()
{
   local output="$1"
   local application_id="$2"
   local version_id="$3"
   local healthy_delay_ms="$4"
   local killable_seconds="${5:-90}"
   jq -n \
      --arg architecture "${architecture}" \
      --argjson applicationID "${application_id}" \
      --argjson versionID "${version_id}" \
      --argjson healthyDelayMs "${healthy_delay_ms}" \
      --argjson killableSeconds "${killable_seconds}" '
      {
         config:{
            type:"ApplicationType::stateless",
            applicationID:$applicationID,
            versionID:$versionID,
            architecture:$architecture,
            filesystemMB:64,
            storageMB:0,
            rootFilesystemReadOnly:true,
            runAsID:65534,
            memoryMB:256,
            nLogicalCores:1,
            msTilHealthy:$healthyDelayMs,
            sTilHealthcheck:60,
            sTilKillable:$killableSeconds
         },
         useHostNetworkNamespace:false,
         minimumSubscriberCapacity:1024,
         isStateful:false,
         stateless:{
            nBase:1,
            maxPerRackRatio:1.0,
            maxPerMachineRatio:1.0,
            moveableDuringCompaction:true
         },
         subscriptions:[],
         advertisements:[],
         canaryCount:0,
         canariesMustLiveForMinutes:1,
         moveConstructively:true,
         requiresDatacenterUniqueTag:false
      }
   ' >"${output}"
}

deployment_field_equals()
{
   local report="$1"
   local version="$2"
   local field="$3"
   local expected="$4"
   awk -v wanted="${version}" -v wanted_field="${field}" -v expected="${expected}" '
      /^[[:space:]]*versionID:/ { active = ($2 == wanted) }
      active && $1 == wanted_field ":" { found = ($2 == expected) }
      END { exit(found ? 0 : 1) }
   ' "${report}"
}

wait_exact_chain()
{
   local application_name="$1"
   local active_version="$2"
   local successor_version="$3"
   local output="$4"
   for _ in $(seq 1 300)
   do
      if application_report "${application_name}" "${output}" &&
         deployment_field_equals "${output}" "${active_version}" state DeploymentState::deploying &&
         deployment_field_equals "${output}" "${active_version}" nHealthy 0 &&
         deployment_field_equals "${output}" "${active_version}" nDeployed 1 &&
         deployment_field_equals "${output}" "${successor_version}" state DeploymentState::waitingToDeploy &&
         deployment_field_equals "${output}" "${successor_version}" nDeployed 0
      then
         return 0
      fi
      sleep 0.1
   done
   return 1
}

wait_marker()
{
   local marker_path="$1"
   for _ in $(seq 1 300)
   do
      [[ -s "${marker_path}" ]] && return 0
      sleep 0.1
   done
   return 1
}

crash_current_master()
{
   local label="$1"
   local report="${evidence}/${label}.pre-crash.cluster.log"
   cluster_report "${report}" || fail "could not resolve master before ${label}"
   local master
   master="$(master_index_from_report "${report}")"
   [[ "${master}" =~ ^[1-4]$ ]] || fail "could not identify current master before ${label}"
   run_mothership faultTestCluster "${cluster_name}" crash "${master}" 3000 0 0 0 \
      >"${evidence}/${label}.fault.log" 2>&1 || fail "Mothership fault failed at ${label}"
   wait_cluster_healthy || fail "cluster did not recover after ${label}"
   cp "${evidence}/cluster-health.log" "${evidence}/${label}.recovered.cluster.log"
}

wait_successor_complete()
{
   local application_name="$1"
   local successor_version="$2"
   local output="$3"
   for _ in $(seq 1 400)
   do
      if application_report "${application_name}" "${output}" &&
         deployment_field_equals "${output}" "${successor_version}" nHealthy 1 &&
         deployment_field_equals "${output}" "${successor_version}" nDeployed 1 &&
         deployment_field_equals "${output}" "${successor_version}" state DeploymentState::running
      then
         return 0
      fi
      sleep 0.1
   done
   return 1
}

healthy_name=CancelControlHealthy
healthy_id="$(reserve_application "${healthy_name}" "${evidence}/reserve-healthy.log")"
[[ "${healthy_id}" =~ ^[1-9][0-9]*$ ]] || fail "could not reserve unrelated healthy application"
healthy_plan="${task_root}/healthy.plan.json"
write_plan "${healthy_plan}" "${healthy_id}" 1 1000
run_mothership deploy "${cluster_name}" "$(jq -c . "${healthy_plan}")" "${container_artifact}" \
   >"${evidence}/deploy-healthy.log" 2>&1 || fail "unrelated healthy application failed to deploy"
wait_successor_complete "${healthy_name}" 1 "${evidence}/healthy.initial.report.log" ||
   fail "unrelated application did not become healthy"

run_scenario()
{
   local phase="$1"
   local suffix="$2"
   local operation_id="123e4567-e89b-42d3-a456-42661417${suffix}"
   local application_name="CancelTarget${suffix}"
   local active_version=$((4100 + 10#${suffix}))
   local successor_version=$((active_version + 1))
   local scenario_dir="${evidence}/${phase}"
   mkdir -p "${scenario_dir}" "${workspace}/cancel-deployment-test"

   local application_id
   application_id="$(reserve_application "${application_name}" "${scenario_dir}/reserve.log")"
   [[ "${application_id}" =~ ^[1-9][0-9]*$ ]] || fail "could not reserve ${application_name}"

   local active_plan="${task_root}/${phase}.active.plan.json"
   local successor_plan="${task_root}/${phase}.successor.plan.json"
   # The unready fixture deliberately ignores graceful stop. Keep the real
   # Neuron hard-kill/ack path while bounding every fault-injection scenario.
   write_plan "${active_plan}" "${application_id}" "${active_version}" 30000 1
   write_plan "${successor_plan}" "${application_id}" "${successor_version}" 1000

   run_mothership deploy "${cluster_name}" "$(jq -c . "${active_plan}")" "${unready_container_artifact}" \
      >"${scenario_dir}/deploy-active.log" 2>&1 || fail "${phase}: active deployment was rejected"

   local active_report="${scenario_dir}/active.report.log"
   for _ in $(seq 1 300)
   do
      if application_report "${application_name}" "${active_report}" &&
         deployment_field_equals "${active_report}" "${active_version}" state DeploymentState::deploying &&
         deployment_field_equals "${active_report}" "${active_version}" nHealthy 0 &&
         deployment_field_equals "${active_report}" "${active_version}" nDeployed 1
      then
         break
      fi
      sleep 0.1
   done
   deployment_field_equals "${active_report}" "${active_version}" state DeploymentState::deploying ||
      fail "${phase}: active deployment never entered the cancellable transition"

   run_mothership deploy "${cluster_name}" "$(jq -c . "${successor_plan}")" "${container_artifact}" \
      >"${scenario_dir}/deploy-successor.log" 2>&1 || fail "${phase}: successor deployment was rejected"
   wait_exact_chain "${application_name}" "${active_version}" "${successor_version}" \
      "${scenario_dir}/chain.report.log" || fail "${phase}: exact active/successor chain was not observed"

   local control_root="${workspace}/cancel-deployment-test"
   local phase_token="${phase}"
   [[ "${phase_token}" != containersTerminated ]] || phase_token=containers-terminated
   [[ "${phase_token}" != successorStarted ]] || phase_token=successor-started
   if [[ "${phase}" != noRestart ]]
   then
      : >"${control_root}/${operation_id}.pause.${phase_token}"
   fi
   if [[ "${phase}" == accepted ]]
   then
      : >"${control_root}/${operation_id}.drop-response"
      : >"${control_root}/${operation_id}.drop-kill-ack"
      : >"${control_root}/${operation_id}.hold-after-drop-kill-ack"
   elif [[ "${phase}" == completed ]]
   then
      : >"${control_root}/${operation_id}.inject-replication-reorder"
   fi

   local cancel_request
   cancel_request="$(jq -nc \
      --arg applicationName "${application_name}" \
      --argjson applicationID "${application_id}" \
      --argjson activeVersionID "${active_version}" \
      --argjson successorVersionID "${successor_version}" \
      --arg operationID "${operation_id}" \
      '{
         applicationName:$applicationName,
         applicationID:$applicationID,
         activeVersionID:$activeVersionID,
         successorVersionID:$successorVersionID,
         operationID:$operationID,
         reason:"verified-guest cancellation recovery integration"
      }')"

   local first_status=0
   run_mothership_timeout 15s cancelDeployment "${cluster_name}" "${cancel_request}" \
      >"${scenario_dir}/cancel-first.log" 2>&1 || first_status=$?
   if [[ "${phase}" == accepted ]]
   then
      [[ "${first_status}" -ne 0 ]] || fail "accepted: first deliberately dropped response unexpectedly arrived"
      run_mothership cancelDeployment "${cluster_name}" "${cancel_request}" \
         >"${scenario_dir}/cancel-retry.log" 2>&1 || fail "accepted: identical retry failed"
      rg -q 'result=alreadyAccepted' "${scenario_dir}/cancel-retry.log" ||
         fail "accepted: identical retry was not idempotently accepted"
   else
      [[ "${first_status}" -eq 0 ]] || fail "${phase}: cancellation request failed"
   fi

   if [[ "${phase}" != noRestart ]]
   then
      local paused_marker="${control_root}/${operation_id}.paused.${phase_token}"
      wait_marker "${paused_marker}" || fail "${phase}: durable phase was not held at its crash barrier"
      if [[ "${phase}" == completed ]]
      then
         wait_marker "${control_root}/${operation_id}.reached.inject-replication-reorder" ||
            fail "completed: stale and duplicate replication injection was not consumed"
         wait_marker "${control_root}/${operation_id}.reached.stale-replication-suppressed" ||
            fail "completed: a follower did not suppress the injected stale accepted phase"
         wait_marker "${control_root}/${operation_id}.reached.duplicate-completed-replication" ||
            fail "completed: a follower did not receive the duplicate completed phase"
      fi
      local paused_cancel="${scenario_dir}/cancel-paused.log"
      run_mothership cancelDeployment "${cluster_name}" "${cancel_request}" >"${paused_cancel}" 2>&1 ||
         fail "${phase}: idempotent query failed while the phase barrier was held"
      rg -q "phase=${phase}" "${paused_cancel}" ||
         fail "${phase}: durable phase advanced while its barrier was held"
      if [[ "${phase}" == accepted ]]
      then
         : >"${control_root}/${operation_id}.release.${phase_token}"
         wait_marker "${control_root}/${operation_id}.reached.drop-kill-ack" ||
            fail "accepted: first kill acknowledgement was not deliberately dropped"
         crash_current_master "accepted-phase"
         rm -f "${control_root}/${operation_id}.hold-after-drop-kill-ack"
      else
         crash_current_master "${phase}-phase"
         : >"${control_root}/${operation_id}.release.${phase_token}"
      fi
   fi

   local final_cancel="${scenario_dir}/cancel-completed-retry.log"
   for _ in $(seq 1 300)
   do
      if run_mothership cancelDeployment "${cluster_name}" "${cancel_request}" >"${final_cancel}" 2>&1 &&
         rg -q 'result=completed' "${final_cancel}"
      then
         break
      fi
      sleep 0.1
   done
   rg -q 'result=completed' "${final_cancel}" || fail "${phase}: durable completed tombstone was not recovered"

   wait_successor_complete "${application_name}" "${successor_version}" \
      "${scenario_dir}/successor.report.log" || fail "${phase}: successor did not become healthy"
   deployment_field_equals "${scenario_dir}/successor.report.log" "${successor_version}" state DeploymentState::running ||
      fail "${phase}: successor did not reach its stable running state"
   if rg -q "versionID:[[:space:]]*${active_version}" "${scenario_dir}/successor.report.log"
   then
      fail "${phase}: cancelled active deployment remained in the live application chain"
   fi

   application_report "${healthy_name}" "${scenario_dir}/unrelated-healthy.report.log" ||
      fail "${phase}: unrelated application report failed"
   deployment_field_equals "${scenario_dir}/unrelated-healthy.report.log" 1 nHealthy 1 ||
      fail "${phase}: unrelated healthy application was not preserved"
}

case "${scenario}" in
   noRestart) run_scenario noRestart 4100 ;;
   accepted) run_scenario accepted 4101 ;;
   containersTerminated) run_scenario containersTerminated 4102 ;;
   successorStarted) run_scenario successorStarted 4103 ;;
   completed) run_scenario completed 4104 ;;
esac

cluster_report "${evidence}/cluster-final.log" || fail "final cluster report failed"
application_report "${healthy_name}" "${evidence}/healthy-final.report.log" ||
   fail "final unrelated application report failed"
deployment_field_equals "${evidence}/healthy-final.report.log" 1 nHealthy 1 ||
   fail "unrelated healthy application did not survive all recovery scenarios"

run_mothership removeCluster "${cluster_name}" >"${evidence}/remove-cluster.log" 2>&1 ||
   fail "Mothership failed to remove its test cluster"
cluster_created=0
[[ ! -e "${workspace}" ]] || fail "Mothership left the test-cluster workspace behind"

echo "PASS: cancelDeployment ${scenario} recovery integration"
