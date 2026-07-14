#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
TASK_PROBE_BIN="${3:-}"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${TASK_PROBE_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_task_probe_container"
   exit 2
fi

if [[ "${PRODIGY_DEV_ALLOW_TASK_CONTAINER_SMOKE:-0}" != "1" ]]
then
   echo "SKIP: task container smoke touches runtime namespaces/cgroups; set PRODIGY_DEV_ALLOW_TASK_CONTAINER_SMOKE=1 only inside an authorized disposable boundary"
   exit 77
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/prodigy_dev_discombobulator_artifact_helpers.sh"
SCRIPT_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_TASK_CONTAINER_SMOKE_MOUNT_NS_READY bash "${SCRIPT_SELF}" "$@"

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for isolated task container smoke"
   exit 77
fi

for cmd in awk btrfs cargo mount zstd timeout ip nsenter python3 rg
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}"
      exit 77
   fi
done

PRODIGY_BIN="$(readlink -f "${PRODIGY_BIN}" 2>/dev/null || printf '%s' "${PRODIGY_BIN}")"
MOTHERSHIP_BIN="$(readlink -f "${MOTHERSHIP_BIN}" 2>/dev/null || printf '%s' "${MOTHERSHIP_BIN}")"
TASK_PROBE_BIN="$(readlink -f "${TASK_PROBE_BIN}" 2>/dev/null || printf '%s' "${TASK_PROBE_BIN}")"
target_arch="$(prodigy_dev_detect_target_arch)"

tmpdir="$(mktemp -d)"
workspace_root="${tmpdir}/workspace"
manifest_path="${workspace_root}/test-cluster-manifest.json"
cluster_name="task-container-$(date -u +%Y%m%d-%H%M%S)"
mothership_db_path="${tmpdir}/mothership-task-container.tidesdb"
keep_tmp="${PRODIGY_DEV_KEEP_TMP:-0}"
cluster_created=0

fail()
{
   echo "FAIL: $1"
   [[ $# -gt 1 ]] && sed -n "1,${3:-200}p" "$2" || true
   exit 1
}

cleanup()
{
   set +e
   if [[ "${cluster_created}" -eq 1 ]]
   then
      env \
         PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" removeCluster "${cluster_name}" \
         >"${tmpdir}/remove_cluster.log" 2>&1 || true
   fi
   [[ "${keep_tmp}" -eq 1 ]] && echo "KEEP_TMP: ${tmpdir}" || rm -rf "${tmpdir}"
}
trap cleanup EXIT

run_mothership()
{
   env \
      PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" "$@"
}

mkdir -p "${workspace_root}"

create_request="$(cat <<EOF
{
  "name": "${cluster_name}",
  "deploymentMode": "test",
  "nBrains": 1,
  "machineSchemas": [{"schema": "bootstrap", "kind": "vm", "vmImageURI": "test://task-container"}],
  "test": {
    "workspaceRoot": "${workspace_root}",
    "machineCount": 1,
    "brainBootstrapFamily": "ipv4",
    "enableFakeIpv4Boundary": false
  }
}
EOF
)"
run_mothership createCluster "${create_request}" >"${tmpdir}/create_cluster.log" 2>&1 || fail "createCluster failed" "${tmpdir}/create_cluster.log"
cluster_created=1

timeout 60s bash -c 'while [[ ! -s "$0" ]]; do sleep 0.1; done' "${manifest_path}" || fail "test cluster manifest did not become ready" "${tmpdir}/create_cluster.log"

new_version()
{
   local value=$(( ($(date +%s%N) & 281474976710655) ))
   [[ "${value}" -le 0 ]] && value=1
   echo "${value}"
}

reserve_app()
{
   local name="$1"
   local id="$2"
   local json
   json="$(printf '{"applicationName":"%s","requestedApplicationID":%u}' "${name}" "${id}")"
   run_mothership reserveApplicationID "${cluster_name}" "${json}" >"${tmpdir}/reserve-${name}.log" 2>&1 ||
      fail "reserveApplicationID ${name} failed" "${tmpdir}/reserve-${name}.log"
}

build_artifact()
{
   local label="$1"
   local env_lines="$2"
   local project_dir="${tmpdir}/${label}-artifact"
   local file="${project_dir}/${label}.DiscombobuFile"
   local blob="${tmpdir}/${label}.container.zst"
   mkdir -p "${project_dir}"
   {
      printf 'FROM scratch for %s\n' "${target_arch}"
      printf '%s\n' "${env_lines}"
      printf 'COPY {bin} ./%s /root/task_probe_container\n' "$(basename "${TASK_PROBE_BIN}")"
      printf 'SURVIVE /root/task_probe_container\n'
   } >"${file}"
   prodigy_dev_write_common_prodigy_assets "${file}"
   printf 'EXECUTE ["/root/task_probe_container"]\n' >>"${file}"
   prodigy_dev_run_discombobulator_build "${project_dir}" "${file}" "${blob}" "bin=$(dirname "${TASK_PROBE_BIN}")" "ebpf=$(dirname "${PRODIGY_BIN}")" ||
      fail "Discombobulator build failed for ${label}" "${project_dir}/discombobulator-build.log"
   printf '%s\n' "${blob}"
}

write_plan()
{
   local path="$1"
   local app_id="$2"
   local version_id="$3"
   local policy="$4"
   cat >"${path}" <<EOF
{
  "config": {
    "type": "ApplicationType::task",
    "applicationID": ${app_id},
    "versionID": ${version_id},
    "taskExecutionPolicy": "TaskExecutionPolicy::${policy}",
    "architecture": "${target_arch}",
    "filesystemMB": 64,
    "storageMB": 64,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 0,
    "sTilHealthcheck": 0,
    "sTilKillable": 30
  },
  "minimumSubscriberCapacity": 1,
  "isStateful": false,
  "requiresDatacenterUniqueTag": false
}
EOF
}

deploy_task()
{
   local label="$1"
   local plan="$2"
   local blob="$3"
   run_mothership deploy "${cluster_name}" "$(cat "${plan}")" "${blob}" >"${tmpdir}/deploy-${label}.log" 2>&1 ||
      fail "deploy ${label} failed" "${tmpdir}/deploy-${label}.log"
}

wait_report()
{
   local label="$1"
   local app_name="$2"
   local version_id="$3"
   local state="$4"
   local extra="$5"
   local log="${tmpdir}/task-report-${label}.log"
   for _ in $(seq 1 180)
   do
      run_mothership taskReport "${cluster_name}" "${app_name}" "${version_id}" >"${log}" 2>&1 || true
      if rg -q "taskReport found=1 .* state=${state} " "${log}" && rg -q "${extra}" "${log}"
      then
         return 0
      fi
      sleep 0.25
   done
   fail "taskReport ${label} did not reach ${state} with ${extra}" "${log}"
}

success_blob="$(build_artifact task-success 'ENV PRODIGY_TASK_PROBE_RESULT=task-success-result')"
failure_blob="$(build_artifact task-failure $'ENV PRODIGY_TASK_PROBE_RESULT=task-failure-result\nENV PRODIGY_TASK_PROBE_EXIT_CODE=7')"
retry_blob="$(build_artifact task-retry 'ENV PRODIGY_TASK_PROBE_SUCCEED_ON_ATTEMPT=2')"

success_name="task-success-${cluster_name}"
failure_name="task-failure-${cluster_name}"
retry_name="task-retry-${cluster_name}"
reserve_app "${success_name}" 62010
reserve_app "${failure_name}" 62011
reserve_app "${retry_name}" 62012

success_version="$(new_version)"
failure_version="$(new_version)"
retry_version="$(new_version)"
success_plan="${tmpdir}/success.plan.json"
failure_plan="${tmpdir}/failure.plan.json"
retry_plan="${tmpdir}/retry.plan.json"
write_plan "${success_plan}" 62010 "${success_version}" runOnce
write_plan "${failure_plan}" 62011 "${failure_version}" runOnce
write_plan "${retry_plan}" 62012 "${retry_version}" untilSucceeded

deploy_task success "${success_plan}" "${success_blob}"
wait_report success "${success_name}" "${success_version}" succeeded 'attempt=1 .* started=1 .* succeeded=1 .* failed=0 .* resultBytes=[1-9]'

deploy_task duplicate-success "${success_plan}" "${success_blob}"
wait_report duplicate-success "${success_name}" "${success_version}" succeeded 'attempt=1 .* started=1 .* succeeded=1 .* failed=0'

deploy_task failure "${failure_plan}" "${failure_blob}"
wait_report failure "${failure_name}" "${failure_version}" failed 'attempt=1 .* started=1 .* succeeded=0 .* failed=1 .* resultBytes=[1-9]'

deploy_task retry "${retry_plan}" "${retry_blob}"
wait_report retry "${retry_name}" "${retry_version}" succeeded 'attempt=2 .* started=2 .* succeeded=1 .* failed=1 .* resultBytes=[1-9]'

echo "PASS: task container smoke success=${success_version} failure=${failure_version} retry=${retry_version}"
