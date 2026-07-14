#!/usr/bin/env bash
set -Eeuo pipefail

prodigy_bin="${1:-}"
shift || true

fail()
{
   echo "FAIL: $*" >&2
   exit 1
}

if [[ -z "${prodigy_bin}" || ! -x "${prodigy_bin}" ]]
then
   echo "usage: $0 /path/to/prodigy [Mothership test-cluster options]" >&2
   exit 2
fi

[[ "${EUID}" -eq 0 ]] || {
   echo "SKIP: Mothership test clusters require root" >&2
   exit 77
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/../../.." && pwd -P)"
mkdir -p "${repo_root}/.run"

runner_mode=oneshot
workspace_root=
manifest_path=
machines=3
brains=3
test_machine_logical_cores="${PRODIGY_DEV_TEST_MACHINE_LOGICAL_CORES:-8}"
test_machine_memory_mb="${PRODIGY_DEV_TEST_MACHINE_MEMORY_MB:-16384}"
test_machine_storage_mb="${PRODIGY_DEV_TEST_MACHINE_STORAGE_MB:-262144}"
duration=10
brain_bootstrap_family="${PRODIGY_DEV_BRAIN_BOOTSTRAP_FAMILY:-ipv4}"
inter_container_mtu=9000
enable_fake_ipv4_boundary="${PRODIGY_DEV_ENABLE_FAKE_IPV4_BOUNDARY:-0}"
mothership_bin=
mothership_autoscale_interval_seconds=180
mothership_update_prodigy_input=
mothership_update_start=2
os_update_restart_on_command="${PRODIGY_DEV_OS_UPDATE_RESTART_ON_COMMAND:-0}"
os_update_command_timeout=90
os_update_rollout_timeout=
master_index=0
fault_mode=link
fault_targets=
fault_start=2
fault_start_on_ready=0
fault_duration=0
fault_cycles=0
fault_down=1
fault_up=1
post_fault_window=8
fault_master_change_budget_ms="${PRODIGY_DEV_FAULT_MASTER_CHANGE_BUDGET_MS:-9000}"
update_master_change_budget_ms="${PRODIGY_DEV_UPDATE_MASTER_CHANGE_BUDGET_MS:-15000}"
update_order_budget_ms="${PRODIGY_DEV_UPDATE_ORDER_BUDGET_MS:-15000}"
expect_master_available=-1
expect_master_change=-1
expect_master_change_during_fault=-1
expect_peer_recovery=-1
expect_full_brain_registration=0
deploy_plan_json=
deploy_container_zstd=
deploy_expect_accept=1
deploy_expect_text=
deploy_second_plan_json=
deploy_second_container_zstd=
deploy_second_start=0
deploy_second_expect_accept=1
deploy_second_expect_text=
deploy_third_plan_json=
deploy_third_container_zstd=
deploy_third_start=0
deploy_third_expect_accept=1
deploy_third_expect_text=
deploy_ping_port=0
deploy_ping_payload=ping
deploy_ping_expect=pong
deploy_ping_all=0
deploy_ping_after_fault=0
deploy_skip_probe=0
deploy_report_application=
deploy_report_version_id=0
deploy_report_version_min=0
deploy_report_attempts=180
deploy_report_min_healthy=0
deploy_report_max_healthy_min=0
deploy_report_final_healthy_min=0
deploy_report_final_healthy_max=-1
deploy_report_min_target=0
deploy_report_max_target_min=0
deploy_report_final_target_max=-1
deploy_report_min_deployed=0
deploy_report_max_deployed_min=0
deploy_report_final_deployed_max=-1
deploy_report_min_shard_groups=0
deploy_report_max_shard_groups_min=0
deploy_report_final_shard_groups_max=-1
deploy_report_max_crashes_max=-1
deploy_report_runtime_cores_min=0
deploy_report_runtime_memory_min_mb=0
deploy_report_runtime_storage_min_mb=0
deploy_report_runtime_cores_max_min=0
deploy_report_runtime_memory_max_min_mb=0
deploy_report_runtime_storage_max_min_mb=0
deploy_report_require_scaler=
deploy_report_require_scaler_value_min=0
deploy_report_traffic_burst=1
deploy_report_success_hold_ms="${PRODIGY_DEV_DEPLOY_REPORT_SUCCESS_HOLD_MS:-2500}"
deploy_report_floor_min_runtime_ms="${PRODIGY_DEV_DEPLOY_REPORT_FLOOR_MIN_RUNTIME_MS:-0}"
deploy_report_poll_interval_ms="${PRODIGY_DEV_DEPLOY_REPORT_POLL_INTERVAL_MS:-300}"
deploy_mesh_mode=
deploy_mesh_require_all=0
declare -a required_log_substrings=()

while [[ $# -gt 0 ]]
do
   case "$1" in
      --require-brain-log-substring=*)
         required_log_substrings+=("${1#*=}")
         ;;
      --tunnel-ebpf=*|--host-ingress-ebpf=*|--host-egress-ebpf=*|--fake-ipv4-boundary-ebpf=*|--private-ipv4-prefix=*|--switchboard-gateway-index=*)
         fail "runtime-owned artifact and network overrides are no longer harness options: ${1%%=*}"
         ;;
      --runner-mode=*|--workspace-root=*|--manifest-path=*|--machines=*|--brains=*|--test-machine-logical-cores=*|--test-machine-memory-mb=*|--test-machine-storage-mb=*|--duration=*|--brain-bootstrap-family=*|--inter-container-mtu=*|--enable-fake-ipv4-boundary=*|--mothership-bin=*|--mothership-autoscale-interval-seconds=*|--mothership-update-prodigy-input=*|--mothership-update-start=*|--os-update-restart-on-command=*|--os-update-command-timeout=*|--os-update-rollout-timeout=*|--master-index=*|--fault-mode=*|--fault-targets=*|--fault-start=*|--fault-start-on-ready=*|--fault-duration=*|--fault-cycles=*|--fault-down=*|--fault-up=*|--post-fault-window=*|--fault-master-change-budget-ms=*|--update-master-change-budget-ms=*|--update-order-budget-ms=*|--expect-master-available=*|--expect-master-change=*|--expect-master-change-during-fault=*|--expect-peer-recovery=*|--expect-full-brain-registration=*|--deploy-plan-json=*|--deploy-container-zstd=*|--deploy-expect-accept=*|--deploy-expect-text=*|--deploy-second-plan-json=*|--deploy-second-container-zstd=*|--deploy-second-start=*|--deploy-second-expect-accept=*|--deploy-second-expect-text=*|--deploy-third-plan-json=*|--deploy-third-container-zstd=*|--deploy-third-start=*|--deploy-third-expect-accept=*|--deploy-third-expect-text=*|--deploy-ping-port=*|--deploy-ping-payload=*|--deploy-ping-expect=*|--deploy-ping-all=*|--deploy-ping-after-fault=*|--deploy-skip-probe=*|--deploy-report-application=*|--deploy-report-version-id=*|--deploy-report-version-min=*|--deploy-report-attempts=*|--deploy-report-min-healthy=*|--deploy-report-max-healthy-min=*|--deploy-report-final-healthy-min=*|--deploy-report-final-healthy-max=*|--deploy-report-min-target=*|--deploy-report-max-target-min=*|--deploy-report-final-target-max=*|--deploy-report-min-deployed=*|--deploy-report-max-deployed-min=*|--deploy-report-final-deployed-max=*|--deploy-report-min-shard-groups=*|--deploy-report-max-shard-groups-min=*|--deploy-report-final-shard-groups-max=*|--deploy-report-max-crashes-max=*|--deploy-report-runtime-cores-min=*|--deploy-report-runtime-memory-min-mb=*|--deploy-report-runtime-storage-min-mb=*|--deploy-report-runtime-cores-max-min=*|--deploy-report-runtime-memory-max-min-mb=*|--deploy-report-runtime-storage-max-min-mb=*|--deploy-report-require-scaler=*|--deploy-report-require-scaler-value-min=*|--deploy-report-traffic-burst=*|--deploy-report-success-hold-ms=*|--deploy-report-floor-min-runtime-ms=*|--deploy-report-poll-interval-ms=*|--deploy-mesh-mode=*|--deploy-mesh-require-all=*)
         key="${1%%=*}"
         key="${key#--}"
         key="${key//-/_}"
         printf -v "${key}" '%s' "${1#*=}"
         ;;
      *)
         echo "unknown argument: $1" >&2
         exit 2
         ;;
   esac
   shift
done

for command in jq mktemp rg sed timeout
do
   command -v "${command}" >/dev/null || {
      echo "SKIP: missing required command: ${command}" >&2
      exit 77
   }
done

unsigned()
{
   [[ "$1" =~ ^[0-9]+$ ]]
}

boolean()
{
   [[ "$1" == 0 || "$1" == 1 ]]
}

for value in "${machines}" "${brains}" "${test_machine_logical_cores}" "${test_machine_memory_mb}" "${test_machine_storage_mb}" "${duration}" "${inter_container_mtu}" "${mothership_autoscale_interval_seconds}" "${fault_start}" "${fault_duration}" "${fault_cycles}" "${fault_down}" "${fault_up}" "${post_fault_window}" "${deploy_ping_port}" "${deploy_report_attempts}" "${deploy_report_poll_interval_ms}"
do
   unsigned "${value}" || fail "numeric option is invalid: ${value}"
done
[[ "${machines}" -ge 1 && "${machines}" -le 128 && "${brains}" -ge 1 && "${brains}" -le "${machines}" ]] || fail "machines/brains shape is invalid"
[[ "${runner_mode}" == oneshot || "${runner_mode}" == persistent ]] || fail "runner mode must be oneshot or persistent"
[[ "${brain_bootstrap_family}" =~ ^(ipv4|private6|public6|multihome6)$ ]] || fail "brain bootstrap family is invalid"
[[ "${fault_mode}" =~ ^(link|crash|flap)$ ]] || fail "fault mode is invalid"
for value in "${enable_fake_ipv4_boundary}" "${fault_start_on_ready}" "${expect_full_brain_registration}" "${deploy_expect_accept}" "${deploy_second_expect_accept}" "${deploy_third_expect_accept}" "${deploy_ping_all}" "${deploy_ping_after_fault}" "${deploy_skip_probe}" "${deploy_report_version_min}" "${deploy_mesh_require_all}" "${os_update_restart_on_command}"
do
   boolean "${value}" || fail "boolean option is invalid: ${value}"
done
if [[ "${enable_fake_ipv4_boundary}" == 1 && "${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}" != 1 ]]
then
   fail "fake IPv4 boundary requires explicitly authorized BPF attachment"
fi

prodigy_bin="$(readlink -f "${prodigy_bin}")"
if [[ -z "${mothership_bin}" ]]
then
   mothership_bin="$(dirname "${prodigy_bin}")/mothership"
fi
mothership_bin="$(readlink -f "${mothership_bin}")"
[[ -x "${mothership_bin}" ]] || fail "Mothership binary is not executable: ${mothership_bin}"
[[ -x "$(dirname "${mothership_bin}")/prodigy" ]] || fail "Mothership has no sibling Prodigy binary"
[[ "$(readlink -f "$(dirname "${mothership_bin}")/prodigy")" == "${prodigy_bin}" ]] || fail "Mothership and requested Prodigy must be sibling release artifacts"

tmpdir="$(mktemp -d "${repo_root}/.run/prodigy-dev-harness.XXXXXX")"
if [[ -z "${workspace_root}" ]]
then
   workspace_root="${tmpdir}/workspace"
fi
[[ "${workspace_root}" == /* ]] || fail "workspace root must be absolute"
provider_manifest="${workspace_root}/test-cluster-manifest.json"
if [[ -z "${manifest_path}" ]]
then
   manifest_path="${provider_manifest}"
fi
cluster_name="harness-$$-${RANDOM}"
export PRODIGY_MOTHERSHIP_TIDESDB_PATH="${PRODIGY_MOTHERSHIP_TIDESDB_PATH:-${tmpdir}/mothership.tidesdb}"
create_log="${tmpdir}/create.log"
cluster_created=0
keep_tmp="${PRODIGY_DEV_KEEP_TMP:-0}"

copy_observation_logs()
{
   [[ -s "${provider_manifest}" ]] || return 0
   mkdir -p "${tmpdir}/logs"
   while IFS=$'\t' read -r index role log_path
   do
      [[ -r "${log_path}" ]] || continue
      cp -p "${log_path}" "${tmpdir}/logs/machine${index}.${role}.stdout.log"
   done < <(jq -r '.nodes[] | [.index, .role, .stdoutLog] | @tsv' "${provider_manifest}")
   cp -p "${provider_manifest}" "${tmpdir}/test-cluster-manifest.json" 2>/dev/null || true
}

cleanup()
{
   local status="$?"
   local preserve_tmp="${keep_tmp}"
   trap - EXIT HUP INT TERM
   set +e
   [[ "${status}" -eq 0 ]] || preserve_tmp=1
   if [[ "${preserve_tmp}" == 1 ]]
   then
      copy_observation_logs
   fi
   if [[ "${cluster_created}" == 1 ]]
   then
      "${mothership_bin}" removeCluster "${cluster_name}" >"${tmpdir}/remove.log" 2>&1 || true
   fi
   if [[ "${manifest_path}" != "${provider_manifest}" && -L "${manifest_path}" ]]
   then
      rm -f "${manifest_path}"
   fi
   if [[ "${preserve_tmp}" == 1 ]]
   then
      echo "DEBUG: preserved tmpdir ${tmpdir}"
   else
      rm -rf "${tmpdir}"
   fi
   exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

policies="${PRODIGY_DEV_CONFIGURE_OS_UPDATE_POLICIES_JSON:-[]}"
if [[ "${policies}" == '[]' && -n "${PRODIGY_DEV_CONFIGURE_TARGET_OS_ID:-}" && -n "${PRODIGY_DEV_CONFIGURE_TARGET_OS_VERSION_ID:-}" && -n "${PRODIGY_DEV_CONFIGURE_OS_UPDATE_COMMAND:-}" ]]
then
   policies="$(jq -nc \
      --arg osID "${PRODIGY_DEV_CONFIGURE_TARGET_OS_ID}" \
      --arg target "${PRODIGY_DEV_CONFIGURE_TARGET_OS_VERSION_ID}" \
      --arg command "${PRODIGY_DEV_CONFIGURE_OS_UPDATE_COMMAND}" \
      --arg include "${PRODIGY_DEV_CONFIGURE_INCLUDE_VMS_IN_OS_UPDATES:-1}" \
      '[{osID:$osID,targetVersionID:$target,command:$command,includeVMs:($include == "1")}]')"
fi
jq -e 'type == "array"' <<< "${policies}" >/dev/null || fail "OS update policies JSON is invalid"

create_request="$(jq -nc \
   --arg name "${cluster_name}" \
   --arg workspace "${workspace_root}" \
   --arg family "${brain_bootstrap_family}" \
   --arg fake "${enable_fake_ipv4_boundary}" \
   --arg enabled "${PRODIGY_DEV_CONFIGURE_OS_UPDATES_ENABLED:-0}" \
   --argjson machines "${machines}" \
   --argjson brains "${brains}" \
   --argjson cores "${test_machine_logical_cores}" \
   --argjson memory "${test_machine_memory_mb}" \
   --argjson storage "${test_machine_storage_mb}" \
   --argjson mtu "${inter_container_mtu}" \
   --argjson autoscale "${mothership_autoscale_interval_seconds}" \
   --argjson policies "${policies}" \
   --argjson drains "${PRODIGY_DEV_CONFIGURE_MAX_OS_DRAINS:-1}" \
   --argjson cadence "${PRODIGY_DEV_CONFIGURE_MACHINE_UPDATE_CADENCE_MINS:-15}" \
   '{
      name:$name,
      deploymentMode:"test",
      nBrains:$brains,
      autoscaleIntervalSeconds:$autoscale,
      machineSchemas:[{schema:"test-machine",kind:"vm",vmImageURI:"test://virtual-datacenter"}],
      test:{
         workspaceRoot:$workspace,
         machineCount:$machines,
         machineLogicalCores:$cores,
         machineMemoryMB:$memory,
         machineStorageMB:$storage,
         brainBootstrapFamily:$family,
         enableFakeIpv4Boundary:($fake == "1"),
         interContainerMTU:$mtu
      },
      osUpdatePolicies:$policies,
      osUpdatesEnabled:($enabled == "1"),
      maxOSDrains:$drains,
      machineUpdateCadenceMins:$cadence
   }')"

if ! "${mothership_bin}" createCluster "${create_request}" >"${create_log}" 2>&1
then
   sed -n '1,260p' "${create_log}" >&2
   fail "Mothership could not create the test cluster"
fi
cluster_created=1

for _ in $(seq 1 600)
do
   [[ -s "${provider_manifest}" ]] && break
   sleep 0.1
done
[[ -s "${provider_manifest}" ]] || fail "Mothership did not publish the test-cluster manifest"
if [[ "${manifest_path}" != "${provider_manifest}" ]]
then
   mkdir -p "$(dirname "${manifest_path}")"
   ln -sfn "${provider_manifest}" "${manifest_path}"
fi

cluster_report()
{
   local output="$1"
   timeout 8s "${mothership_bin}" clusterReport "${cluster_name}" >"${output}" 2>&1
}

application_report()
{
   local application="$1"
   local output="$2"
   timeout 8s "${mothership_bin}" applicationReport "${cluster_name}" "${application}" >"${output}" 2>&1
}

container_logs()
{
   local application="$1"
   local output="$2"
   timeout 25s "${mothership_bin}" containerLogs "${cluster_name}" "${application}" >"${output}" 2>&1
}

report_healthy_count()
{
   rg -c '^[[:space:]]*Machine: state=healthy ' "$1" 2>/dev/null || true
}

report_ready_count()
{
   rg -c '^[[:space:]]*lifecycle controlPlaneReachable=1 runtimeReady=1 ' "$1" 2>/dev/null || true
}

wait_cluster_healthy()
{
   local attempts="${1:-600}"
   local report="${tmpdir}/cluster-health.log"
   local healthy=0
   local ready=0
   for _ in $(seq 1 "${attempts}")
   do
      if cluster_report "${report}"
      then
         healthy="$(report_healthy_count "${report}")"
         ready="$(report_ready_count "${report}")"
         if [[ "${healthy:-0}" -ge "${machines}" && "${ready:-0}" -ge "${machines}" ]]
         then
            return 0
         fi
      fi
      sleep 0.2
   done
   sed -n '1,240p' "${report}" >&2 || true
   return 1
}

wait_cluster_healthy || fail "test cluster did not become healthy"
initial_report="${tmpdir}/cluster-initial.log"
cluster_report "${initial_report}" || fail "initial cluster report failed"

master_index_from_report()
{
   awk '
      /^[[:space:]]*Machine:/ {
         machine = 0
         if (match($0, /10[.]0[.]0[.]([0-9]+)/, value))
            machine = value[1] - 9
      }
      /^[[:space:]]*lifecycle / && /currentMaster=1/ {
         if (machine > 0) {
            print machine
            exit
         }
      }
   ' "$1"
}

brain_indices_from_report()
{
   awk '
      /^[[:space:]]*Machine:/ && /role=brain/ {
         if (match($0, /10[.]0[.]0[.]([0-9]+)/, value))
            print value[1] - 9
      }
   ' "$1" | sort -n
}

deployed_indices_from_report()
{
   awk '
      /^[[:space:]]*Machine:/ {
         machine = 0
         if (match($0, /10[.]0[.]0[.]([0-9]+)/, value))
            machine = value[1] - 9
      }
      /^[[:space:]]*placement / && /containers=[^ ]/ {
         if (machine > 0) print machine
      }
   ' "$1" | sort -nu
}

initial_master="$(master_index_from_report "${initial_report}")"
[[ -n "${initial_master}" ]] || fail "cluster has no single reported master"
echo "MOTHERSHIP_BOOTSTRAP success cluster=${cluster_name} masterIndex=${initial_master} machines=${machines} brains=${brains}"

if [[ "${runner_mode}" == persistent ]]
then
   while true
   do
      sleep 0.5
   done
fi

application_name_for_plan()
{
   local plan="$1"
   local value
   value="$(jq -r '.config.applicationID // empty' "${plan}")"
   case "${value}" in
      '${application:'*'}'|'${app:'*'}')
         value="${value#*:}"
         echo "${value%\}}"
         return
         ;;
   esac
   case "${value}" in
      1) echo DNS ;;
      2) echo Pulse ;;
      3) echo Hot ;;
      4) echo Cold ;;
      5) echo Radar ;;
      6) echo Nametag ;;
      7) echo Telnyx ;;
      8) echo AppleNotifs ;;
      *) echo "HarnessApp.$(basename "${plan}" | tr -cd 'A-Za-z0-9._-')" ;;
   esac
}

resolved_plan=
resolved_application=
prepare_plan()
{
   local plan="$1"
   local label="$2"
   [[ -r "${plan}" ]] || fail "deployment plan is not readable: ${plan}"
   jq -e 'type == "object" and (.config | type == "object")' "${plan}" >/dev/null || fail "deployment plan is invalid: ${plan}"
   resolved_application="$(application_name_for_plan "${plan}")"
   local requested
   requested="$(jq -r '.config.applicationID | select(type == "number") // empty' "${plan}")"
   local request
   request="$(jq -nc --arg name "${resolved_application}" --arg requested "${requested}" \
      '{applicationName:$name} + (if $requested == "" then {} else {requestedApplicationID:($requested|tonumber)} end)')"
   local reserve_log="${tmpdir}/reserve-application-${label}.log"
   local reserved=
   for _ in $(seq 1 "${PRODIGY_DEV_RESERVE_ATTEMPTS:-8}")
   do
      if "${mothership_bin}" reserveApplicationID "${cluster_name}" "${request}" >"${reserve_log}" 2>&1 &&
         rg -q 'reserveApplicationID success=1' "${reserve_log}"
      then
         reserved="$(rg -m1 -o 'appID=[0-9]+' "${reserve_log}" | sed 's/appID=//')"
         break
      fi
      sleep 0.2
   done
   [[ "${reserved}" =~ ^[1-9][0-9]*$ ]] || {
      sed -n '1,180p' "${reserve_log}" >&2
      fail "application ID reservation failed for ${plan}"
   }

   resolved_plan="${tmpdir}/plan-${label}.json"
   jq --argjson applicationID "${reserved}" '
      .config.applicationID = $applicationID
      | if ((.tls? | type) == "object" and (.tls | has("applicationID"))) then .tls.applicationID = $applicationID else . end
      | if ((.apiCredentials? | type) == "object" and (.apiCredentials | has("applicationID"))) then .apiCredentials.applicationID = $applicationID else . end
   ' "${plan}" >"${resolved_plan}"

   local kind=stateless
   if [[ "$(jq -r '.isStateful // false' "${plan}")" == true || "$(jq -r '.config.type // ""' "${plan}")" == ApplicationType::stateful ]]
   then
      kind=stateful
   fi
   local ref
   while IFS= read -r ref
   do
      [[ -n "${ref}" ]] || continue
      local body="${ref#*:}"
      body="${body%\}}"
      [[ "${body}" == */* ]] || fail "invalid symbolic service reference: ${ref}"
      local app="${body%%/*}"
      local service="${body#*/}"
      service="${service%.group[0-9]*}"
      local service_request
      if [[ "${app}" == "${resolved_application}" ]]
      then
         service_request="$(jq -nc --arg app "${app}" --arg service "${service}" --arg kind "${kind}" --argjson appID "${reserved}" \
            '{applicationName:$app,applicationID:$appID,serviceName:$service,kind:$kind}')"
      else
         service_request="$(jq -nc --arg app "${app}" --arg service "${service}" --arg kind "${kind}" \
            '{applicationName:$app,serviceName:$service,kind:$kind}')"
      fi
      local service_log="${tmpdir}/reserve-service-${label}-$(tr '/ ' '__' <<< "${body}").log"
      if ! "${mothership_bin}" reserveServiceID "${cluster_name}" "${service_request}" >"${service_log}" 2>&1 ||
         ! rg -q 'reserveServiceID success=1' "${service_log}"
      then
         sed -n '1,180p' "${service_log}" >&2
         fail "service ID reservation failed for ${body}"
      fi
   done < <(jq -r '.. | objects | .service? // empty | select(type == "string") | select(test("^\\$\\{(service|svc):[^}]+\\}$"))' "${plan}")
}

deploy_one()
{
   local label="$1"
   local plan="$2"
   local blob="$3"
   local expect_accept="$4"
   local expect_text="$5"
   [[ -r "${blob}" ]] || fail "container artifact is not readable: ${blob}"
   prepare_plan "${plan}" "${label}"
   local payload
   payload="$(jq -c . "${resolved_plan}")"
   local output="${tmpdir}/deploy-${label}.log"
   local status=0
   "${mothership_bin}" deploy "${cluster_name}" "${payload}" "${blob}" >"${output}" 2>&1 || status=$?
   if [[ "${expect_accept}" == 1 && "${status}" -ne 0 ]]
   then
      sed -n '1,240p' "${output}" >&2
      fail "deployment ${label} was rejected"
   fi
   if [[ "${expect_accept}" == 0 && "${status}" -eq 0 ]]
   then
      sed -n '1,240p' "${output}" >&2
      fail "deployment ${label} was unexpectedly accepted"
   fi
   if [[ -n "${expect_text}" ]] && ! rg -Fq "${expect_text}" "${output}"
   then
      sed -n '1,240p' "${output}" >&2
      fail "deployment ${label} output omitted expected text"
   fi
   echo "MOTHERSHIP_DEPLOY label=${label} accepted=${expect_accept} application=${resolved_application}"
}

if [[ -n "${deploy_plan_json}" || -n "${deploy_container_zstd}" ]]
then
   [[ -n "${deploy_plan_json}" && -n "${deploy_container_zstd}" ]] || fail "primary deployment requires both plan and container"
   deploy_one primary "${deploy_plan_json}" "${deploy_container_zstd}" "${deploy_expect_accept}" "${deploy_expect_text}"
fi
if [[ -n "${deploy_second_plan_json}" || -n "${deploy_second_container_zstd}" ]]
then
   [[ -n "${deploy_second_plan_json}" && -n "${deploy_second_container_zstd}" ]] || fail "second deployment requires both plan and container"
   sleep "${deploy_second_start}"
   deploy_one second "${deploy_second_plan_json}" "${deploy_second_container_zstd}" "${deploy_second_expect_accept}" "${deploy_second_expect_text}"
fi
if [[ -n "${deploy_third_plan_json}" || -n "${deploy_third_container_zstd}" ]]
then
   [[ -n "${deploy_third_plan_json}" && -n "${deploy_third_container_zstd}" ]] || fail "third deployment requires both plan and container"
   sleep "${deploy_third_start}"
   deploy_one third "${deploy_third_plan_json}" "${deploy_third_container_zstd}" "${deploy_third_expect_accept}" "${deploy_third_expect_text}"
fi

probe_once()
{
   local require_all="$1"
   local successes=0
   local index
   for index in $(seq 1 "${machines}")
   do
      local address="10.0.0.$((9 + index))"
      if timeout 3s "${mothership_bin}" probeTestCluster "${cluster_name}" "${address}" "${deploy_ping_port}" "${deploy_ping_payload}" "${deploy_ping_expect}" 1500 0 >/dev/null 2>&1
      then
         successes=$((successes + 1))
      elif [[ "${require_all}" == 1 ]]
      then
         return 1
      fi
   done
   [[ "${successes}" -gt 0 ]]
}

probe_until_ready()
{
   local require_all="$1"
   local attempts="${PRODIGY_DEV_DEPLOY_PING_ATTEMPTS:-180}"
   for _ in $(seq 1 "${attempts}")
   do
      probe_once "${require_all}" && return 0
      sleep 0.2
   done
   return 1
}

select_deployment_block()
{
   local report="$1"
   local block="$2"
   awk -v want="${deploy_report_version_id}" -v minimum="${deploy_report_version_min}" '
      /^[[:space:]]*versionID:/ {
         version = $2 + 0
         if (selected) exit
         if (want == 0 || (minimum == 0 && version == want) || (minimum == 1 && version >= want))
            selected = 1
      }
      selected { print }
   ' "${report}" >"${block}"
   [[ -s "${block}" ]]
}

block_scalar()
{
   local key="$1"
   local block="$2"
   local value
   value="$(rg -m1 -o "${key}:[[:space:]]*[0-9]+" "${block}" 2>/dev/null | sed -E 's/.*:[[:space:]]*//' || true)"
   echo "${value:-0}"
}

scaler_satisfied()
{
   local block="$1"
   [[ -z "${deploy_report_require_scaler}" ]] && return 0
   awk -v wanted="${deploy_report_require_scaler}" -v minimum="${deploy_report_require_scaler_value_min}" '
      /^[[:space:]]*name:/ {
         name = $0
         sub(/^[[:space:]]*name:[[:space:]]*/, "", name)
      }
      /^[[:space:]]*value:/ && name == wanted {
         value = $0
         sub(/^[[:space:]]*value:[[:space:]]*/, "", value)
         if ((value + 0) >= (minimum + 0)) found = 1
      }
      END { exit(found ? 0 : 1) }
   ' "${block}"
}

runtime_resources_satisfied()
{
   local block="$1"
   local seen=0
   local max_cores=0
   local max_memory=0
   local max_storage=0
   while read -r cores memory storage
   do
      seen=1
      [[ "${cores}" -ge "${deploy_report_runtime_cores_min}" ]] || return 1
      [[ "${memory}" -ge "${deploy_report_runtime_memory_min_mb}" ]] || return 1
      [[ "${storage}" -ge "${deploy_report_runtime_storage_min_mb}" ]] || return 1
      (( cores > max_cores )) && max_cores="${cores}"
      (( memory > max_memory )) && max_memory="${memory}"
      (( storage > max_storage )) && max_storage="${storage}"
   done < <(sed -n -E 's/.*containerRuntime: cores=([0-9]+) memMB=([0-9]+) storMB=([0-9]+).*/\1 \2 \3/p' "${block}")
   if [[ "${deploy_report_runtime_cores_min}" -gt 0 || "${deploy_report_runtime_memory_min_mb}" -gt 0 || "${deploy_report_runtime_storage_min_mb}" -gt 0 || "${deploy_report_runtime_cores_max_min}" -gt 0 || "${deploy_report_runtime_memory_max_min_mb}" -gt 0 || "${deploy_report_runtime_storage_max_min_mb}" -gt 0 ]]
   then
      [[ "${seen}" == 1 ]] || return 1
   fi
   [[ "${max_cores}" -ge "${deploy_report_runtime_cores_max_min}" &&
      "${max_memory}" -ge "${deploy_report_runtime_memory_max_min_mb}" &&
      "${max_storage}" -ge "${deploy_report_runtime_storage_max_min_mb}" ]]
}

wait_application_report()
{
   [[ -n "${deploy_report_application}" ]] || return 0
   local report="${tmpdir}/application-report.log"
   local block="${tmpdir}/application-deployment.log"
   local peak_healthy=0
   local peak_target=0
   local peak_deployed=0
   local peak_shards=0
   local started="$(date +%s%3N)"
   local stable_since=0
   local attempt
   for attempt in $(seq 1 "${deploy_report_attempts}")
   do
      if application_report "${deploy_report_application}" "${report}" && select_deployment_block "${report}" "${block}"
      then
         if rg -q '^[[:space:]]*state: DeploymentState::failed$' "${block}"
         then
            sed -n '1,260p' "${report}" >&2
            return 1
         fi
         local healthy target deployed shards crashes
         healthy="$(block_scalar nHealthy "${block}")"
         target="$(block_scalar nTarget "${block}")"
         deployed="$(block_scalar nDeployed "${block}")"
         shards="$(block_scalar nShardGroups "${block}")"
         crashes="$(block_scalar nCrashes "${block}")"
         (( healthy > peak_healthy )) && peak_healthy="${healthy}"
         (( target > peak_target )) && peak_target="${target}"
         (( deployed > peak_deployed )) && peak_deployed="${deployed}"
         (( shards > peak_shards )) && peak_shards="${shards}"

         local current_ok=1
         [[ "${healthy}" -ge "${deploy_report_min_healthy}" ]] || current_ok=0
         [[ "${target}" -ge "${deploy_report_min_target}" ]] || current_ok=0
         [[ "${deployed}" -ge "${deploy_report_min_deployed}" ]] || current_ok=0
         [[ "${shards}" -ge "${deploy_report_min_shard_groups}" ]] || current_ok=0
         [[ "${peak_healthy}" -ge "${deploy_report_max_healthy_min}" ]] || current_ok=0
         [[ "${peak_target}" -ge "${deploy_report_max_target_min}" ]] || current_ok=0
         [[ "${peak_deployed}" -ge "${deploy_report_max_deployed_min}" ]] || current_ok=0
         [[ "${peak_shards}" -ge "${deploy_report_max_shard_groups_min}" ]] || current_ok=0
         [[ "${healthy}" -ge "${deploy_report_final_healthy_min}" ]] || current_ok=0
         [[ "${deploy_report_final_healthy_max}" == -1 || "${healthy}" -le "${deploy_report_final_healthy_max}" ]] || current_ok=0
         [[ "${deploy_report_final_target_max}" == -1 || "${target}" -le "${deploy_report_final_target_max}" ]] || current_ok=0
         [[ "${deploy_report_final_deployed_max}" == -1 || "${deployed}" -le "${deploy_report_final_deployed_max}" ]] || current_ok=0
         [[ "${deploy_report_final_shard_groups_max}" == -1 || "${shards}" -le "${deploy_report_final_shard_groups_max}" ]] || current_ok=0
         [[ "${deploy_report_max_crashes_max}" == -1 || "${crashes}" -le "${deploy_report_max_crashes_max}" ]] || current_ok=0
         runtime_resources_satisfied "${block}" || current_ok=0
         scaler_satisfied "${block}" || current_ok=0

         local now elapsed stable
         now="$(date +%s%3N)"
         elapsed=$((now - started))
         if [[ "${current_ok}" == 1 && "${elapsed}" -ge "${deploy_report_floor_min_runtime_ms}" ]]
         then
            [[ "${stable_since}" -gt 0 ]] || stable_since="${now}"
            stable=$((now - stable_since))
            if [[ "${stable}" -ge "${deploy_report_success_hold_ms}" ]]
            then
               echo "APPLICATION_REPORT_ASSERT success application=${deploy_report_application} healthy=${healthy} target=${target} deployed=${deployed} shards=${shards} crashes=${crashes}"
               return 0
            fi
         else
            stable_since=0
         fi
      fi

      if [[ "${deploy_ping_port}" -gt 0 && "${deploy_skip_probe}" == 0 && ( "${deploy_report_traffic_burst}" -gt 1 || -n "${deploy_report_require_scaler}" ) ]]
      then
         for _ in $(seq 1 "${deploy_report_traffic_burst}")
         do
            probe_once 0 || true
         done
      fi
      printf -v poll_sleep '%d.%03d' "$((deploy_report_poll_interval_ms / 1000))" "$((deploy_report_poll_interval_ms % 1000))"
      sleep "${poll_sleep}"
   done
   sed -n '1,260p' "${report}" >&2 || true
   return 1
}

if wait_application_report
then
   if [[ -n "${deploy_report_application}" ]]
   then
      container_logs "${deploy_report_application}" "${tmpdir}/container-logs.log" || fail "Mothership could not read container logs through the production control path"
      rg -q '^container=.* state=(running|failed) ' "${tmpdir}/container-logs.log" || fail "Mothership returned no container log entries"
      echo "MOTHERSHIP_CONTAINER_LOGS success application=${deploy_report_application}"
   fi
else
   if [[ -n "${deploy_report_application}" ]]
   then
      container_logs "${deploy_report_application}" "${tmpdir}/container-logs.log" || true
      sed -n '1,260p' "${tmpdir}/container-logs.log" >&2 || true
   fi
   fail "application report constraints were not satisfied"
fi

if [[ "${deploy_ping_port}" -gt 0 && "${deploy_skip_probe}" == 0 && "${PRODIGY_DEV_DEPLOY_SKIP_FINAL_PING:-0}" != 1 && "${deploy_ping_after_fault}" == 0 ]]
then
   probe_until_ready "${deploy_ping_all}" || fail "deployment probe did not become ready"
   echo "DEPLOY_PING success port=${deploy_ping_port}"
fi

if [[ -n "${mothership_update_prodigy_input}" ]]
then
   sleep "${mothership_update_start}"
   update_before="$(date +%s%3N)"
   "${mothership_bin}" updateProdigy "${cluster_name}" "${mothership_update_prodigy_input}" >"${tmpdir}/update.log" 2>&1 || {
      sed -n '1,240p' "${tmpdir}/update.log" >&2
      fail "updateProdigy failed"
   }
   wait_cluster_healthy || fail "cluster did not recover after updateProdigy"
   update_after="$(date +%s%3N)"
   [[ $((update_after - update_before)) -le "${update_order_budget_ms}" || "${update_order_budget_ms}" -eq 0 ]] || fail "updateProdigy exceeded its completion budget"
fi

emit_spin_snapshot()
{
   local pairs=
   local index
   for index in $(seq 1 "${machines}")
   do
      local log_path
      log_path="$(jq -r --argjson index "${index}" '.nodes[] | select(.index == $index) | .stdoutLog' "${provider_manifest}")"
      local count=0
      if [[ -r "${log_path}" ]]
      then
         count="$(rg -c -F 'neuron spinContainer deploymentID=' "${log_path}" 2>/dev/null || true)"
      fi
      [[ -z "${pairs}" ]] || pairs+=,
      pairs+="${index}:${count:-0}"
   done
   echo "DEPLOY_SPIN_SNAPSHOT hosts=${machines} counts=${pairs}"
}

resolve_fault_targets()
{
   local specification="$1"
   local report="${tmpdir}/fault-target-report.log"
   cluster_report "${report}" || return 1
   local master
   master="$(master_index_from_report "${report}")"
   case "${specification}" in
      master)
         [[ -n "${master}" ]] || return 1
         echo "${master}"
         ;;
      follower1|follower2)
         local wanted=1
         [[ "${specification}" == follower1 ]] || wanted=2
         mapfile -t followers < <(brain_indices_from_report "${report}" | awk -v master="${master}" '$1 != master')
         [[ "${#followers[@]}" -ge "${wanted}" ]] || return 1
         echo "${followers[$((wanted - 1))]}"
         ;;
      deployed)
         local deployed
         deployed="$(deployed_indices_from_report "${report}" | paste -sd, -)"
         [[ -n "${deployed}" ]] || return 1
         echo "${deployed}"
         ;;
      *)
         [[ "${specification}" =~ ^[0-9]+(,[0-9]+)*$ ]] || return 1
         local index
         IFS=, read -r -a indices <<< "${specification}"
         for index in "${indices[@]}"
         do
            [[ "${index}" -ge 1 && "${index}" -le "${machines}" ]] || return 1
         done
         echo "${specification}"
         ;;
   esac
}

if [[ -n "${fault_targets}" ]]
then
   sleep "${fault_start}"
   fault_report="${tmpdir}/fault-baseline.log"
   cluster_report "${fault_report}" || fail "could not report cluster before fault"
   fault_baseline_master="$(master_index_from_report "${fault_report}")"
   resolved_fault_targets="$(resolve_fault_targets "${fault_targets}")" || fail "could not resolve fault targets: ${fault_targets}"
   emit_spin_snapshot
   echo "FAULT_BASELINE index=${fault_baseline_master}"
   echo "FAULT_PLAN mode=${fault_mode} targets=${resolved_fault_targets} duration=${fault_duration}s"
   duration_ms=$((fault_duration * 1000))
   down_ms=$((fault_down * 1000))
   up_ms=$((fault_up * 1000))
   fault_log="${tmpdir}/fault.log"
   fault_started="$(date +%s%3N)"
   "${mothership_bin}" faultTestCluster "${cluster_name}" "${fault_mode}" "${resolved_fault_targets}" "${duration_ms}" "${fault_cycles}" "${down_ms}" "${up_ms}" >"${fault_log}" 2>&1 &
   fault_pid="$!"
   echo "FAULT_APPLIED mode=${fault_mode} targets=${resolved_fault_targets}"
   sleep 0.2
   fault_changed=0
   fault_none=0
   first_change_ms=0
   monitor_deadline=$((fault_started + (fault_duration > 0 ? fault_duration * 1000 : post_fault_window * 1000)))
   while kill -0 "${fault_pid}" >/dev/null 2>&1 || [[ "$(date +%s%3N)" -lt "${monitor_deadline}" ]]
   do
      sample="${tmpdir}/fault-sample.log"
      if cluster_report "${sample}"
      then
         sample_master="$(master_index_from_report "${sample}")"
         if [[ -z "${sample_master}" ]]
         then
            fault_none=1
         elif [[ "${sample_master}" != "${fault_baseline_master}" ]]
         then
            fault_changed=1
            [[ "${first_change_ms}" -gt 0 ]] || first_change_ms="$(date +%s%3N)"
         fi
      else
         fault_none=1
      fi
      sleep 0.1
   done
   wait "${fault_pid}" || {
      sed -n '1,200p' "${fault_log}" >&2
      fail "Mothership fault operation failed"
   }
   sed -n '1,80p' "${fault_log}"

   if [[ "${fault_duration}" -gt 0 ]]
   then
      wait_cluster_healthy || fail "cluster did not recover after transient fault"
   elif [[ "${post_fault_window}" -gt 0 ]]
   then
      sleep 0.2
   fi
   final_fault_report="${tmpdir}/fault-final.log"
   final_master=
   if cluster_report "${final_fault_report}"
   then
      final_master="$(master_index_from_report "${final_fault_report}")"
   fi
   echo "FAULT_RESULT index=${final_master:-0} changed=${fault_changed} unavailable=${fault_none}"

   if [[ "${expect_master_available}" == 1 && -z "${final_master}" ]]
   then
      fail "expected a master after fault"
   elif [[ "${expect_master_available}" == 0 && "${fault_none}" != 1 && -n "${final_master}" ]]
   then
      fail "expected no master during the fault"
   fi
   if [[ "${expect_master_change}" == 1 && ( -z "${final_master}" || "${final_master}" == "${fault_baseline_master}" ) ]]
   then
      fail "expected master change after fault"
   elif [[ "${expect_master_change}" == 0 && -n "${final_master}" && "${final_master}" != "${fault_baseline_master}" ]]
   then
      fail "expected master stability after fault"
   fi
   if [[ "${expect_master_change_during_fault}" == 1 && "${fault_changed}" != 1 ]]
   then
      fail "expected master change during fault"
   elif [[ "${expect_master_change_during_fault}" == 0 && "${fault_changed}" != 0 ]]
   then
      fail "unexpected master change during fault"
   fi
   if [[ "${first_change_ms}" -gt 0 && "${fault_master_change_budget_ms}" -gt 0 && $((first_change_ms - fault_started)) -gt "${fault_master_change_budget_ms}" ]]
   then
      fail "master failover exceeded its latency budget"
   fi
   if [[ "${expect_peer_recovery}" == 1 && "${fault_duration}" -gt 0 ]]
   then
      wait_cluster_healthy || fail "expected peer recovery after fault"
   fi
   if [[ "${deploy_ping_after_fault}" == 1 && "${deploy_skip_probe}" == 0 && "${deploy_ping_port}" -gt 0 ]]
   then
      probe_until_ready "${deploy_ping_all}" || fail "post-fault deployment probe did not recover"
      echo "POST_FAULT_DEPLOY_PING success port=${deploy_ping_port}"
   fi
fi

if [[ -n "${deploy_mesh_mode}" ]]
then
   [[ "${deploy_ping_port}" -gt 0 ]] || fail "mesh assertions require an application protocol probe"
   probe_until_ready "${deploy_mesh_require_all}" || fail "mesh application protocol assertion failed"
   echo "DEPLOY_MESH_ASSERT success mode=${deploy_mesh_mode}"
fi

if [[ "${expect_full_brain_registration}" == 1 ]]
then
   final_registration_report="${tmpdir}/full-registration.log"
   cluster_report "${final_registration_report}" || fail "full registration report failed"
   registered="$(rg -c '^[[:space:]]*Machine: state=healthy role=brain ' "${final_registration_report}" 2>/dev/null || true)"
   [[ "${registered:-0}" -ge "${brains}" ]] || fail "not all brains are registered"
fi

if [[ "${os_update_restart_on_command}" == 1 ]]
then
   wait_cluster_healthy || fail "cluster did not recover from its configured OS update"
fi

for substring in "${required_log_substrings[@]}"
do
   found=0
   for _ in $(seq 1 "${PRODIGY_DEV_REQUIRE_BRAIN_LOG_ATTEMPTS:-180}")
   do
      while IFS= read -r log_path
      do
         if [[ -r "${log_path}" ]] && rg -Fq "${substring}" "${log_path}"
         then
            found=1
            break
         fi
      done < <(jq -r '.nodes[] | select(.role == "brain") | .stdoutLog' "${provider_manifest}")
      [[ "${found}" == 0 ]] || break
      sleep 0.2
   done
   [[ "${found}" == 1 ]] || fail "brain logs omitted required substring: ${substring}"
   echo "BRAIN_LOG_ASSERT success substring='${substring}'"
done

final_report="${tmpdir}/cluster-final.log"
final_master=
if cluster_report "${final_report}"
then
   final_master="$(master_index_from_report "${final_report}")"
elif [[ "${expect_master_available}" != 0 ]]
then
   fail "final cluster report failed"
fi
if [[ "${expect_master_available}" == 1 && -z "${final_master}" ]]
then
   fail "final cluster report has no master"
fi
echo "PRODIGY_DEV_HARNESS_PASS cluster=${cluster_name} masterIndex=${final_master:-0}"
