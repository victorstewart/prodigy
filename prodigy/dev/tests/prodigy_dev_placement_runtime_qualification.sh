#!/usr/bin/env bash
# Mothership-client qualification for a single stateless constructive successor.
# Cluster creation, deployment, policy commit, and removal are ordinary
# Mothership operations. This client never enters a test namespace or
# manipulates a provider/runtime resource directly.
set -Eeuo pipefail

if [[ "${1:-}" == "--validate-only" && "$#" -eq 1 ]]
then
   bash -n "$0"
   printf 'placement runtime qualification client syntax is valid\n'
   exit 0
fi

prodigy_bin="${1:-}"
mothership_bin="${2:-}"
application_artifact="${3:-}"
application_plan="${4:-}"
[[ "$#" -eq 4 && -x "${prodigy_bin}" && -x "${mothership_bin}" && -r "${application_artifact}" && -r "${application_plan}" ]] || {
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/discombobulator-app.zst /path/to/app.plan.json" >&2
   exit 2
}
[[ "${EUID}" -eq 0 ]] || { echo "SKIP: Mothership test clusters require root" >&2; exit 77; }

for command in jq rg timeout date mktemp readlink sed awk sort sha256sum sleep wc python3
 do
   command -v "${command}" >/dev/null || { echo "SKIP: missing required command: ${command}" >&2; exit 77; }
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/../../.." && pwd -P)"
prodigy_bin="$(readlink -f "${prodigy_bin}")"
mothership_bin="$(readlink -f "${mothership_bin}")"
application_artifact="$(readlink -f "${application_artifact}")"
application_plan="$(readlink -f "${application_plan}")"
[[ "$(dirname "${prodigy_bin}")" == "$(dirname "${mothership_bin}")" ]] || {
   echo "FAIL: Prodigy and Mothership must be sibling release artifacts" >&2
   exit 1
}
jq -e '.config.type == "ApplicationType::stateless" and (.isStateful // false | not) and .moveConstructively == true' "${application_plan}" >/dev/null || {
   echo "FAIL: application plan must be a stateless constructive deployment" >&2
   exit 1
}

run_root="$(mktemp -d "${repo_root}/.run/prodigy-placement-runtime.XXXXXX")"
registry_path="${run_root}/mothership.tidesdb"
receipts_dir="${run_root}/timing-receipts"
cluster_name="placement-runtime-${$}-${RANDOM}"
workspace="${run_root}/workspace"
provider_manifest="${workspace}/test-cluster-manifest.json"
application_name="PlacementRuntime.${$}.${RANDOM}"
service_name="server"
application_id=
cluster_attempted=0
mkdir -p "${receipts_dir}"
sha256sum "${prodigy_bin}" "${mothership_bin}" "${application_artifact}" "${application_plan}" >"${run_root}/artifact-identities.sha256"
printf 'scenario=stateless-constructive-placement machines=3 brains=3 cores=4 memoryMB=8192 storageMB=8192\n' >"${run_root}/scenario.txt"
cat >"${run_root}/limitations.txt" <<'EOF_LIMITATIONS'
This client records Mothership report observations. The normal report APIs do not
expose a container or advertised-service endpoint for useHostNetworkNamespace=false,
so this scenario does not guess a machine address or claim application continuity.
The scenario qualifies one target-only constructive successor under one authority.
EOF_LIMITATIONS

mship()
{
   local label="$1" timeout_seconds="$2" log_path="$3"
   shift 3
   local started ended status
   started="$(date +%s%3N)"
   if timeout "${timeout_seconds}s" env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${registry_path}" "${mothership_bin}" "$@" >"${log_path}" 2>&1
   then status=0
   else status=$?
   fi
   ended="$(date +%s%3N)"
   jq -nc --arg label "${label}" --arg operation "$1" --argjson status "${status}" \
      --argjson startedMs "${started}" --argjson endedMs "${ended}" \
      '{label:$label,operation:$operation,status:$status,startedMs:$startedMs,endedMs:$endedMs}' \
      >"${receipts_dir}/${label}-${started}-${BASHPID}.json"
   return "${status}"
}

require_success()
{
   local log="$1" operation="$2"
   rg -q "(^|[[:space:]])${operation} success=1([[:space:]]|$)" "${log}" || {
      sed -n '1,240p' "${log}" >&2 || true
      return 1
   }
}

remove_cluster()
{
   local log="$1"
   if mship remove 120 "${log}" removeCluster "${cluster_name}"
   then require_success "${log}" removeCluster
   elif rg -q "removeCluster success=0 removed=0 identity=${cluster_name} failure=record not found" "${log}"
   then return 0
   else
      sed -n '1,240p' "${log}" >&2 || true
      return 1
   fi
}

cleanup()
{
   local status="$?"
   trap - EXIT HUP INT TERM
   set +e
   if [[ "${cluster_attempted}" == 1 ]]
   then remove_cluster "${run_root}/remove-cleanup.log" || status=1
   fi
   if [[ -e "${provider_manifest}" ]]
   then
      echo "FAIL: provider manifest remains after Mothership cleanup" >&2
      status=1
   fi
   printf '{"result":"%s","clusterCreateAttempted":%s}\n' \
      "$([[ "${status}" -eq 0 ]] && echo pass || echo fail)" "${cluster_attempted}" >"${run_root}/result.json"
   echo "PLACEMENT_RUNTIME_QUALIFICATION_EVIDENCE=${run_root}"
   exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

create_request="$(jq -nc --arg name "${cluster_name}" --arg workspace "${workspace}" '
  {name:$name,deploymentMode:"test",nBrains:3,autoscaleIntervalSeconds:180,
   machineSchemas:[{schema:"placement-runtime-machine",kind:"vm",vmImageURI:"test://virtual-datacenter"}],
   test:{workspaceRoot:$workspace,machineCount:3,machineLogicalCores:4,machineMemoryMB:8192,
         machineStorageMB:8192,brainBootstrapFamily:"ipv4",enableFakeIpv4Boundary:false,
         interContainerMTU:1500}}')"
printf '%s\n' "${create_request}" >"${run_root}/create-request.json"
cluster_attempted=1
mship create 180 "${run_root}/create.log" createCluster "${create_request}" || { sed -n '1,260p' "${run_root}/create.log" >&2; exit 1; }
require_success "${run_root}/create.log" createCluster || { echo "FAIL: createCluster returned no success receipt" >&2; exit 1; }

cluster_report()
{
   mship "report-$1" 8 "${run_root}/cluster-$1.log" clusterReport "${cluster_name}"
}
application_report()
{
   mship "application-$1" 8 "${run_root}/application-$1.log" applicationReport "${cluster_name}" "${application_name}"
}
cluster_ready()
{
   local report="$1"
   [[ "$(rg -c '^[[:space:]]*Machine: state=healthy role=brain' "${report}" || true)" -eq 3 ]] &&
      [[ "$(rg -c '^[[:space:]]*lifecycle controlPlaneReachable=1 runtimeReady=1 ' "${report}" || true)" -eq 3 ]]
}
wait_cluster_ready()
{
   local deadline=$(( $(date +%s%3N) + 90000 ))
   while [[ "$(date +%s%3N)" -lt "${deadline}" ]]
   do
      cluster_report ready && cluster_ready "${run_root}/cluster-ready.log" && return 0
      sleep 0.2
   done
   sed -n '1,260p' "${run_root}/cluster-ready.log" >&2 || true
   return 1
}
wait_cluster_ready || { echo "FAIL: cluster did not reach three healthy ready Brains" >&2; exit 1; }

reserve_request="$(jq -nc --arg name "${application_name}" '{applicationName:$name,requestedApplicationID:1000,createIfMissing:true}')"
mship reserve-application 20 "${run_root}/reserve-application.log" reserveApplicationID "${cluster_name}" "${reserve_request}" || exit 1
require_success "${run_root}/reserve-application.log" reserveApplicationID || { echo "FAIL: application reservation failed" >&2; exit 1; }
application_id="$(rg -m1 -o 'appID=[0-9]+' "${run_root}/reserve-application.log" | sed 's/appID=//')"
[[ "${application_id}" =~ ^[1-9][0-9]*$ ]] || { echo "FAIL: reservation omitted application ID" >&2; exit 1; }
service_request="$(jq -nc --arg app "${application_name}" --arg service "${service_name}" --argjson appID "${application_id}" \
   '{applicationName:$app,applicationID:$appID,serviceName:$service,kind:"stateless",createIfMissing:true}')"
mship reserve-service 20 "${run_root}/reserve-service.log" reserveServiceID "${cluster_name}" "${service_request}" || exit 1
require_success "${run_root}/reserve-service.log" reserveServiceID || { echo "FAIL: service reservation failed" >&2; exit 1; }

app_reference="\${application:${application_name}}"
service_reference="\${service:${application_name}/${service_name}}"
base_plan="${run_root}/version-1.plan.json"
successor_plan="${run_root}/version-2.plan.json"
jq --arg appref "${app_reference}" --arg serviceref "${service_reference}" '
  .config.applicationID = $appref
  | .config.versionID = 1
  | .apiCredentials.applicationID = $appref
  | .advertisements |= map(.service = $serviceref)
  | .moveConstructively = true
' "${application_plan}" >"${base_plan}"
jq '.config.versionID = 2 | .moveConstructively = true' "${base_plan}" >"${successor_plan}"

deploy()
{
   local label="$1" plan="$2"
   local payload
   payload="$(jq -c . "${plan}")"
   mship "deploy-${label}" 45 "${run_root}/deploy-${label}.log" deploy "${cluster_name}" "${payload}" "${application_artifact}"
}

deployment_id()
{
   local version="$1"
   printf '%s\n' "$(( (application_id << 48) | version ))"
}
source_deployment_id="$(deployment_id 1)"
successor_deployment_id="$(deployment_id 2)"

deploy v1 "${base_plan}" || { sed -n '1,240p' "${run_root}/deploy-v1.log" >&2; exit 1; }
rg -q "SpinApplicationResponseCode::okay" "${run_root}/deploy-v1.log" || { sed -n '1,240p' "${run_root}/deploy-v1.log" >&2; echo "FAIL: initial deployment was not accepted" >&2; exit 1; }

machine_for_deployment()
{
   local report="$1" deployment="$2"
   awk -v deployment="${deployment}" '
      /^[[:space:]]*Machine:/ { uuid="" }
      /^[[:space:]]*identity uuid=/ {
        line=$0; sub(/^.*identity uuid=/,"",line); sub(/[[:space:]].*$/,"",line); uuid=line
      }
      /^[[:space:]]*placement containers=/ {
        line=$0; sub(/^.*deploymentIDs=/,"",line); sub(/[[:space:]].*$/,"",line)
        # Deployment IDs exceed exact IEEE-754 integer range. Force textual
        # equality so adjacent versions never collapse to the same number.
        n=split(line, ids, ","); for (i=1; i<=n; ++i) if (("id:" ids[i]) == ("id:" deployment) && uuid != "") print uuid
      }' "${report}" | sort -u
}
all_machine_uuids()
{
   awk '/^[[:space:]]*identity uuid=/ { line=$0; sub(/^.*identity uuid=/,"",line); sub(/[[:space:]].*$/,"",line); print line }' "$1" | sort -u
}
version_healthy()
{
   local report="$1" version="$2"
   awk -v version="${version}" '
      /^[[:space:]]*versionID:/ { in_version=($2 == version); next }
      in_version && /^[[:space:]]*state:/ { state=$2 }
      in_version && /^[[:space:]]*nHealthy:/ { healthy=$2; if (state == "DeploymentState::running" && healthy >= 1) ok=1 }
      END { exit(ok ? 0 : 1) }' "${report}"
}
wait_initial()
{
   local deadline=$(( $(date +%s%3N) + 90000 ))
   while [[ "$(date +%s%3N)" -lt "${deadline}" ]]
   do
      application_report initial || true
      cluster_report initial || true
      if version_healthy "${run_root}/application-initial.log" 1
      then
         initial_source="$(machine_for_deployment "${run_root}/cluster-initial.log" "${source_deployment_id}")"
         [[ "$(wc -l <<<"${initial_source}")" -eq 1 ]] && [[ "${initial_source}" =~ ^0x[0-9a-f]+$ ]] && return 0
      fi
      sleep 0.25
   done
   return 1
}
wait_initial || { sed -n '1,260p' "${run_root}/application-initial.log" >&2 || true; sed -n '1,260p' "${run_root}/cluster-initial.log" >&2 || true; echo "FAIL: initial version was not healthy on one authoritative machine" >&2; exit 1; }
source_uuid="${initial_source}"
destination_uuid="$(all_machine_uuids "${run_root}/cluster-initial.log" | awk -v source="${source_uuid}" '$0 != source { print; exit }')"
[[ "${destination_uuid}" =~ ^0x[0-9a-f]+$ && "${destination_uuid}" != "${source_uuid}" ]] || { echo "FAIL: authoritative report did not expose a distinct destination UUID" >&2; exit 1; }
printf 'sourceMachineUUID=%s\ndestinationMachineUUID=%s\napplicationID=%s\n' "${source_uuid}" "${destination_uuid}" "${application_id}" >>"${run_root}/scenario.txt"

operation_id="$(python3 - "${cluster_name}" "${application_id}" "${source_uuid}" "${destination_uuid}" <<'PYTHON_UUID'
import sys
import uuid
print(uuid.uuid5(uuid.NAMESPACE_URL, ':'.join(sys.argv[1:])))
PYTHON_UUID
)"
policy="$(jq -nc --arg operation "${operation_id}" --arg destination "${destination_uuid}" --argjson applicationID "${application_id}" \
   '{applicationID:$applicationID,versionID:2,operationID:$operation,eligibleMachineUUIDs:[$destination]}')"
printf '%s\n' "${policy}" >"${run_root}/placement-policy.json"
mship placement-policy 30 "${run_root}/placement-policy.log" placementPolicy "${cluster_name}" "${policy}" || { sed -n '1,240p' "${run_root}/placement-policy.log" >&2; exit 1; }
rg -q 'placementPolicy success=1 ' "${run_root}/placement-policy.log" || { sed -n '1,240p' "${run_root}/placement-policy.log" >&2; echo "FAIL: target-only placement policy was rejected" >&2; exit 1; }

deploy v2 "${successor_plan}" || { sed -n '1,240p' "${run_root}/deploy-v2.log" >&2; exit 1; }
rg -q "SpinApplicationResponseCode::okay" "${run_root}/deploy-v2.log" || { sed -n '1,240p' "${run_root}/deploy-v2.log" >&2; echo "FAIL: constructive successor deployment was not accepted" >&2; exit 1; }


wait_successor()
{
   local deadline=$(( $(date +%s%3N) + 120000 ))
   while [[ "$(date +%s%3N)" -lt "${deadline}" ]]
   do
      application_report successor || true
      cluster_report successor || true
      local successor_machine active_machine
      successor_machine="$(machine_for_deployment "${run_root}/cluster-successor.log" "${successor_deployment_id}")"
      active_machine="$(machine_for_deployment "${run_root}/cluster-successor.log" "${source_deployment_id}")"
      if version_healthy "${run_root}/application-successor.log" 2 &&
         [[ "${successor_machine}" == "${destination_uuid}" ]] && [[ -z "${active_machine}" ]]
      then return 0
      fi
      sleep 0.25
   done
   return 1
}

wait_successor || { sed -n '1,260p' "${run_root}/application-successor.log" >&2 || true; sed -n '1,260p' "${run_root}/cluster-successor.log" >&2 || true; echo "FAIL: successor did not become healthy on the policy target while retiring the source version" >&2; exit 1; }
printf 'sourceVersionRetired=1\nsuccessorHealthy=1\nsuccessorMachineUUID=%s\n' \
   "${destination_uuid}" >>"${run_root}/scenario.txt"

echo "PLACEMENT_RUNTIME_QUALIFICATION success=1 source=${source_uuid} destination=${destination_uuid}"
