#!/usr/bin/env bash
# Deterministic Mothership-client lifecycle qualification only.  It does not
# deploy an application and therefore does not qualify migration.
set -Eeuo pipefail

if [[ "${1:-}" == "--validate-only" && "$#" -eq 1 ]]
then
   bash -n "$0"
   printf 'two-cluster coexistence client syntax is valid\n'
   exit 0
fi

prodigy_bin="${1:-}"
mothership_bin="${2:-}"
[[ "$#" -eq 2 && -x "${prodigy_bin}" && -x "${mothership_bin}" ]] || {
   echo "usage: $0 /path/to/prodigy /path/to/mothership" >&2
   exit 2
}
[[ "${EUID}" -eq 0 ]] || { echo "SKIP: Mothership test clusters require root" >&2; exit 77; }

for command in jq rg timeout sha256sum date mktemp uname sleep readlink sort comm sed grep seq stat cp uniq cut wc awk tail
 do
   command -v "${command}" >/dev/null || { echo "SKIP: missing required command: ${command}" >&2; exit 77; }
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/../../.." && pwd -P)"
prodigy_bin="$(readlink -f "${prodigy_bin}")"
mothership_bin="$(readlink -f "${mothership_bin}")"
[[ "$(dirname "${prodigy_bin}")" == "$(dirname "${mothership_bin}")" ]] || {
   echo "FAIL: Prodigy and Mothership must be sibling release artifacts" >&2
   exit 1
}

case "$(uname -m)" in
   x86_64) bundle_arch=x86_64 ;;
   aarch64|arm64) bundle_arch=aarch64 ;;
   riscv64) bundle_arch=riscv64 ;;
   *) echo "SKIP: unsupported bundle architecture $(uname -m)" >&2; exit 77 ;;
esac
bundle_path="$(dirname "${prodigy_bin}")/prodigy.${bundle_arch}.bundle.tar.zst"
[[ -r "${bundle_path}" ]] || { echo "FAIL: required sibling bundle is unreadable: ${bundle_path}" >&2; exit 1; }

run_root="$(mktemp -d "${repo_root}/.run/prodigy-two-cluster-coexistence.XXXXXX")"
registry_path="${run_root}/mothership.tidesdb"
receipts_dir="${run_root}/timing-receipts"
identities_path="${run_root}/artifact-identities.sha256"
limitations_path="${run_root}/limitations.txt"
bundle_sha256="$(sha256sum "${bundle_path}" | awk '{print $1}')"
first_name="two-cluster-a-$$-${RANDOM}"
second_name="two-cluster-b-$$-${RANDOM}"
first_workspace="${run_root}/workspace-a"
second_workspace="${run_root}/workspace-b"
first_manifest="${first_workspace}/test-cluster-manifest.json"
second_manifest="${second_workspace}/test-cluster-manifest.json"
first_attempted=0
second_attempted=0
bootstrap_observer_pid=

mkdir -p "${receipts_dir}"
sha256sum "${prodigy_bin}" "${mothership_bin}" "${bundle_path}" >"${identities_path}"
printf 'scenario=two-cluster-coexistence migrationCoverage=0 fakeBoundary=0 machinesPerCluster=3 brainsPerCluster=3\n' >"${run_root}/scenario.txt"
cat >"${limitations_path}" <<'EOF'
This is lifecycle coexistence coverage only; it does not deploy a workload or qualify migration.
clusterReport exposes readiness and approved installed-bundle identity, but not packet-level proof that the first link was down.
The fault command and each report are separate Mothership processes. Fault-window observations use Mothership clusterReport local with the exact control socket published by the second cluster provider, avoiding registry writes during observation. Named-target clusterReport refreshes the local registry and competing CLI processes currently fail fast on its TidesDB lock; concurrent registry command handling is not qualified by this scenario. Reports are issued serially and their overlap is recorded from command timing receipts.
EOF

mship()
{
   local label="$1"
   local timeout_seconds="$2"
   local log_path="$3"
   shift 3
   local started status ended
   started="$(date +%s%3N)"
   if timeout "${timeout_seconds}s" env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${registry_path}" "${mothership_bin}" "$@" >"${log_path}" 2>&1
   then
      status=0
   else
      status=$?
   fi
   ended="$(date +%s%3N)"
   jq -nc --arg operation "$1" --arg label "${label}" --argjson status "${status}" \
      --argjson startedMs "${started}" --argjson endedMs "${ended}" \
      '{operation:$operation,label:$label,status:$status,startedMs:$startedMs,endedMs:$endedMs}' \
      >"${receipts_dir}/${label}-${started}-${BASHPID}.json"
   return "${status}"
}

require_success_receipt()
{
   local log_path="$1"
   local operation="$2"
   rg -q "(^|[[:space:]])${operation} success=1([[:space:]]|$)" "${log_path}" || {
      sed -n '1,220p' "${log_path}" >&2 || true
      echo "FAIL: ${operation} did not return its exact success receipt" >&2
      return 1
   }
}

remove_cluster()
{
   local name="$1"
   local log_path="$2"
   if mship "remove-${name}" 120 "${log_path}" removeCluster "${name}"
   then
      require_success_receipt "${log_path}" removeCluster
      return
   fi
   # A create can fail before the registry transaction.  Only this exact
   # Mothership receipt proves that the attempted identity was never recorded.
   if rg -q "removeCluster success=0 removed=0 identity=${name} failure=record not found" "${log_path}"
   then
      return
   fi
   sed -n '1,220p' "${log_path}" >&2 || true
   return 1
}

cleanup()
{
   local status="$?"
   trap - EXIT HUP INT TERM
   set +e
   if [[ -n "${bootstrap_observer_pid}" ]]
   then
      kill "${bootstrap_observer_pid}" 2>/dev/null || true
      wait "${bootstrap_observer_pid}" 2>/dev/null || true
   fi
   if [[ "${first_attempted}" == 1 ]]
   then
      remove_cluster "${first_name}" "${run_root}/remove-first-cleanup.log" || status=1
   fi
   if [[ "${second_attempted}" == 1 ]]
   then
      remove_cluster "${second_name}" "${run_root}/remove-second-cleanup.log" || status=1
   fi
   if [[ -n "${fault_pid:-}" ]]
   then
      wait "${fault_pid}" || true
   fi
   if [[ -e "${first_manifest}" || -e "${second_manifest}" ]]
   then
      echo "FAIL: provider manifest remains after Mothership cleanup" >&2
      status=1
   fi
   printf '{"result":"%s","firstCreateAttempted":%s,"secondCreateAttempted":%s}\n' \
      "$([[ "${status}" -eq 0 ]] && echo pass || echo fail)" "${first_attempted}" "${second_attempted}" >"${run_root}/result.json"
   echo "TWO_CLUSTER_COEXISTENCE_EVIDENCE=${run_root}"
   exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

create_request()
{
   local name="$1"
   local workspace="$2"
   jq -nc --arg name "${name}" --arg workspace "${workspace}" \
      '{name:$name,deploymentMode:"test",nBrains:3,autoscaleIntervalSeconds:180,
        machineSchemas:[{schema:"coexistence-machine",kind:"vm",vmImageURI:"test://virtual-datacenter"}],
        test:{workspaceRoot:$workspace,machineCount:3,machineLogicalCores:4,machineMemoryMB:8192,
              machineStorageMB:8192,brainBootstrapFamily:"ipv4",enableFakeIpv4Boundary:false,
              interContainerMTU:1500}}'
}

create_cluster()
{
   local name="$1"
   local workspace="$2"
   local log_path="$3"
   local request
   request="$(create_request "${name}" "${workspace}")"
   printf '%s\n' "${request}" >"${run_root}/${name}-request.json"
   # Creation can remove its provider on failure. Preserve bounded read-only
   # observations while it runs, before the owner removes those log files.
   (
      while true
      do
         for machine_index in 1 2 3
         do
            machine_log="${workspace}/machine${machine_index}.log"
            if [[ -r "${machine_log}" ]]
            then
               tail -c 1048576 "${machine_log}" >"${run_root}/${name}-machine${machine_index}-bootstrap.log" || true
            fi
         done
         sleep 1
      done
   ) &
   bootstrap_observer_pid="$!"
   local create_status=0
   mship "create-${name}" 180 "${log_path}" createCluster "${request}" || create_status="$?"
   kill "${bootstrap_observer_pid}" 2>/dev/null || true
   wait "${bootstrap_observer_pid}" 2>/dev/null || true
   bootstrap_observer_pid=
   if [[ "${create_status}" != 0 ]]
   then
      sed -n '1,260p' "${log_path}" >&2 || true
      return 1
   fi
   require_success_receipt "${log_path}" createCluster
}

report_cluster()
{
   local name="$1"
   local log_path="$2"
   local label="${3:-report-${name}}"
   mship "${label}" 8 "${log_path}" clusterReport "${name}"
}

require_healthy_three()
{
   local report="$1"
   [[ "$(rg -c '^[[:space:]]*Machine: state=healthy ' "${report}" || true)" -eq 3 ]] &&
      [[ "$(rg -c '^[[:space:]]*lifecycle controlPlaneReachable=1 runtimeReady=1 ' "${report}" || true)" -eq 3 ]] &&
      [[ "$(rg -c '^[[:space:]]*Machine: state=healthy role=brain' "${report}" || true)" -eq 3 ]] &&
      [[ "$(rg -c -F "approvedBundleSHA256=${bundle_sha256}" "${report}" || true)" -eq 3 ]]
}

wait_healthy()
{
   local name="$1"
   local prefix="$2"
   local report="${run_root}/${prefix}-report.log"
   local deadline_ms=$(( $(date +%s%3N) + 90000 ))
   while [[ "$(date +%s%3N)" -lt "${deadline_ms}" ]]
   do
      if report_cluster "${name}" "${report}" "${prefix}-ready" && require_healthy_three "${report}"
      then
         return 0
      fi
      sleep 0.2
   done
   sed -n '1,260p' "${report}" >&2 || true
   return 1
}

read_cluster_uuid()
{
   rg -o 'clusterUUID=0x[0-9a-f]+' "$1" | head -n1 | cut -d= -f2
}

assert_distinct_boundaries()
{
   local first_uuid second_uuid first_v4 second_v4 first_v6 second_v6
   first_uuid="$(read_cluster_uuid "${run_root}/create-first.log")"
   second_uuid="$(read_cluster_uuid "${run_root}/create-second.log")"
   [[ -n "${first_uuid}" && -n "${second_uuid}" && "${first_uuid}" != "${second_uuid}" ]] || return 1
   first_v4="$(jq -r '.privateIPv4Subnet' "${first_manifest}")"
   second_v4="$(jq -r '.privateIPv4Subnet' "${second_manifest}")"
   first_v6="$(jq -r '.privateIPv6Subnet' "${first_manifest}")"
   second_v6="$(jq -r '.privateIPv6Subnet' "${second_manifest}")"
   [[ "${first_v4}" != "${second_v4}" && "${first_v6}" != "${second_v6}" ]] || return 1
   cp -- "${first_manifest}" "${run_root}/first-manifest.json"
   cp -- "${second_manifest}" "${run_root}/second-manifest.json"
   local first_ca second_ca
   first_ca="$(jq -er '.clusterRootCertPem | select(type == "string" and length > 0)' "${first_workspace}/transport-tls/1.json" | sha256sum | cut -d ' ' -f 1)"
   second_ca="$(jq -er '.clusterRootCertPem | select(type == "string" and length > 0)' "${second_workspace}/transport-tls/1.json" | sha256sum | cut -d ' ' -f 1)"
   [[ -n "${first_ca}" && -n "${second_ca}" && "${first_ca}" != "${second_ca}" ]] || return 1
   printf 'firstCAFingerprint=%s\nsecondCAFingerprint=%s\n' "${first_ca}" "${second_ca}" >>"${run_root}/scenario.txt"
   local manifest provider_pid namespace namespace_path
   : >"${run_root}/namespace-identities.txt"
   for manifest in "${first_manifest}" "${second_manifest}"
   do
      provider_pid="$(jq -er '.parentPid | select(type == "number" and . > 1)' "${manifest}")"
      while IFS= read -r namespace
      do
         namespace_path="/proc/${provider_pid}/root/var/run/netns/${namespace}"
         stat -Lc '%d:%i' "${namespace_path}" >>"${run_root}/namespace-identities.txt" || return 1
      done < <(jq -er '.parentNamespace, (.nodes[] | .namespace)' "${manifest}")
   done
   [[ "$(sort -u "${run_root}/namespace-identities.txt" | wc -l)" -eq 8 ]] || return 1
   local shared_namespaces
   shared_namespaces="$(comm -12 \
      <(jq -r '.parentNamespace, (.nodes[] | .namespace)' "${first_manifest}" | sort -u) \
      <(jq -r '.parentNamespace, (.nodes[] | .namespace)' "${second_manifest}" | sort -u))"
   [[ -z "${shared_namespaces}" ]] || return 1
   jq -e '.machineCount == 3 and .brainCount == 3 and (.privateIPv4Subnet != "") and ((.nodes | length) == 3)' \
      "${first_manifest}" >/dev/null
   jq -e '.machineCount == 3 and .brainCount == 3 and (.privateIPv4Subnet != "") and ((.nodes | length) == 3)' \
      "${second_manifest}" >/dev/null
   printf 'firstClusterUUID=%s\nsecondClusterUUID=%s\nfirstPrivateIPv4=%s\nsecondPrivateIPv4=%s\nfirstPrivateIPv6=%s\nsecondPrivateIPv6=%s\n' \
      "${first_uuid}" "${second_uuid}" "${first_v4}" "${second_v4}" "${first_v6}" "${second_v6}" >>"${run_root}/scenario.txt"
}

first_attempted=1
create_cluster "${first_name}" "${first_workspace}" "${run_root}/create-first.log"
second_attempted=1
create_cluster "${second_name}" "${second_workspace}" "${run_root}/create-second.log"
wait_healthy "${first_name}" first-initial || { echo "FAIL: first cluster did not reach three healthy ready Brains" >&2; exit 1; }
wait_healthy "${second_name}" second-initial || { echo "FAIL: second cluster did not reach three healthy ready Brains" >&2; exit 1; }
assert_distinct_boundaries || { echo "FAIL: two Mothership-managed clusters do not have distinct UUID, private prefix, and namespace boundaries" >&2; exit 1; }

fault_log="${run_root}/fault-first-link.log"
mship fault-first-link 30 "${fault_log}" faultTestCluster "${first_name}" link 1 5000 0 0 0 &
fault_pid="$!"
fault_samples=0
fault_attempts=0
fault_unhealthy_samples=0
fault_failed_reports=0
fault_deadline_ms=$(( $(date +%s%3N) + 30000 ))
while kill -0 "${fault_pid}" >/dev/null 2>&1 && [[ "$(date +%s%3N)" -lt "${fault_deadline_ms}" ]]
do
   sample_log="${run_root}/second-during-first-fault-${fault_attempts}.log"
   sample_label="second-during-first-fault-${fault_attempts}"
   fault_attempts=$((fault_attempts + 1))
   # A named report also refreshes Mothership's on-disk registry. This is an
   # observation of the live cluster during a provider fault, so use the
   # existing read-only local report operation at its published control socket.
   second_control_socket="$(jq -er '.controlSocketPath | select(type == "string" and length > 0)' "${second_manifest}")"
   if PRODIGY_MOTHERSHIP_SOCKET="${second_control_socket}" \
      mship "${sample_label}" 8 "${sample_log}" clusterReport local
   then
      fault_samples=$((fault_samples + 1))
      require_healthy_three "${sample_log}" || fault_unhealthy_samples=$((fault_unhealthy_samples + 1))
   else
      fault_failed_reports=$((fault_failed_reports + 1))
   fi
   sleep 0.1
done
wait "${fault_pid}" || { sed -n '1,220p' "${fault_log}" >&2 || true; echo "FAIL: Mothership fault operation failed" >&2; exit 1; }
require_success_receipt "${fault_log}" faultTestCluster
fault_overlap_samples="$(jq -s '[.[] | select(.label == "fault-first-link")] as $fault | if ($fault | length) != 1 then 0 else $fault[0] as $window | [.[] | select(.label | startswith("second-during-first-fault-")) | select(.startedMs < $window.endedMs and .endedMs > $window.startedMs)] | length end' "${receipts_dir}"/*.json)"
printf 'faultSamples=%s faultUnhealthySamples=%s faultFailedReports=%s faultOverlapSamples=%s\n' \
   "${fault_samples}" "${fault_unhealthy_samples}" "${fault_failed_reports}" "${fault_overlap_samples}" >>"${run_root}/scenario.txt"
[[ "${fault_samples}" -gt 0 && "${fault_unhealthy_samples}" -eq 0 && "${fault_failed_reports}" -eq 0 && "${fault_overlap_samples}" -gt 0 ]] || {
   echo "FAIL: second-cluster health was not continuously observed during the active first-cluster fault command" >&2
   exit 1
}
wait_healthy "${first_name}" first-restored || { echo "FAIL: first cluster did not recover after its ordinary bounded fault" >&2; exit 1; }
wait_healthy "${second_name}" second-after-fault || { echo "FAIL: first-cluster fault affected second cluster" >&2; exit 1; }

remove_cluster "${first_name}" "${run_root}/remove-first.log"
first_attempted=0
[[ ! -e "${first_manifest}" ]] || { echo "FAIL: first provider manifest remains after removeCluster receipt" >&2; exit 1; }
wait_healthy "${second_name}" second-after-first-remove || { echo "FAIL: removing first cluster affected second cluster" >&2; exit 1; }
remove_cluster "${second_name}" "${run_root}/remove-second.log"
second_attempted=0
[[ ! -e "${second_manifest}" ]] || { echo "FAIL: second provider manifest remains after removeCluster receipt" >&2; exit 1; }
printf 'coexistenceLifecycle=passed\n' >>"${run_root}/scenario.txt"
