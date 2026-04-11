#!/usr/bin/env bash
set -euo pipefail

# Low-level isolated netns runner used underneath Mothership test clusters.
# For persistent fake clusters, prefer `mothership createCluster` with
# `deploymentMode: "test"` and use this harness directly only for low-level
# debugging, harness development, or matrix/smoke flows that intentionally
# exercise harness-only behavior.

PRODIGY_BIN="${1:-}"
shift || true

if [[ -z "${PRODIGY_BIN}" || ! -x "${PRODIGY_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy [--runner-mode=oneshot|persistent] [--workspace-root=/abs/path] [--manifest-path=/abs/path.json] [--machines=COUNT] [--brains=COUNT] [--duration=SECONDS] [--brain-bootstrap-family=ipv4|private6|public6|multihome6] [--tunnel-ebpf=/path/to/object] [--host-ingress-ebpf=/path/to/object] [--host-egress-ebpf=/path/to/object] [--enable-fake-ipv4-boundary=0|1] [--fake-ipv4-boundary-ebpf=/path/to/object] [--switchboard-gateway-index=INDEX] [--mothership-bin=/path/to/mothership] [--mothership-autoscale-interval-seconds=SECONDS] [--mothership-update-prodigy-input=/path/to/new/prodigy-or-bundle] [--mothership-update-start=SECONDS] [--master-index=0|1|2|3 (deprecated; ignored)] [--fault-mode=link|crash|flap] [--fault-targets=master|deployed|1|2|3|csv] [--fault-start=SECONDS] [--fault-start-on-ready=0|1] [--fault-duration=SECONDS] [--fault-cycles=COUNT] [--fault-down=SECONDS] [--fault-up=SECONDS] [--post-fault-window=SECONDS] [--expect-master-available=0|1] [--expect-master-change=0|1] [--expect-master-change-during-fault=0|1] [--expect-peer-recovery=0|1] [--deploy-plan-json=/path/to/plan.json] [--deploy-container-zstd=/path/to/blob.zst] [--deploy-expect-accept=0|1] [--deploy-expect-text=STRING] [--deploy-second-plan-json=/path/to/plan.json] [--deploy-second-container-zstd=/path/to/blob.zst] [--deploy-second-start=SECONDS] [--deploy-second-expect-accept=0|1] [--deploy-second-expect-text=STRING] [--deploy-third-plan-json=/path/to/plan.json] [--deploy-third-container-zstd=/path/to/blob.zst] [--deploy-third-start=SECONDS] [--deploy-third-expect-accept=0|1] [--deploy-third-expect-text=STRING] [--deploy-ping-port=PORT] [--deploy-ping-payload=STRING] [--deploy-ping-expect=STRING] [--deploy-ping-all=0|1] [--deploy-ping-after-fault=0|1] [--deploy-skip-probe=0|1] [--deploy-report-application=...] [--deploy-report-version-id=ID] [--deploy-report-version-min=0|1] [--deploy-report-attempts=COUNT] [--deploy-report-min-healthy=COUNT] [--deploy-report-max-healthy-min=COUNT] [--deploy-report-final-healthy-max=COUNT] [--deploy-report-min-target=COUNT] [--deploy-report-max-target-min=COUNT] [--deploy-report-final-target-max=COUNT] [--deploy-report-min-shard-groups=COUNT] [--deploy-report-max-shard-groups-min=COUNT] [--deploy-report-final-shard-groups-max=COUNT] [--deploy-report-runtime-cores-min=COUNT] [--deploy-report-runtime-memory-min-mb=COUNT] [--deploy-report-runtime-storage-min-mb=COUNT] [--deploy-report-runtime-cores-max-min=COUNT] [--deploy-report-runtime-memory-max-min-mb=COUNT] [--deploy-report-runtime-storage-max-min-mb=COUNT] [--deploy-report-traffic-burst=COUNT] [--deploy-mesh-mode=any|exclusiveSome|all|radar] [--deploy-mesh-require-all=0|1] [--require-brain-log-substring=TEXT]"
   echo "note: for a persistent fake cluster managed by Mothership, prefer 'mothership createCluster' with deploymentMode=test; invoke this harness directly only for low-level debugging or harness-focused test flows"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for netns setup"
   exit 77
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRODIGY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"

runner_mode="oneshot"
brains=3
machines=3
duration_s=10
brain_bootstrap_family="${PRODIGY_DEV_BRAIN_BOOTSTRAP_FAMILY:-ipv4}"
workspace_root=""
manifest_path=""
tunnel_ebpf=""
host_ingress_ebpf=""
host_egress_ebpf=""
enable_fake_ipv4_boundary="${PRODIGY_DEV_ENABLE_FAKE_IPV4_BOUNDARY:-0}"
require_fake_ipv4_boundary="${PRODIGY_DEV_REQUIRE_FAKE_IPV4_BOUNDARY:-0}"
fake_ipv4_boundary_ebpf=""
fake_ipv4_boundary_rebuild="${PRODIGY_DEV_FAKE_IPV4_BOUNDARY_REBUILD:-1}"
allow_bpf_attach="${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}"
switchboard_gateway_index=1
mothership_bin=""
mothership_autoscale_interval_seconds=180
mothership_update_prodigy_input=""
mothership_update_start_s=2
master_index=0
fault_mode="link"
fault_targets=""
fault_start_s=2
fault_start_on_ready=0
fault_duration_s=0
fault_cycles=0
fault_down_s=1
fault_up_s=1
post_fault_window_s=8
expect_master_available=-1
expect_master_change=-1
expect_master_change_during_fault=-1
expect_peer_recovery=-1
deploy_plan_json=""
deploy_container_zstd=""
deploy_expect_accept=1
deploy_expect_text=""
deploy_second_plan_json=""
deploy_second_container_zstd=""
deploy_second_start_s=0
deploy_second_expect_accept=1
deploy_second_expect_text=""
deploy_third_plan_json=""
deploy_third_container_zstd=""
deploy_third_start_s=0
deploy_third_expect_accept=1
deploy_third_expect_text=""
deploy_ping_port=0
deploy_ping_payload="ping"
deploy_ping_expect="pong"
deploy_ping_all=0
deploy_ping_after_fault=0
deploy_ping_emit_stats="${PRODIGY_DEV_DEPLOY_PING_EMIT_STATS:-0}"
deploy_skip_final_ping="${PRODIGY_DEV_DEPLOY_SKIP_FINAL_PING:-0}"
deploy_ping_attempts="${PRODIGY_DEV_DEPLOY_PING_ATTEMPTS:-180}"
deploy_attempts="${PRODIGY_DEV_DEPLOY_ATTEMPTS:-12}"
deploy_attempt_timeout_s="${PRODIGY_DEV_DEPLOY_ATTEMPT_TIMEOUT_S:-12}"
deploy_skip_probe=0
deploy_report_application=""
deploy_report_version_id=0
deploy_report_version_min=0
deploy_report_attempts=180
deploy_report_min_healthy=0
deploy_report_max_healthy_min=0
deploy_report_final_healthy_max=-1
deploy_report_min_target=0
deploy_report_max_target_min=0
deploy_report_final_target_max=-1
deploy_report_min_shard_groups=0
deploy_report_max_shard_groups_min=0
deploy_report_final_shard_groups_max=-1
deploy_report_runtime_cores_min=0
deploy_report_runtime_memory_min_mb=0
deploy_report_runtime_storage_min_mb=0
deploy_report_runtime_cores_max_min=0
deploy_report_runtime_memory_max_min_mb=0
deploy_report_runtime_storage_max_min_mb=0
deploy_report_traffic_burst=1
deploy_report_success_hold_ms="${PRODIGY_DEV_DEPLOY_REPORT_SUCCESS_HOLD_MS:-2500}"
deploy_report_floor_min_runtime_ms="${PRODIGY_DEV_DEPLOY_REPORT_FLOOR_MIN_RUNTIME_MS:-12000}"
deploy_report_poll_interval_ms="${PRODIGY_DEV_DEPLOY_REPORT_POLL_INTERVAL_MS:-300}"
deploy_report_max_seconds="${PRODIGY_DEV_DEPLOY_REPORT_MAX_SECONDS:-360}"
deploy_mesh_mode=""
deploy_mesh_require_all=0
deploy_mesh_attempts="${PRODIGY_DEV_DEPLOY_MESH_ATTEMPTS:-180}"
test_cluster_boot_json_bin=""
declare -a require_brain_log_substrings=()
suite_runtime_s=10
prodigy_runtime_root=""
prodigy_runtime_bundle_path=""

while [[ $# -gt 0 ]]
do
   case "$1" in
      --runner-mode=*)
         runner_mode="${1#*=}"
         ;;
      --workspace-root=*)
         workspace_root="${1#*=}"
         ;;
      --manifest-path=*)
         manifest_path="${1#*=}"
         ;;
      --machines=*)
         machines="${1#*=}"
         ;;
      --brains=*)
         brains="${1#*=}"
         ;;
      --duration=*)
         duration_s="${1#*=}"
         ;;
      --brain-bootstrap-family=*)
         brain_bootstrap_family="${1#*=}"
         ;;
      --tunnel-ebpf=*)
         tunnel_ebpf="${1#*=}"
         ;;
      --host-ingress-ebpf=*)
         host_ingress_ebpf="${1#*=}"
         ;;
      --host-egress-ebpf=*)
         host_egress_ebpf="${1#*=}"
         ;;
      --enable-fake-ipv4-boundary=*)
         enable_fake_ipv4_boundary="${1#*=}"
         ;;
      --fake-ipv4-boundary-ebpf=*)
         fake_ipv4_boundary_ebpf="${1#*=}"
         ;;
      --switchboard-gateway-index=*)
         switchboard_gateway_index="${1#*=}"
         ;;
      --mothership-bin=*)
         mothership_bin="${1#*=}"
         ;;
      --mothership-autoscale-interval-seconds=*)
         mothership_autoscale_interval_seconds="${1#*=}"
         ;;
      --mothership-update-prodigy-input=*)
         mothership_update_prodigy_input="${1#*=}"
         ;;
      --mothership-update-start=*)
         mothership_update_start_s="${1#*=}"
         ;;
      --master-index=*)
         master_index="${1#*=}"
         ;;
      --fault-mode=*)
         fault_mode="${1#*=}"
         ;;
      --fault-targets=*)
         fault_targets="${1#*=}"
         ;;
      --fault-start=*)
         fault_start_s="${1#*=}"
         ;;
      --fault-start-on-ready=*)
         fault_start_on_ready="${1#*=}"
         ;;
      --fault-duration=*)
         fault_duration_s="${1#*=}"
         ;;
      --fault-cycles=*)
         fault_cycles="${1#*=}"
         ;;
      --fault-down=*)
         fault_down_s="${1#*=}"
         ;;
      --fault-up=*)
         fault_up_s="${1#*=}"
         ;;
      --post-fault-window=*)
         post_fault_window_s="${1#*=}"
         ;;
      --expect-master-available=*)
         expect_master_available="${1#*=}"
         ;;
      --expect-master-change=*)
         expect_master_change="${1#*=}"
         ;;
      --expect-master-change-during-fault=*)
         expect_master_change_during_fault="${1#*=}"
         ;;
      --expect-peer-recovery=*)
         expect_peer_recovery="${1#*=}"
         ;;
      --deploy-plan-json=*)
         deploy_plan_json="${1#*=}"
         ;;
      --deploy-container-zstd=*)
         deploy_container_zstd="${1#*=}"
         ;;
      --deploy-expect-accept=*)
         deploy_expect_accept="${1#*=}"
         ;;
      --deploy-expect-text=*)
         deploy_expect_text="${1#*=}"
         ;;
      --deploy-second-plan-json=*)
         deploy_second_plan_json="${1#*=}"
         ;;
      --deploy-second-container-zstd=*)
         deploy_second_container_zstd="${1#*=}"
         ;;
      --deploy-second-start=*)
         deploy_second_start_s="${1#*=}"
         ;;
      --deploy-second-expect-accept=*)
         deploy_second_expect_accept="${1#*=}"
         ;;
      --deploy-second-expect-text=*)
         deploy_second_expect_text="${1#*=}"
         ;;
      --deploy-third-plan-json=*)
         deploy_third_plan_json="${1#*=}"
         ;;
      --deploy-third-container-zstd=*)
         deploy_third_container_zstd="${1#*=}"
         ;;
      --deploy-third-start=*)
         deploy_third_start_s="${1#*=}"
         ;;
      --deploy-third-expect-accept=*)
         deploy_third_expect_accept="${1#*=}"
         ;;
      --deploy-third-expect-text=*)
         deploy_third_expect_text="${1#*=}"
         ;;
      --deploy-ping-port=*)
         deploy_ping_port="${1#*=}"
         ;;
      --deploy-ping-payload=*)
         deploy_ping_payload="${1#*=}"
         ;;
      --deploy-ping-expect=*)
         deploy_ping_expect="${1#*=}"
         ;;
      --deploy-ping-all=*)
         deploy_ping_all="${1#*=}"
         ;;
      --deploy-ping-after-fault=*)
         deploy_ping_after_fault="${1#*=}"
         ;;
      --deploy-ping-emit-stats=*)
         deploy_ping_emit_stats="${1#*=}"
         ;;
      --deploy-skip-probe=*)
         deploy_skip_probe="${1#*=}"
         ;;
      --deploy-report-application=*)
         deploy_report_application="${1#*=}"
         ;;
      --deploy-report-version-id=*)
         deploy_report_version_id="${1#*=}"
         ;;
      --deploy-report-version-min=*)
         deploy_report_version_min="${1#*=}"
         ;;
      --deploy-report-attempts=*)
         deploy_report_attempts="${1#*=}"
         ;;
      --deploy-report-min-healthy=*)
         deploy_report_min_healthy="${1#*=}"
         ;;
      --deploy-report-max-healthy-min=*)
         deploy_report_max_healthy_min="${1#*=}"
         ;;
      --deploy-report-final-healthy-max=*)
         deploy_report_final_healthy_max="${1#*=}"
         ;;
      --deploy-report-min-target=*)
         deploy_report_min_target="${1#*=}"
         ;;
      --deploy-report-max-target-min=*)
         deploy_report_max_target_min="${1#*=}"
         ;;
      --deploy-report-final-target-max=*)
         deploy_report_final_target_max="${1#*=}"
         ;;
      --deploy-report-min-shard-groups=*)
         deploy_report_min_shard_groups="${1#*=}"
         ;;
      --deploy-report-max-shard-groups-min=*)
         deploy_report_max_shard_groups_min="${1#*=}"
         ;;
      --deploy-report-final-shard-groups-max=*)
         deploy_report_final_shard_groups_max="${1#*=}"
         ;;
      --deploy-report-runtime-cores-min=*)
         deploy_report_runtime_cores_min="${1#*=}"
         ;;
      --deploy-report-runtime-memory-min-mb=*)
         deploy_report_runtime_memory_min_mb="${1#*=}"
         ;;
      --deploy-report-runtime-storage-min-mb=*)
         deploy_report_runtime_storage_min_mb="${1#*=}"
         ;;
      --deploy-report-runtime-cores-max-min=*)
         deploy_report_runtime_cores_max_min="${1#*=}"
         ;;
      --deploy-report-runtime-memory-max-min-mb=*)
         deploy_report_runtime_memory_max_min_mb="${1#*=}"
         ;;
      --deploy-report-runtime-storage-max-min-mb=*)
         deploy_report_runtime_storage_max_min_mb="${1#*=}"
         ;;
      --deploy-report-traffic-burst=*)
         deploy_report_traffic_burst="${1#*=}"
         ;;
      --deploy-report-success-hold-ms=*)
         deploy_report_success_hold_ms="${1#*=}"
         ;;
      --deploy-report-floor-min-runtime-ms=*)
         deploy_report_floor_min_runtime_ms="${1#*=}"
         ;;
      --deploy-report-poll-interval-ms=*)
         deploy_report_poll_interval_ms="${1#*=}"
         ;;
      --deploy-mesh-mode=*)
         deploy_mesh_mode="${1#*=}"
         ;;
      --deploy-mesh-require-all=*)
         deploy_mesh_require_all="${1#*=}"
         ;;
      --require-brain-log-substring=*)
         require_brain_log_substrings+=("${1#*=}")
         ;;
      *)
         echo "unknown argument: $1"
         exit 2
         ;;
   esac

   shift
done

if [[ "${runner_mode}" != "oneshot" && "${runner_mode}" != "persistent" ]]
then
   echo "FAIL: --runner-mode must be oneshot or persistent"
   exit 1
fi

if ! [[ "${machines}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --machines must be an integer"
   exit 1
fi

if ! [[ "${brains}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --brains must be an integer"
   exit 1
fi

if [[ "${runner_mode}" == "oneshot" && "${machines}" != "${brains}" ]]
then
   echo "FAIL: oneshot mode currently requires --machines to equal --brains"
   exit 1
fi

if [[ "${runner_mode}" == "oneshot" && "${brains}" != "1" && "${brains}" != "3" ]]
then
   echo "FAIL: --brains must be 1 or 3"
   exit 1
fi

if [[ "${brains}" -le 0 || "${machines}" -le 0 || "${brains}" -gt "${machines}" ]]
then
   echo "FAIL: require 1 <= brains <= machines"
   exit 1
fi

if [[ "${brain_bootstrap_family}" != "ipv4" && "${brain_bootstrap_family}" != "private6" && "${brain_bootstrap_family}" != "public6" && "${brain_bootstrap_family}" != "multihome6" ]]
then
   echo "FAIL: --brain-bootstrap-family must be ipv4, private6, public6, or multihome6"
   exit 1
fi

if [[ "${enable_fake_ipv4_boundary}" != "0" && "${enable_fake_ipv4_boundary}" != "1" ]]
then
   echo "FAIL: --enable-fake-ipv4-boundary must be 0 or 1"
   exit 1
fi

if [[ "${require_fake_ipv4_boundary}" != "0" && "${require_fake_ipv4_boundary}" != "1" ]]
then
   echo "FAIL: PRODIGY_DEV_REQUIRE_FAKE_IPV4_BOUNDARY must be 0 or 1"
   exit 1
fi

if [[ "${require_fake_ipv4_boundary}" == "1" && "${enable_fake_ipv4_boundary}" != "1" ]]
then
   echo "FAIL: CI requires fake public boundary mode (set --enable-fake-ipv4-boundary=1)"
   exit 1
fi

if [[ "${fake_ipv4_boundary_rebuild}" != "0" && "${fake_ipv4_boundary_rebuild}" != "1" ]]
then
   echo "FAIL: PRODIGY_DEV_FAKE_IPV4_BOUNDARY_REBUILD must be 0 or 1"
   exit 1
fi

if ! [[ "${switchboard_gateway_index}" =~ ^[0-9]+$ ]] || [[ "${switchboard_gateway_index}" -le 0 ]] || [[ "${switchboard_gateway_index}" -gt "${brains}" ]]
then
   echo "FAIL: --switchboard-gateway-index must be an integer in 1..${brains}"
   exit 1
fi

if [[ "${runner_mode}" == "persistent" && -z "${workspace_root}" ]]
then
   echo "FAIL: persistent mode requires --workspace-root"
   exit 1
fi

if ! [[ "${duration_s}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --duration must be an integer number of seconds"
   exit 1
fi

if ! [[ "${fault_start_s}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --fault-start must be an integer number of seconds"
   exit 1
fi

if [[ "${fault_start_on_ready}" != "0" && "${fault_start_on_ready}" != "1" ]]
then
   echo "FAIL: --fault-start-on-ready must be 0 or 1"
   exit 1
fi

if ! [[ "${fault_duration_s}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --fault-duration must be an integer number of seconds"
   exit 1
fi

if ! [[ "${fault_cycles}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --fault-cycles must be an integer number of cycles"
   exit 1
fi

if ! [[ "${fault_down_s}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --fault-down must be an integer number of seconds"
   exit 1
fi

if ! [[ "${fault_up_s}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --fault-up must be an integer number of seconds"
   exit 1
fi

if ! [[ "${post_fault_window_s}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --post-fault-window must be an integer number of seconds"
   exit 1
fi

if [[ -n "${mothership_bin}" && ! -x "${mothership_bin}" ]]
then
   echo "FAIL: --mothership-bin is not executable: ${mothership_bin}"
   exit 1
fi

if [[ -n "${mothership_update_prodigy_input}" && ! -f "${mothership_update_prodigy_input}" ]]
then
   echo "FAIL: --mothership-update-prodigy-input path does not exist: ${mothership_update_prodigy_input}"
   exit 1
fi

if ! [[ "${mothership_update_start_s}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --mothership-update-start must be an integer number of seconds"
   exit 1
fi

if ! [[ "${mothership_autoscale_interval_seconds}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --mothership-autoscale-interval-seconds must be an integer number of seconds"
   exit 1
fi

if [[ "${mothership_autoscale_interval_seconds}" -le 0 || "${mothership_autoscale_interval_seconds}" -gt 86400 ]]
then
   echo "FAIL: --mothership-autoscale-interval-seconds must be in 1..86400"
   exit 1
fi

if [[ "${master_index}" != "0" && "${master_index}" != "1" && "${master_index}" != "2" && "${master_index}" != "3" ]]
then
   echo "FAIL: --master-index must be 0, 1, 2, or 3"
   exit 1
fi

if [[ "${master_index}" != "0" ]]
then
   echo "WARN: --master-index is deprecated and ignored; cluster self-elects the master"
fi

if [[ -n "${fault_targets}" && "${brains}" != "3" ]]
then
   echo "FAIL: --fault-targets currently requires --brains=3"
   exit 1
fi

if [[ "${fault_mode}" != "link" && "${fault_mode}" != "crash" && "${fault_mode}" != "flap" ]]
then
   echo "FAIL: --fault-mode must be link, crash, or flap"
   exit 1
fi

if [[ -n "${mothership_update_prodigy_input}" && -z "${mothership_bin}" ]]
then
   echo "FAIL: --mothership-update-prodigy-input requires --mothership-bin"
   exit 1
fi

PRODIGY_BIN="$(readlink -f "${PRODIGY_BIN}" 2>/dev/null || printf '%s' "${PRODIGY_BIN}")"
prodigy_bin_dir="$(dirname "${PRODIGY_BIN}")"
test_cluster_boot_json_bin="${prodigy_bin_dir}/prodigy_test_cluster_boot_json"

if [[ ! -x "${test_cluster_boot_json_bin}" ]]
then
   if [[ -f "${prodigy_bin_dir}/build.ninja" || -f "${prodigy_bin_dir}/CMakeCache.txt" ]]
   then
      cmake --build "${prodigy_bin_dir}" -j"$(nproc)" --target prodigy_test_cluster_boot_json >/dev/null
   fi
fi

if [[ ! -x "${test_cluster_boot_json_bin}" ]]
then
   echo "SKIP: missing Prodigy test boot json helper: ${test_cluster_boot_json_bin}"
   exit 77
fi

if [[ -n "${mothership_bin}" ]]
then
   mothership_bin="$(readlink -f "${mothership_bin}" 2>/dev/null || printf '%s' "${mothership_bin}")"
fi

if [[ -n "${mothership_update_prodigy_input}" ]]
then
   mothership_update_prodigy_input="$(readlink -f "${mothership_update_prodigy_input}" 2>/dev/null || printf '%s' "${mothership_update_prodigy_input}")"
fi

if [[ -n "${fake_ipv4_boundary_ebpf}" ]]
then
   fake_ipv4_boundary_ebpf="$(readlink -f "${fake_ipv4_boundary_ebpf}" 2>/dev/null || printf '%s' "${fake_ipv4_boundary_ebpf}")"
fi

if [[ -n "${deploy_plan_json}" ]]
then
   deploy_plan_json="$(readlink -f "${deploy_plan_json}" 2>/dev/null || printf '%s' "${deploy_plan_json}")"
fi

if [[ -n "${deploy_container_zstd}" ]]
then
   deploy_container_zstd="$(readlink -f "${deploy_container_zstd}" 2>/dev/null || printf '%s' "${deploy_container_zstd}")"
fi

if [[ -n "${deploy_second_plan_json}" ]]
then
   deploy_second_plan_json="$(readlink -f "${deploy_second_plan_json}" 2>/dev/null || printf '%s' "${deploy_second_plan_json}")"
fi

if [[ -n "${deploy_second_container_zstd}" ]]
then
   deploy_second_container_zstd="$(readlink -f "${deploy_second_container_zstd}" 2>/dev/null || printf '%s' "${deploy_second_container_zstd}")"
fi

if [[ -n "${deploy_third_plan_json}" ]]
then
   deploy_third_plan_json="$(readlink -f "${deploy_third_plan_json}" 2>/dev/null || printf '%s' "${deploy_third_plan_json}")"
fi

if [[ -n "${deploy_third_container_zstd}" ]]
then
   deploy_third_container_zstd="$(readlink -f "${deploy_third_container_zstd}" 2>/dev/null || printf '%s' "${deploy_third_container_zstd}")"
fi

if [[ -n "${fault_targets}" && "${fault_mode}" == "flap" && "${fault_cycles}" -le 0 ]]
then
   echo "FAIL: --fault-cycles must be > 0 when --fault-mode=flap"
   exit 1
fi

if [[ -n "${fault_targets}" && "${fault_mode}" == "flap" && "${fault_down_s}" -le 0 ]]
then
   echo "FAIL: --fault-down must be > 0 when --fault-mode=flap"
   exit 1
fi

if [[ -n "${fault_targets}" && "${fault_mode}" == "flap" && "${fault_up_s}" -le 0 ]]
then
   echo "FAIL: --fault-up must be > 0 when --fault-mode=flap"
   exit 1
fi

if [[ "${expect_master_available}" != "-1" && "${expect_master_available}" != "0" && "${expect_master_available}" != "1" ]]
then
   echo "FAIL: --expect-master-available must be 0 or 1"
   exit 1
fi

if [[ "${expect_master_change}" != "-1" && "${expect_master_change}" != "0" && "${expect_master_change}" != "1" ]]
then
   echo "FAIL: --expect-master-change must be 0 or 1"
   exit 1
fi

if [[ "${expect_master_change_during_fault}" != "-1" && "${expect_master_change_during_fault}" != "0" && "${expect_master_change_during_fault}" != "1" ]]
then
   echo "FAIL: --expect-master-change-during-fault must be 0 or 1"
   exit 1
fi

if [[ "${expect_peer_recovery}" != "-1" && "${expect_peer_recovery}" != "0" && "${expect_peer_recovery}" != "1" ]]
then
   echo "FAIL: --expect-peer-recovery must be 0 or 1"
   exit 1
fi

if [[ -n "${deploy_plan_json}" && ! -f "${deploy_plan_json}" ]]
then
   echo "FAIL: --deploy-plan-json path does not exist: ${deploy_plan_json}"
   exit 1
fi

if [[ -n "${deploy_container_zstd}" && ! -f "${deploy_container_zstd}" ]]
then
   echo "FAIL: --deploy-container-zstd path does not exist: ${deploy_container_zstd}"
   exit 1
fi

if [[ -n "${deploy_second_plan_json}" && ! -f "${deploy_second_plan_json}" ]]
then
   echo "FAIL: --deploy-second-plan-json path does not exist: ${deploy_second_plan_json}"
   exit 1
fi

if [[ -n "${deploy_second_container_zstd}" && ! -f "${deploy_second_container_zstd}" ]]
then
   echo "FAIL: --deploy-second-container-zstd path does not exist: ${deploy_second_container_zstd}"
   exit 1
fi

if [[ -n "${deploy_third_plan_json}" && ! -f "${deploy_third_plan_json}" ]]
then
   echo "FAIL: --deploy-third-plan-json path does not exist: ${deploy_third_plan_json}"
   exit 1
fi

if [[ -n "${deploy_third_container_zstd}" && ! -f "${deploy_third_container_zstd}" ]]
then
   echo "FAIL: --deploy-third-container-zstd path does not exist: ${deploy_third_container_zstd}"
   exit 1
fi

if ! [[ "${deploy_second_start_s}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --deploy-second-start must be an integer number of seconds"
   exit 1
fi

if ! [[ "${deploy_third_start_s}" =~ ^[0-9]+$ ]]
then
   echo "FAIL: --deploy-third-start must be an integer number of seconds"
   exit 1
fi

if [[ "${deploy_second_expect_accept}" != "0" && "${deploy_second_expect_accept}" != "1" ]]
then
   echo "FAIL: --deploy-second-expect-accept must be 0 or 1"
   exit 1
fi

if [[ "${deploy_third_expect_accept}" != "0" && "${deploy_third_expect_accept}" != "1" ]]
then
   echo "FAIL: --deploy-third-expect-accept must be 0 or 1"
   exit 1
fi

if [[ "${deploy_expect_accept}" != "0" && "${deploy_expect_accept}" != "1" ]]
then
   echo "FAIL: --deploy-expect-accept must be 0 or 1"
   exit 1
fi

if [[ -n "${deploy_plan_json}" || -n "${deploy_container_zstd}" || "${deploy_expect_accept}" != "1" || -n "${deploy_expect_text}" || -n "${deploy_second_plan_json}" || -n "${deploy_second_container_zstd}" || -n "${deploy_third_plan_json}" || -n "${deploy_third_container_zstd}" || "${deploy_ping_port}" != "0" ]]
then
   if [[ -z "${mothership_bin}" ]]
   then
      echo "FAIL: deploy options require --mothership-bin"
      exit 1
   fi

   if [[ -z "${deploy_plan_json}" || -z "${deploy_container_zstd}" ]]
   then
      echo "FAIL: deploy requires both --deploy-plan-json and --deploy-container-zstd"
      exit 1
   fi

   if [[ -n "${deploy_second_plan_json}" || -n "${deploy_second_container_zstd}" || "${deploy_second_start_s}" != "0" || -n "${deploy_second_expect_text}" || "${deploy_second_expect_accept}" != "1" ]]
   then
      if [[ -z "${deploy_second_plan_json}" || -z "${deploy_second_container_zstd}" ]]
      then
         echo "FAIL: second deploy requires both --deploy-second-plan-json and --deploy-second-container-zstd"
         exit 1
      fi
   fi

   if [[ -n "${deploy_third_plan_json}" || -n "${deploy_third_container_zstd}" || "${deploy_third_start_s}" != "0" || -n "${deploy_third_expect_text}" || "${deploy_third_expect_accept}" != "1" ]]
   then
      if [[ -z "${deploy_third_plan_json}" || -z "${deploy_third_container_zstd}" ]]
      then
         echo "FAIL: third deploy requires both --deploy-third-plan-json and --deploy-third-container-zstd"
         exit 1
      fi
   fi

   if [[ "${deploy_skip_probe}" != "0" && "${deploy_skip_probe}" != "1" ]]
   then
      echo "FAIL: --deploy-skip-probe must be 0 or 1"
      exit 1
   fi

if [[ "${deploy_skip_probe}" == "0" ]] && ( ! [[ "${deploy_ping_port}" =~ ^[0-9]+$ ]] || [[ "${deploy_ping_port}" -le 0 ]] || [[ "${deploy_ping_port}" -gt 65535 ]] )
then
   echo "FAIL: --deploy-ping-port must be an integer in 1..65535"
   exit 1
fi

   if ! [[ "${deploy_ping_attempts}" =~ ^[0-9]+$ ]] || [[ "${deploy_ping_attempts}" -le 0 ]]
   then
      echo "FAIL: PRODIGY_DEV_DEPLOY_PING_ATTEMPTS must be a positive integer"
      exit 1
   fi

   if ! [[ "${deploy_attempts}" =~ ^[0-9]+$ ]] || [[ "${deploy_attempts}" -le 0 ]]
   then
      echo "FAIL: PRODIGY_DEV_DEPLOY_ATTEMPTS must be a positive integer"
      exit 1
   fi

   if ! [[ "${deploy_attempt_timeout_s}" =~ ^[0-9]+$ ]] || [[ "${deploy_attempt_timeout_s}" -le 0 ]]
   then
      echo "FAIL: PRODIGY_DEV_DEPLOY_ATTEMPT_TIMEOUT_S must be a positive integer"
      exit 1
   fi

   if [[ "${deploy_ping_all}" != "0" && "${deploy_ping_all}" != "1" ]]
   then
      echo "FAIL: --deploy-ping-all must be 0 or 1"
      exit 1
   fi

   if [[ "${deploy_ping_after_fault}" != "0" && "${deploy_ping_after_fault}" != "1" ]]
   then
      echo "FAIL: --deploy-ping-after-fault must be 0 or 1"
      exit 1
   fi

if [[ "${deploy_ping_emit_stats}" != "0" && "${deploy_ping_emit_stats}" != "1" ]]
then
   echo "FAIL: --deploy-ping-emit-stats must be 0 or 1"
   exit 1
fi

if [[ "${deploy_skip_final_ping}" != "0" && "${deploy_skip_final_ping}" != "1" ]]
then
   echo "FAIL: PRODIGY_DEV_DEPLOY_SKIP_FINAL_PING must be 0 or 1"
   exit 1
fi

   if [[ "${deploy_skip_probe}" == "1" && "${deploy_ping_after_fault}" == "1" ]]
   then
      echo "FAIL: --deploy-ping-after-fault requires --deploy-skip-probe=0"
      exit 1
   fi

   if ! [[ "${deploy_report_min_healthy}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-min-healthy must be an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_version_id}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-version-id must be an integer >= 0"
      exit 1
   fi

   if [[ "${deploy_report_version_min}" != "0" && "${deploy_report_version_min}" != "1" ]]
   then
      echo "FAIL: --deploy-report-version-min must be 0 or 1"
      exit 1
   fi

   if ! [[ "${deploy_report_attempts}" =~ ^[0-9]+$ ]] || [[ "${deploy_report_attempts}" -le 0 ]]
   then
      echo "FAIL: --deploy-report-attempts must be a positive integer"
      exit 1
   fi

   if ! [[ "${deploy_report_max_healthy_min}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-max-healthy-min must be an integer >= 0"
      exit 1
   fi

   if [[ "${deploy_report_final_healthy_max}" != "-1" ]] && ! [[ "${deploy_report_final_healthy_max}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-final-healthy-max must be -1 or an integer >= 0"
      exit 1
   fi

   if [[ "${deploy_report_max_healthy_min}" -gt 0 && -z "${deploy_report_application}" ]]
   then
      echo "FAIL: --deploy-report-max-healthy-min > 0 requires --deploy-report-application"
      exit 1
   fi

   if [[ "${deploy_report_final_healthy_max}" != "-1" && -z "${deploy_report_application}" ]]
   then
      echo "FAIL: --deploy-report-final-healthy-max requires --deploy-report-application"
      exit 1
   fi

   if [[ "${deploy_report_min_healthy}" -gt 0 && -z "${deploy_report_application}" ]]
   then
      echo "FAIL: --deploy-report-min-healthy > 0 requires --deploy-report-application"
      exit 1
   fi

   if ! [[ "${deploy_report_min_target}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-min-target must be an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_max_target_min}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-max-target-min must be an integer >= 0"
      exit 1
   fi

   if [[ "${deploy_report_final_target_max}" != "-1" ]] && ! [[ "${deploy_report_final_target_max}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-final-target-max must be -1 or an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_min_shard_groups}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-min-shard-groups must be an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_max_shard_groups_min}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-max-shard-groups-min must be an integer >= 0"
      exit 1
   fi

   if [[ "${deploy_report_final_shard_groups_max}" != "-1" ]] && ! [[ "${deploy_report_final_shard_groups_max}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-final-shard-groups-max must be -1 or an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_runtime_cores_min}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-runtime-cores-min must be an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_runtime_memory_min_mb}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-runtime-memory-min-mb must be an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_runtime_storage_min_mb}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-runtime-storage-min-mb must be an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_runtime_cores_max_min}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-runtime-cores-max-min must be an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_runtime_memory_max_min_mb}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-runtime-memory-max-min-mb must be an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_runtime_storage_max_min_mb}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-runtime-storage-max-min-mb must be an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_traffic_burst}" =~ ^[0-9]+$ ]] || [[ "${deploy_report_traffic_burst}" -le 0 ]]
   then
      echo "FAIL: --deploy-report-traffic-burst must be a positive integer"
      exit 1
   fi

   if ! [[ "${deploy_report_success_hold_ms}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-success-hold-ms must be an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_floor_min_runtime_ms}" =~ ^[0-9]+$ ]]
   then
      echo "FAIL: --deploy-report-floor-min-runtime-ms must be an integer >= 0"
      exit 1
   fi

   if ! [[ "${deploy_report_poll_interval_ms}" =~ ^[0-9]+$ ]] || [[ "${deploy_report_poll_interval_ms}" -le 0 ]]
   then
      echo "FAIL: --deploy-report-poll-interval-ms must be an integer > 0"
      exit 1
   fi

   if ! [[ "${deploy_report_max_seconds}" =~ ^[0-9]+$ ]] || [[ "${deploy_report_max_seconds}" -le 0 ]]
   then
      echo "FAIL: PRODIGY_DEV_DEPLOY_REPORT_MAX_SECONDS must be a positive integer"
      exit 1
   fi

   if [[ "${deploy_report_min_target}" -gt 0 && -z "${deploy_report_application}" ]]
   then
      echo "FAIL: --deploy-report-min-target > 0 requires --deploy-report-application"
      exit 1
   fi

   if [[ "${deploy_report_max_target_min}" -gt 0 && -z "${deploy_report_application}" ]]
   then
      echo "FAIL: --deploy-report-max-target-min > 0 requires --deploy-report-application"
      exit 1
   fi

   if [[ "${deploy_report_final_target_max}" != "-1" && -z "${deploy_report_application}" ]]
   then
      echo "FAIL: --deploy-report-final-target-max requires --deploy-report-application"
      exit 1
   fi

   if [[ "${deploy_report_min_shard_groups}" -gt 0 && -z "${deploy_report_application}" ]]
   then
      echo "FAIL: --deploy-report-min-shard-groups > 0 requires --deploy-report-application"
      exit 1
   fi

   if [[ "${deploy_report_max_shard_groups_min}" -gt 0 && -z "${deploy_report_application}" ]]
   then
      echo "FAIL: --deploy-report-max-shard-groups-min > 0 requires --deploy-report-application"
      exit 1
   fi

   if [[ "${deploy_report_final_shard_groups_max}" != "-1" && -z "${deploy_report_application}" ]]
   then
      echo "FAIL: --deploy-report-final-shard-groups-max requires --deploy-report-application"
      exit 1
   fi

   if [[ "${deploy_report_version_id}" -gt 0 && -z "${deploy_report_application}" ]]
   then
      echo "FAIL: --deploy-report-version-id requires --deploy-report-application"
      exit 1
   fi

   if [[ "${deploy_report_runtime_cores_min}" -gt 0 || "${deploy_report_runtime_memory_min_mb}" -gt 0 || "${deploy_report_runtime_storage_min_mb}" -gt 0 || "${deploy_report_runtime_cores_max_min}" -gt 0 || "${deploy_report_runtime_memory_max_min_mb}" -gt 0 || "${deploy_report_runtime_storage_max_min_mb}" -gt 0 ]]
   then
      if [[ -z "${deploy_report_application}" ]]
      then
         echo "FAIL: runtime deploy-report constraints require --deploy-report-application"
         exit 1
      fi
   fi

   if [[ -n "${deploy_mesh_mode}" && "${deploy_mesh_mode}" != "any" && "${deploy_mesh_mode}" != "exclusiveSome" && "${deploy_mesh_mode}" != "all" && "${deploy_mesh_mode}" != "radar" ]]
   then
      echo "FAIL: --deploy-mesh-mode must be any, exclusiveSome, all, or radar"
      exit 1
   fi

   if [[ "${deploy_mesh_require_all}" != "0" && "${deploy_mesh_require_all}" != "1" ]]
   then
      echo "FAIL: --deploy-mesh-require-all must be 0 or 1"
      exit 1
   fi

   if ! [[ "${deploy_mesh_attempts}" =~ ^[0-9]+$ ]] || [[ "${deploy_mesh_attempts}" -le 0 ]]
   then
      echo "FAIL: PRODIGY_DEV_DEPLOY_MESH_ATTEMPTS must be a positive integer"
      exit 1
   fi
fi

# Keep child brain runtimes safely beyond assertion windows; teardown stops them explicitly.
suite_runtime_s=$((duration_s + 180))
if [[ -n "${deploy_report_application}" ]]
then
   report_runtime_s=$((deploy_report_max_seconds + 180))
   if [[ "${report_runtime_s}" -gt "${suite_runtime_s}" ]]
   then
      suite_runtime_s="${report_runtime_s}"
   fi
fi
deploy_report_poll_sleep_s="$(printf '%d.%03d' $((deploy_report_poll_interval_ms / 1000)) $((deploy_report_poll_interval_ms % 1000)))"

deps=(ip stat timeout mktemp sed unshare ss rg setsid stdbuf mount tc sysctl)

for cmd in "${deps[@]}"
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}"
      exit 77
   fi
done

resolve_ebpf_object_path()
{
   local requested_path="$1"
   local sibling_name="$2"
   local cli_flag="$3"
   local object_label="$4"
   local candidate=""

   if [[ -n "${requested_path}" ]]
   then
      candidate="${requested_path}"
   else
      local prodigy_dir
      prodigy_dir="$(dirname "${PRODIGY_BIN}")"
      candidate="${prodigy_dir}/${sibling_name}"
   fi

   if [[ -f "${candidate}" ]]
   then
      readlink -f "${candidate}" 2>/dev/null || printf '%s' "${candidate}"
      return 0
   fi

   echo "FAIL: unable to resolve ${object_label} eBPF object (${candidate}); pass ${cli_flag}=<path>" >&2
   return 1
}

ipv4_to_u32_literal()
{
   local ip="$1"
   local octet1=0
   local octet2=0
   local octet3=0
   local octet4=0

   if ! IFS='.' read -r octet1 octet2 octet3 octet4 <<< "${ip}"
   then
      return 1
   fi

   for octet in "${octet1}" "${octet2}" "${octet3}" "${octet4}"
   do
      if ! [[ "${octet}" =~ ^[0-9]+$ ]] || [[ "${octet}" -lt 0 ]] || [[ "${octet}" -gt 255 ]]
      then
         return 1
      fi
   done

   printf '0x%02X%02X%02X%02Xu' "${octet1}" "${octet2}" "${octet3}" "${octet4}"
}

build_fake_ipv4_boundary_ebpf_object()
{
   local source_path="${PRODIGY_ROOT}/prodigy/dev/fake_ipv4_boundary_nat.ebpf.c"
   local output_path="${tmpdir}/fake_ipv4_boundary_nat.dynamic.ebpf.o"
   local translated_ipv4_define=""

   if [[ ! -f "${source_path}" ]]
   then
      echo "FAIL: fake ipv4 boundary eBPF source missing: ${source_path}" >&2
      return 1
   fi

   if ! command -v clang >/dev/null 2>&1
   then
      echo "FAIL: clang is required to build fake ipv4 boundary eBPF object" >&2
      return 1
   fi

   if ! translated_ipv4_define="$(ipv4_to_u32_literal "${parent_edge_ip}")"
   then
      echo "FAIL: unable to encode parent edge IPv4: ${parent_edge_ip}" >&2
      return 1
   fi

   if ! clang \
      -g \
      -O2 \
      -target bpf \
      -I"${PRODIGY_ROOT}" \
      -I"${PRODIGY_ROOT}/libraries/include" \
      -DDEV_BOUNDARY_TRANSLATED_IPV4="${translated_ipv4_define}" \
      -c "${source_path}" \
      -o "${output_path}"
   then
      echo "FAIL: unable to compile fake ipv4 boundary eBPF object for parent edge IPv4 ${parent_edge_ip}" >&2
      return 1
   fi

   fake_ipv4_boundary_ebpf="${output_path}"
   return 0
}

build_dev_host_ingress_ebpf_object()
{
   local source_path="${PRODIGY_ROOT}/switchboard/kernel/host.ingress.router.ebpf.c"
   local output_path="${tmpdir}/host.ingress.router.dynamic.ebpf.o"

   if [[ ! -f "${source_path}" ]]
   then
      echo "FAIL: host ingress eBPF source missing: ${source_path}" >&2
      return 1
   fi

   if ! command -v clang >/dev/null 2>&1
   then
      echo "FAIL: clang is required to build dev host ingress eBPF object" >&2
      return 1
   fi

   if ! clang \
      -g \
      -O2 \
      -target bpf \
      -I"${PRODIGY_ROOT}" \
      -I"${PRODIGY_ROOT}/libraries/include" \
      -DPRODIGY_DEBUG=1 \
      -DNAMETAG_SWITCHBOARD_DEV_FAKE_IPV4_ROUTE=1 \
      -c "${source_path}" \
      -o "${output_path}"
   then
      echo "FAIL: unable to compile dev host ingress eBPF object" >&2
      return 1
   fi

   host_ingress_ebpf="${output_path}"
   return 0
}

if [[ "${allow_bpf_attach}" != "1" ]]
then
   if [[ -n "${tunnel_ebpf}" || -n "${host_ingress_ebpf}" || -n "${host_egress_ebpf}" || -n "${fake_ipv4_boundary_ebpf}" ]]
   then
      echo "FAIL: eBPF object flags require PRODIGY_DEV_ALLOW_BPF_ATTACH=1"
      exit 1
   fi

   if [[ "${enable_fake_ipv4_boundary}" == "1" ]]
   then
      echo "FAIL: --enable-fake-ipv4-boundary requires PRODIGY_DEV_ALLOW_BPF_ATTACH=1"
      exit 1
   fi
else
   if ! tunnel_ebpf="$(resolve_ebpf_object_path "${tunnel_ebpf}" "tunnel_to_nic.ebpf.o" "--tunnel-ebpf" "tunnel_to_nic")"
   then
      exit 1
   fi

   if ! host_ingress_ebpf="$(resolve_ebpf_object_path "${host_ingress_ebpf}" "host.ingress.router.ebpf.o" "--host-ingress-ebpf" "host.ingress.router")"
   then
      exit 1
   fi

   if ! host_egress_ebpf="$(resolve_ebpf_object_path "${host_egress_ebpf}" "host.egress.router.ebpf.o" "--host-egress-ebpf" "host.egress.router")"
   then
      exit 1
   fi

   if [[ "${enable_fake_ipv4_boundary}" == "1" && "${fake_ipv4_boundary_rebuild}" != "1" ]]
   then
      if ! fake_ipv4_boundary_ebpf="$(resolve_ebpf_object_path "${fake_ipv4_boundary_ebpf}" "fake_ipv4_boundary_nat.ebpf.o" "--fake-ipv4-boundary-ebpf" "fake_ipv4_boundary_nat")"
      then
         exit 1
      fi
   fi
fi

iptables_cmd=""
ip6tables_cmd=""
if [[ "${enable_fake_ipv4_boundary}" == "1" ]]
then
   if ! command -v bpftool >/dev/null 2>&1
   then
      echo "FAIL: --enable-fake-ipv4-boundary requires bpftool"
      exit 1
   fi

   if command -v iptables >/dev/null 2>&1
   then
      iptables_cmd="iptables"
   elif command -v iptables-nft >/dev/null 2>&1
   then
      iptables_cmd="iptables-nft"
   fi

   if [[ -z "${iptables_cmd}" ]]
   then
      echo "FAIL: --enable-fake-ipv4-boundary requires iptables or iptables-nft"
      exit 1
   fi

   if command -v ip6tables >/dev/null 2>&1
   then
      ip6tables_cmd="ip6tables"
   elif command -v ip6tables-nft >/dev/null 2>&1
   then
      ip6tables_cmd="ip6tables-nft"
   fi

   if [[ -z "${ip6tables_cmd}" ]]
   then
      echo "FAIL: --enable-fake-ipv4-boundary requires ip6tables or ip6tables-nft"
      exit 1
   fi
fi

host_netns_ino="$(stat -Lc '%i' /proc/self/ns/net)"
if [[ "${runner_mode}" == "persistent" ]]
then
   tmpdir="${workspace_root}"
   mkdir -p "${tmpdir}"
else
   tmpdir="$(mktemp -d)"
fi
keep_tmp="${PRODIGY_DEV_KEEP_TMP:-0}"
keep_fs="${PRODIGY_DEV_KEEP_FS:-0}"
mothership_socket_path=""
public_mothership_socket_path=""
if [[ -z "${manifest_path}" ]]
then
   manifest_path="${tmpdir}/test-cluster-manifest.json"
fi
node_count="${machines}"

prodigy_runtime_root="$(dirname "${PRODIGY_BIN}")"
if [[ ! -x "${prodigy_runtime_root}/prodigy" ]]
then
   echo "FAIL: runtime root missing prodigy binary: ${prodigy_runtime_root}/prodigy" >&2
   exit 1
fi

resolve_prodigy_bundle_artifact_path_for_input()
{
   local input_path="$1"
   local bundle_home=""
   local bundle_name=""
   local input_dir=""
   local magic=""
   magic="$(od -An -tx1 -N4 "${input_path}" 2>/dev/null | tr -d ' \n' || true)"
   if [[ "${magic}" == "28b52ffd" ]]
   then
      printf '%s\n' "${input_path}"
      return 0
   fi

   case "$(uname -m)" in
      x86_64|amd64)
         bundle_name="prodigy.x86_64.bundle.tar.zst"
         ;;
      aarch64|arm64)
         bundle_name="prodigy.aarch64.bundle.tar.zst"
         ;;
      riscv64)
         bundle_name="prodigy.riscv64.bundle.tar.zst"
         ;;
      *)
         return 1
         ;;
   esac

   input_dir="$(dirname "${input_path}")"
   if [[ -r "${input_dir}/${bundle_name}" ]]
   then
      printf '%s\n' "${input_dir}/${bundle_name}"
      return 0
   fi

   if [[ -n "${XDG_DATA_HOME:-}" ]]
   then
      bundle_home="${XDG_DATA_HOME}/prodigy"
   elif [[ -n "${HOME:-}" ]]
   then
      bundle_home="${HOME}/.local/share/prodigy"
   else
      return 1
   fi

   printf '%s/%s\n' "${bundle_home}" "${bundle_name}"
}

prodigy_runtime_bundle_path="$(resolve_prodigy_bundle_artifact_path_for_input "${PRODIGY_BIN}" || true)"
if [[ -z "${prodigy_runtime_bundle_path}" || ! -r "${prodigy_runtime_bundle_path}" ]]
then
   echo "FAIL: runtime bundle artifact is not readable for ${PRODIGY_BIN}: ${prodigy_runtime_bundle_path}" >&2
   exit 1
fi

stage_prodigy_install_root_from_bundle()
{
   local bundle_path="$1"
   local install_root="$2"
   local install_root_temp="${install_root}.new"
   local install_root_previous="${install_root}.prev"
   local bundle_sha256_path="${bundle_path}.sha256"
   local installed_bundle_path="${install_root_temp}/prodigy.bundle.tar.zst"
   local installed_bundle_sha256_path="${installed_bundle_path}.sha256"

   rm -rf "${install_root_temp}" "${install_root_previous}"
   mkdir -p "${install_root_temp}"
   tar --zstd -xf "${bundle_path}" -C "${install_root_temp}"
   install -m 0644 "${bundle_path}" "${installed_bundle_path}"
   if [[ -r "${bundle_sha256_path}" ]]
   then
      install -m 0644 "${bundle_sha256_path}" "${installed_bundle_sha256_path}"
   fi

   if [[ -e "${install_root}" ]]
   then
      mv "${install_root}" "${install_root_previous}"
   fi

   mv "${install_root_temp}" "${install_root}"
   rm -rf "${install_root_previous}"
}

if [[ "${allow_bpf_attach}" == "1" && "${enable_fake_ipv4_boundary}" == "1" ]]
then
   if ! build_dev_host_ingress_ebpf_object
   then
      exit 1
   fi
fi

assigned_brain_ips=()
assigned_brain_ips6=()
assigned_brain_public_ips6=()
for idx in $(seq 1 "${node_count}")
do
   host_octet=$((9 + idx))
   assigned_brain_ips+=("10.0.0.${host_octet}")
   assigned_brain_ips6+=("fd00:10::$(printf '%x' "${host_octet}")")
   if [[ "${enable_fake_ipv4_boundary}" == "1" ]]
   then
      assigned_brain_public_ips6+=("2602:fac0:0:12ab:34cd::$(printf '%x' "${host_octet}")")
   else
      assigned_brain_public_ips6+=("2001:db8:100::$(printf '%x' "${host_octet}")")
   fi
done

render_bootstrap_json()
{
   local local_index="$1"
   local role="$2"
   local -a command=("${test_cluster_boot_json_bin}"
      "--role=${role}"
      "--control-socket-path=${mothership_socket_path}"
      "--local-index=${local_index}"
      "--brains=${brains}")
   local idx=0

   for idx in "${!assigned_brain_ips[@]}"
   do
      local rack_uuid=$((idx + 1))
      command+=("--machine=${assigned_brain_ips[$idx]},${assigned_brain_ips6[$idx]},${assigned_brain_public_ips6[$idx]},${rack_uuid}")
   done

   "${command[@]}"
}
export PRODIGY_BOOTSTRAP_BRAIN_COUNT="${brains}"

write_persistent_manifest()
{
   local leader_idx="$1"
   local leader_ns=""
   local idx=0
   if [[ "${leader_idx}" -gt 0 ]]
   then
      leader_ns="${child_names[$((leader_idx - 1))]}"
   fi

   {
      printf '{"workspaceRoot":"%s","manifestPath":"%s","controlSocketPath":"%s","parentNamespace":"%s","machineCount":%s,"brainCount":%s,"leaderIndex":%s,"leaderNamespace":"%s","nodes":[' \
         "${tmpdir}" \
         "${manifest_path}" \
         "${public_mothership_socket_path}" \
         "${parent_ns}" \
         "${machines}" \
         "${brains}" \
         "${leader_idx}" \
         "${leader_ns}"

      for idx in $(seq 1 "${node_count}")
      do
         if [[ "${idx}" -gt 1 ]]
         then
            printf ','
         fi

         local role="neuron"
         if [[ "${idx}" -le "${brains}" ]]
         then
            role="brain"
         fi

         local pid="${active_pids[$((idx - 1))]:-0}"
         local stdout_log="${pid_log_by_pid[${pid}]:-${brain_log_root}/brain${idx}.stdout.log}"

         printf '{"index":%s,"role":"%s","namespace":"%s","pid":%s,"stdoutLog":"%s","ipv4":"%s","private6":"%s","public6":"%s"}' \
            "${idx}" \
            "${role}" \
            "${child_names[$((idx - 1))]}" \
            "${pid}" \
            "${stdout_log}" \
            "${assigned_brain_ips[$((idx - 1))]}" \
            "${assigned_brain_ips6[$((idx - 1))]}" \
            "${assigned_brain_public_ips6[$((idx - 1))]}"
      done

      printf ']}\n'
   } > "${manifest_path}"
}

parent_ns="prodigy-dev-parent-${$}-${RANDOM}"
child_names=()
parent_ifs=()
pids=()
status_codes=()
brain_start_count=()
active_pids=()
declare -A expected_nonzero_pid=()
declare -A pid_log_by_pid=()
deploy_container_runtime_path=""
deploy_second_container_runtime_path=""
deploy_third_container_runtime_path=""
deploy_initial_spin_hosts=""
deploy_initial_spin_counts=()
cleanup_ran=0
brain_fs_parent=""
brain_fs_roots=()
brain_fs_shared_store=""
brain_fs_shared_store_backing=""
brain_fs_control_root=""
brain_log_root=""
runtime_tunnel_ebpf=""
runtime_host_ingress_ebpf=""
runtime_host_egress_ebpf=""
runtime_switchboard_balancer_ebpf=""
fake_ipv4_subnet_cidr="198.18.0.0/16"
fake_public6_subnet_cidr="2602:fac0:0:12ab:34cd::/88"
switchboard_gateway_ip=""
switchboard_gateway_ip6=""
switchboard_balancer_ebpf="${PRODIGY_DEV_SWITCHBOARD_BALANCER_EBPF:-}"
switchboard_balancer_machine_fragment_override=""
parent_edge_if=""
host_edge_if=""
host_uplink_if=""
host_uplink_gateway=""
host_uplink_if6=""
host_uplink_gateway6=""
fake_ipv4_boundary_pin_dir=""
fake_ipv4_boundary_pin_root=""
fake_ipv4_boundary_pin_mounted=0
host_policy_table=$((20000 + ($$ % 10000)))
edge_subnet_octet=$((20 + ($$ % 200)))
host_edge_ip="172.31.${edge_subnet_octet}.1"
parent_edge_ip="172.31.${edge_subnet_octet}.2"
host_edge_ip6="fd00:31:${edge_subnet_octet}::1"
parent_edge_ip6="fd00:31:${edge_subnet_octet}::2"
host_edge_rule_nat_added=0
host_edge_rule_fwd_out_added=0
host_edge_rule_fwd_in_added=0
host_edge_rule_nat6_added=0
host_edge_rule_nat6_parent_added=0
host_edge_rule_fwd6_out_added=0
host_edge_rule_fwd6_in_added=0
host_edge_policy_rule_added=0
host_edge_policy_route_added=0
host_edge_policy_rule6_added=0
host_edge_policy_rule6_parent_added=0
host_edge_policy_route6_added=0
host_ip_forward_prev=""
host_ip6_forward_prev=""
parent_edge_rule_nat6_added=0

is_test_container_process()
{
   local pid="$1"
   local exe_path=""
   local exe_base=""
   local comm_name=""
   local cmdline=""

   exe_path="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
   if [[ -n "${exe_path}" ]]
   then
      exe_base="$(basename "${exe_path}")"
      case "${exe_base}" in
         pingpong_container)
            return 0
            ;;
      esac
   fi

   comm_name="$(cat "/proc/${pid}/comm" 2>/dev/null || true)"
   case "${comm_name}" in
      pingpong_contai)
         return 0
         ;;
   esac

   cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
   case "${cmdline}" in
      *"/pingpong_container"*)
         return 0
         ;;
   esac

   return 1
}

kill_leaked_test_containers()
{
   local killed_any=0

   for procdir in /proc/[0-9]*
   do
      if [[ ! -d "${procdir}" ]]
      then
         continue
      fi

      local pid="${procdir##*/}"
      if is_test_container_process "${pid}"
      then
         kill -TERM "${pid}" >/dev/null 2>&1 || true
         killed_any=1
      fi
   done

   if [[ "${killed_any}" -eq 0 ]]
   then
      return 0
   fi

   sleep 0.2

   for procdir in /proc/[0-9]*
   do
      if [[ ! -d "${procdir}" ]]
      then
         continue
      fi

      local pid="${procdir##*/}"
      if is_test_container_process "${pid}"
      then
         kill -KILL "${pid}" >/dev/null 2>&1 || true
      fi
   done
}

prepare_brain_fs_roots()
{
   if [[ ! -d /containers ]]
   then
      mkdir -p /containers
   fi

   brain_fs_parent="/containers/.prodigy-dev-fs-${$}-${RANDOM}"
   mkdir -p "${brain_fs_parent}"
   # Keep launcher stdout logs on the host-visible harness tmp root so failure
   # diagnostics survive even when the disposable container filesystem tree is
   # private to a mount namespace or cleaned independently of keep-fs mode.
   brain_log_root="${tmpdir}/logs"
   mkdir -p "${brain_log_root}"
   brain_fs_control_root="${brain_fs_parent}/control"
   mkdir -p "${brain_fs_control_root}"
   brain_fs_shared_store_backing="${brain_fs_parent}/shared-store"
   mkdir -p "${brain_fs_shared_store_backing}"
   brain_fs_shared_store="${brain_fs_shared_store_backing}"

   local idx=0
   for idx in $(seq 1 "${node_count}")
   do
      local root="${brain_fs_parent}/brain${idx}"
      local install_root="${root}/root/prodigy"
      mkdir -p "${root}/root"
      stage_prodigy_install_root_from_bundle "${prodigy_runtime_bundle_path}" "${install_root}"

      if [[ -n "${tunnel_ebpf}" ]]
      then
         local installed_tunnel_name=""
         installed_tunnel_name="$(basename -- "${tunnel_ebpf}")"
         install -m 0644 "${tunnel_ebpf}" "${install_root}/${installed_tunnel_name}"
         runtime_tunnel_ebpf="/root/prodigy/${installed_tunnel_name}"
      fi

      if [[ -n "${host_ingress_ebpf}" ]]
      then
         local installed_host_ingress_name=""
         installed_host_ingress_name="$(basename -- "${host_ingress_ebpf}")"
         install -m 0644 "${host_ingress_ebpf}" "${install_root}/${installed_host_ingress_name}"
         runtime_host_ingress_ebpf="/root/prodigy/${installed_host_ingress_name}"
      fi

      if [[ -n "${host_egress_ebpf}" ]]
      then
         local installed_host_egress_name=""
         installed_host_egress_name="$(basename -- "${host_egress_ebpf}")"
         install -m 0644 "${host_egress_ebpf}" "${install_root}/${installed_host_egress_name}"
         runtime_host_egress_ebpf="/root/prodigy/${installed_host_egress_name}"
      fi

      if [[ -n "${switchboard_balancer_ebpf}" ]]
      then
         local installed_switchboard_balancer_name=""
         installed_switchboard_balancer_name="$(basename -- "${switchboard_balancer_ebpf}")"
         install -m 0644 "${switchboard_balancer_ebpf}" "${install_root}/${installed_switchboard_balancer_name}"
         runtime_switchboard_balancer_ebpf="/root/prodigy/${installed_switchboard_balancer_name}"
      fi

      brain_fs_roots+=("${root}")
   done
}

delete_btrfs_subvolumes_under()
{
   local root="$1"
   if [[ -z "${root}" || ! -d "${root}" ]]
   then
      return 0
   fi

   if ! command -v btrfs >/dev/null 2>&1
   then
      return 0
   fi

   local -a rel_paths=()
   mapfile -t rel_paths < <(
      btrfs subvolume list -o "${root}" 2>/dev/null \
         | awk -F ' path ' 'NF==2 {print $2}' \
         | awk '{print length($0) ":" $0}' \
         | sort -rn
   )

   local entry=""
   for entry in "${rel_paths[@]}"
   do
      local rel="${entry#*:}"
      if [[ -n "${rel}" ]]
      then
         btrfs subvolume delete "/containers/${rel}" >/dev/null 2>&1 || true
      fi
   done
}

cleanup_brain_fs_roots()
{
   local root=""

   for root in "${brain_fs_roots[@]}"
   do
      if [[ -z "${root}" ]]
      then
         continue
      fi

      delete_btrfs_subvolumes_under "${root}"
      rm -rf "${root}" >/dev/null 2>&1 || true
   done

   if [[ -n "${brain_fs_shared_store_backing}" ]]
   then
      delete_btrfs_subvolumes_under "${brain_fs_shared_store_backing}"
      rm -rf "${brain_fs_shared_store_backing}" >/dev/null 2>&1 || true
   fi

   if [[ -n "${brain_fs_shared_store}" && "${brain_fs_shared_store}" != "${brain_fs_shared_store_backing}" ]]
   then
      rmdir "${brain_fs_shared_store}" >/dev/null 2>&1 || rm -rf "${brain_fs_shared_store}" >/dev/null 2>&1 || true
   fi

   if [[ -n "${brain_fs_parent}" ]]
   then
      rmdir "${brain_fs_parent}" >/dev/null 2>&1 || rm -rf "${brain_fs_parent}" >/dev/null 2>&1 || true
   fi
}

dump_brain_container_artifacts()
{
   local brain_label="$1"
   local root="$2"

   echo "--- ${brain_label} container artifacts ---"

   if [[ -z "${root}" || ! -d "${root}" ]]
   then
      echo "(missing root: ${root})"
      return
   fi

   local -a artifact_files=()
   mapfile -t artifact_files < <(
      find "${root}" -maxdepth 4 -type f \
         \( -name "bootstage.txt" -o -name "crashreport.txt" -o -name "aegis.hash.log" -o -name "params.dump" -o -name "readytrace.log" -o -name "stdout.log" -o -name "stderr.log" \) \
         | sort
   )

   if [[ "${#artifact_files[@]}" -eq 0 ]]
   then
      echo "(no boot/crash/hash artifacts found under ${root})"
      return
   fi

   local file=""
   for file in "${artifact_files[@]}"
   do
      local rel_path="${file#${root}/}"
      if [[ "${rel_path}" == "${file}" ]]
      then
         rel_path="${file}"
      fi

      echo ">>> ${rel_path}"
      sed -n '1,200p' "${file}" 2>/dev/null || true
   done
}

terminate_tracked_brain_wrappers()
{
   for pid in "${pids[@]}"
   do
      if [[ -z "${pid}" ]]
      then
         continue
      fi

      kill -INT -- "-${pid}" >/dev/null 2>&1 || kill -INT "${pid}" >/dev/null 2>&1 || true
   done

   sleep 0.2

   for pid in "${pids[@]}"
   do
      if [[ -z "${pid}" ]]
      then
         continue
      fi

      if kill -0 "${pid}" >/dev/null 2>&1
      then
         kill -KILL -- "-${pid}" >/dev/null 2>&1 || kill -KILL "${pid}" >/dev/null 2>&1 || true
      fi
   done
}

terminate_netns_processes()
{
   local ns="$1"
   local ns_pids=""
   ns_pids="$(ip netns pids "${ns}" 2>/dev/null || true)"

   if [[ -z "${ns_pids}" ]]
   then
      return
   fi

   kill -TERM ${ns_pids} >/dev/null 2>&1 || true
   sleep 0.2
   kill -KILL ${ns_pids} >/dev/null 2>&1 || true
}

cleanup()
{
   if [[ "${cleanup_ran}" -eq 1 ]]
   then
      return
   fi
   cleanup_ran=1

   set +e

   terminate_tracked_brain_wrappers

   for ns in "${child_names[@]}"
   do
      terminate_netns_processes "${ns}"
   done
   terminate_netns_processes "${parent_ns}"

   if [[ "${enable_fake_ipv4_boundary}" == "1" ]]
   then
      if [[ "${host_edge_rule_fwd6_in_added}" -eq 1 && -n "${ip6tables_cmd}" && -n "${host_edge_if}" ]]
      then
         "${ip6tables_cmd}" -D FORWARD ! -i "${host_edge_if}" -o "${host_edge_if}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || true
      fi

      if [[ "${host_edge_rule_fwd6_out_added}" -eq 1 && -n "${ip6tables_cmd}" && -n "${host_edge_if}" ]]
      then
         "${ip6tables_cmd}" -D FORWARD -i "${host_edge_if}" ! -o "${host_edge_if}" -j ACCEPT >/dev/null 2>&1 || true
      fi

      if [[ "${host_edge_rule_nat6_added}" -eq 1 && -n "${ip6tables_cmd}" ]]
      then
         "${ip6tables_cmd}" -t nat -D POSTROUTING -s "${fake_public6_subnet_cidr}" -j MASQUERADE >/dev/null 2>&1 || true
      fi

      if [[ "${host_edge_rule_nat6_parent_added}" -eq 1 && -n "${ip6tables_cmd}" ]]
      then
         "${ip6tables_cmd}" -t nat -D POSTROUTING -s "${parent_edge_ip6}/128" -j MASQUERADE >/dev/null 2>&1 || true
      fi

      if [[ "${host_edge_rule_fwd_in_added}" -eq 1 && -n "${iptables_cmd}" && -n "${host_edge_if}" ]]
      then
         "${iptables_cmd}" -D FORWARD ! -i "${host_edge_if}" -o "${host_edge_if}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || true
      fi

      if [[ "${host_edge_rule_fwd_out_added}" -eq 1 && -n "${iptables_cmd}" && -n "${host_edge_if}" ]]
      then
         "${iptables_cmd}" -D FORWARD -i "${host_edge_if}" ! -o "${host_edge_if}" -j ACCEPT >/dev/null 2>&1 || true
      fi

      if [[ "${host_edge_rule_nat_added}" -eq 1 && -n "${iptables_cmd}" && -n "${host_edge_if}" ]]
      then
         "${iptables_cmd}" -t nat -D POSTROUTING -s "${parent_edge_ip}/32" ! -o "${host_edge_if}" -j MASQUERADE >/dev/null 2>&1 || true
      fi

      if [[ "${host_edge_policy_rule_added}" -eq 1 ]]
      then
         ip rule del pref 99 from "${parent_edge_ip}/32" table "${host_policy_table}" >/dev/null 2>&1 || true
      fi

      if [[ "${host_edge_policy_route_added}" -eq 1 ]]
      then
         ip route del table "${host_policy_table}" default >/dev/null 2>&1 || true
      fi

      if [[ "${host_edge_policy_rule6_added}" -eq 1 ]]
      then
         ip -6 rule del pref 98 from "${fake_public6_subnet_cidr}" table "${host_policy_table}" >/dev/null 2>&1 || true
      fi

      if [[ "${host_edge_policy_rule6_parent_added}" -eq 1 ]]
      then
         ip -6 rule del pref 97 from "${parent_edge_ip6}/128" table "${host_policy_table}" >/dev/null 2>&1 || true
      fi

      if [[ "${host_edge_policy_route6_added}" -eq 1 ]]
      then
         ip -6 route del table "${host_policy_table}" default >/dev/null 2>&1 || true
      fi

      if [[ "${parent_edge_rule_nat6_added}" -eq 1 && -n "${ip6tables_cmd}" && -n "${parent_edge_if}" ]]
      then
         ip netns exec "${parent_ns}" "${ip6tables_cmd}" -t nat -D POSTROUTING -s "${fake_public6_subnet_cidr}" -o "${parent_edge_if}" -j SNAT --to-source "${parent_edge_ip6}" >/dev/null 2>&1 || true
      fi

      if [[ -n "${host_ip_forward_prev}" ]]
      then
         sysctl -q -w "net.ipv4.ip_forward=${host_ip_forward_prev}" >/dev/null 2>&1 || true
      fi

      if [[ -n "${host_ip6_forward_prev}" ]]
      then
         sysctl -q -w "net.ipv6.conf.all.forwarding=${host_ip6_forward_prev}" >/dev/null 2>&1 || true
      fi

      if [[ "${keep_tmp}" != "1" ]]
      then
         if [[ -n "${fake_ipv4_boundary_pin_dir}" ]]
         then
            rm -rf "${fake_ipv4_boundary_pin_dir}" >/dev/null 2>&1 || true
         fi

         if [[ "${fake_ipv4_boundary_pin_mounted}" -eq 1 && -n "${fake_ipv4_boundary_pin_root}" ]]
         then
            umount "${fake_ipv4_boundary_pin_root}" >/dev/null 2>&1 || true
         fi

         if [[ -n "${fake_ipv4_boundary_pin_root}" ]]
         then
            rm -rf "${fake_ipv4_boundary_pin_root}" >/dev/null 2>&1 || true
         fi
      else
         if [[ -n "${fake_ipv4_boundary_pin_root}" ]]
         then
            echo "DEBUG: preserved fake ipv4 boundary pin root ${fake_ipv4_boundary_pin_root}"
         fi
      fi
   fi

   # Prevent cross-test contamination from orphaned container test binaries.
   kill_leaked_test_containers

   for ns in "${child_names[@]}"
   do
      ip netns del "${ns}" >/dev/null 2>&1 || true
   done
   ip netns del "${parent_ns}" >/dev/null 2>&1 || true
   if [[ -n "${host_edge_if}" ]]
   then
      ip link del "${host_edge_if}" >/dev/null 2>&1 || true
   fi

   if [[ "${keep_fs}" != "1" ]]
   then
      cleanup_brain_fs_roots
   else
      echo "DEBUG: preserved brain fs root ${brain_fs_parent}"
   fi

   if [[ -n "${deploy_container_runtime_path}" && -n "${deploy_container_zstd}" && "${deploy_container_runtime_path}" != "${deploy_container_zstd}" ]]
   then
      rm -f "${deploy_container_runtime_path}" >/dev/null 2>&1 || true
   fi

   if [[ -n "${deploy_second_container_runtime_path}" && -n "${deploy_second_container_zstd}" && "${deploy_second_container_runtime_path}" != "${deploy_second_container_zstd}" ]]
   then
      rm -f "${deploy_second_container_runtime_path}" >/dev/null 2>&1 || true
   fi

   if [[ -n "${deploy_third_container_runtime_path}" && -n "${deploy_third_container_zstd}" && "${deploy_third_container_runtime_path}" != "${deploy_third_container_zstd}" ]]
   then
      rm -f "${deploy_third_container_runtime_path}" >/dev/null 2>&1 || true
   fi

   if [[ "${keep_tmp}" != "1" ]]
   then
      rm -rf "${tmpdir}"
   else
      echo "DEBUG: preserved tmpdir ${tmpdir}"
   fi
}

handle_cleanup_signal()
{
   cleanup
   exit 1
}

trap cleanup EXIT
trap handle_cleanup_signal INT TERM HUP

# Prevent a prior aborted run from contaminating this run or burning CPU.
kill_leaked_test_containers

prepare_brain_fs_roots

mothership_socket_path="${brain_fs_control_root}/prodigy-mothership.sock"
public_mothership_socket_path="${tmpdir}/prodigy-mothership.sock"
rm -f "${mothership_socket_path}"
rm -f "${public_mothership_socket_path}"
ln -s "${mothership_socket_path}" "${public_mothership_socket_path}"

ip netns add "${parent_ns}"
ip netns exec "${parent_ns}" ip link set lo up

parent_ino="$(ip netns exec "${parent_ns}" stat -Lc '%i' /proc/self/ns/net)"
if [[ "${parent_ino}" == "${host_netns_ino}" ]]
then
   echo "FAIL: parent netns inode matches host netns inode (${host_netns_ino})"
   exit 1
fi

for idx in $(seq 1 "${node_count}")
do
   ns="prodigy-dev-brain${idx}-${$}-${RANDOM}"
   child_names+=("${ns}")

   # Create each child netns from inside the parent netns, then attach a name.
   ip netns exec "${parent_ns}" unshare -n -- bash -lc 'sleep 60' &
   seed_pid=$!
   sleep 0.1
   ip netns attach "${ns}" "${seed_pid}"
   kill "${seed_pid}" >/dev/null 2>&1 || true
   wait "${seed_pid}" 2>/dev/null || true

   ip netns exec "${ns}" ip link set lo up
done

child_inodes=()
for ns in "${child_names[@]}"
do
   ino="$(ip netns exec "${ns}" stat -Lc '%i' /proc/self/ns/net)"
   child_inodes+=("${ino}")

   if [[ "${ino}" == "${host_netns_ino}" ]]
   then
      echo "FAIL: child netns ${ns} matches host netns inode"
      exit 1
   fi
done

for i in $(seq 0 $((${#child_inodes[@]} - 1)))
do
   for j in $(seq $((i + 1)) $((${#child_inodes[@]} - 1)))
   do
      if [[ "${child_inodes[$i]}" == "${child_inodes[$j]}" ]]
      then
         echo "FAIL: child netns ${child_names[$i]} and ${child_names[$j]} are not unique"
         exit 1
      fi
   done
done

ip netns exec "${parent_ns}" ip link add prodigy-br0 type bridge
ip netns exec "${parent_ns}" ip link set dev prodigy-br0 type bridge mcast_snooping 0
ip netns exec "${parent_ns}" ip addr add 10.0.0.1/24 dev prodigy-br0
ip netns exec "${parent_ns}" ip -6 addr add fd00:10::1/64 nodad dev prodigy-br0
if [[ "${enable_fake_ipv4_boundary}" == "1" ]]
then
   ip netns exec "${parent_ns}" ip -6 addr add 2602:fac0:0:12ab:34cd::1/64 nodad dev prodigy-br0
else
   ip netns exec "${parent_ns}" ip -6 addr add 2001:db8:100::1/64 nodad dev prodigy-br0
fi
ip netns exec "${parent_ns}" ip link set prodigy-br0 up

for idx in $(seq 1 "${node_count}")
do
   ns="${child_names[$((idx - 1))]}"
   parent_if="bp${idx}"
   child_if="bc${idx}"
   brain_ip="${assigned_brain_ips[$((idx - 1))]}"
   brain_ip6="${assigned_brain_ips6[$((idx - 1))]}"
   brain_public_ip6="${assigned_brain_public_ips6[$((idx - 1))]}"
   parent_ifs+=("${parent_if}")

   ip netns exec "${parent_ns}" ip link add "${parent_if}" type veth peer name "${child_if}"
   ip netns exec "${parent_ns}" ip link set "${parent_if}" master prodigy-br0
   ip netns exec "${parent_ns}" ip link set "${parent_if}" up
   ip netns exec "${parent_ns}" ip link set "${child_if}" netns "${ns}"

   ip netns exec "${ns}" ip link set "${child_if}" name bond0
   ip netns exec "${ns}" ip link set bond0 up
   ip netns exec "${ns}" ip addr add "${brain_ip}/24" dev bond0
   ip netns exec "${ns}" ip -6 addr add "${brain_ip6}/64" nodad dev bond0
   ip netns exec "${ns}" ip -6 addr add "${brain_public_ip6}/64" nodad dev bond0
   ip netns exec "${ns}" ip route replace default via 10.0.0.1 dev bond0
   ip netns exec "${ns}" ip -6 route replace default via fd00:10::1 dev bond0
done

# Make peer routing explicit so all cluster-node traffic stays on bond0/veth.
for src_idx in $(seq 1 "${node_count}")
do
   src_ns="${child_names[$((src_idx - 1))]}"

   for dst_idx in $(seq 1 "${node_count}")
   do
      if [[ "${src_idx}" == "${dst_idx}" ]]
      then
         continue
      fi

      dst_ip="${assigned_brain_ips[$((dst_idx - 1))]}"
      dst_ip6="${assigned_brain_ips6[$((dst_idx - 1))]}"
      dst_public_ip6="${assigned_brain_public_ips6[$((dst_idx - 1))]}"
      ip netns exec "${src_ns}" ip route replace "${dst_ip}/32" dev bond0 scope link
      ip netns exec "${src_ns}" ip -6 route replace "${dst_ip6}/128" dev bond0 scope link
      ip netns exec "${src_ns}" ip -6 route replace "${dst_public_ip6}/128" dev bond0 scope link
   done
done

setup_fake_ipv4_boundary()
{
   local egress_prog_pin=""
   local ingress_prog_pin=""

   switchboard_gateway_ip="${assigned_brain_ips[$((switchboard_gateway_index - 1))]}"
   switchboard_gateway_ip6="${assigned_brain_ips6[$((switchboard_gateway_index - 1))]}"
   if [[ -z "${switchboard_gateway_ip}" ]]
   then
      echo "FAIL: unable to resolve switchboard gateway IP for index ${switchboard_gateway_index}"
      return 1
   fi
   if [[ -z "${switchboard_gateway_ip6}" ]]
   then
      echo "FAIL: unable to resolve switchboard gateway IPv6 for index ${switchboard_gateway_index}"
      return 1
   fi

   host_edge_if="peh${$}"
   parent_edge_if="pep${$}"

   if [[ "${#host_edge_if}" -gt 15 || "${#parent_edge_if}" -gt 15 ]]
   then
      echo "FAIL: generated boundary interface names exceed Linux IFNAMSIZ"
      return 1
   fi

   if [[ "${fake_ipv4_boundary_rebuild}" == "1" ]]
   then
      if ! build_fake_ipv4_boundary_ebpf_object
      then
         return 1
      fi
   fi

   if [[ -z "${fake_ipv4_boundary_ebpf}" || ! -f "${fake_ipv4_boundary_ebpf}" ]]
   then
      echo "FAIL: fake ipv4 boundary eBPF object missing: ${fake_ipv4_boundary_ebpf}"
      return 1
   fi

   fake_ipv4_boundary_pin_root="${tmpdir}/fake_ipv4_boundary_bpffs"
   fake_ipv4_boundary_pin_dir="${fake_ipv4_boundary_pin_root}/progs"
   fake_ipv4_boundary_pin_mounted=0
   mkdir -p "${fake_ipv4_boundary_pin_root}"
   if ! mountpoint -q "${fake_ipv4_boundary_pin_root}"
   then
      if ! mount -t bpf bpf "${fake_ipv4_boundary_pin_root}"
      then
         echo "FAIL: unable to mount bpffs at ${fake_ipv4_boundary_pin_root}"
         return 1
      fi

      fake_ipv4_boundary_pin_mounted=1
   fi

   rm -rf "${fake_ipv4_boundary_pin_dir}" >/dev/null 2>&1 || true
   mkdir -p "${fake_ipv4_boundary_pin_dir}"

   if ! bpftool prog loadall "${fake_ipv4_boundary_ebpf}" "${fake_ipv4_boundary_pin_dir}" >/dev/null 2>&1
   then
      echo "FAIL: unable to load fake ipv4 boundary eBPF programs from ${fake_ipv4_boundary_ebpf}"
      return 1
   fi

   egress_prog_pin="${fake_ipv4_boundary_pin_dir}/fake_ipv4_boundary_nat_egress"
   ingress_prog_pin="${fake_ipv4_boundary_pin_dir}/fake_ipv4_boundary_nat_ingress"
   if [[ ! -f "${egress_prog_pin}" || ! -f "${ingress_prog_pin}" ]]
   then
      echo "FAIL: fake ipv4 boundary eBPF pinned programs missing under ${fake_ipv4_boundary_pin_dir}"
      return 1
   fi

   ip link del "${host_edge_if}" >/dev/null 2>&1 || true
   ip link add "${host_edge_if}" type veth peer name "${parent_edge_if}"
   ip link set "${parent_edge_if}" netns "${parent_ns}"

   ip addr add "${host_edge_ip}/30" dev "${host_edge_if}"
   # Keep host/parent edge endpoints on the same subnet; ::1 and ::2 are not peers on /127.
   ip -6 addr add "${host_edge_ip6}/126" dev "${host_edge_if}"
   ip link set "${host_edge_if}" up

   ip netns exec "${parent_ns}" ip link set "${parent_edge_if}" up
   ip netns exec "${parent_ns}" ip addr add "${parent_edge_ip}/30" dev "${parent_edge_if}"
   ip netns exec "${parent_ns}" ip -6 addr add "${parent_edge_ip6}/126" dev "${parent_edge_if}"
   ip netns exec "${parent_ns}" ip route replace default via "${host_edge_ip}" dev "${parent_edge_if}"
   ip netns exec "${parent_ns}" ip -6 route replace default via "${host_edge_ip6}" dev "${parent_edge_if}"
   ip netns exec "${parent_ns}" ip route replace "${fake_ipv4_subnet_cidr}" via "${switchboard_gateway_ip}" dev prodigy-br0
   ip netns exec "${parent_ns}" ip -6 route replace "${fake_public6_subnet_cidr}" via "${switchboard_gateway_ip6}" dev prodigy-br0
   ip netns exec "${parent_ns}" sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
   ip netns exec "${parent_ns}" sysctl -q -w net.ipv6.conf.all.forwarding=1 >/dev/null
   ip netns exec "${parent_ns}" "${ip6tables_cmd}" -t nat -A POSTROUTING -s "${fake_public6_subnet_cidr}" -o "${parent_edge_if}" -j SNAT --to-source "${parent_edge_ip6}"
   parent_edge_rule_nat6_added=1

   host_uplink_if="$(ip route show default 2>/dev/null | awk 'NR==1 {for (i = 1; i <= NF; ++i) if ($i == "dev") {print $(i + 1); exit}}')"
   host_uplink_gateway="$(ip route show default 2>/dev/null | awk 'NR==1 {for (i = 1; i <= NF; ++i) if ($i == "via") {print $(i + 1); exit}}')"
   if [[ -z "${host_uplink_if}" || -z "${host_uplink_gateway}" ]]
   then
      echo "FAIL: unable to resolve host default uplink route for fake ipv4 boundary NAT"
      return 1
   fi

   host_uplink_if6="$(ip -6 route show default 2>/dev/null | awk 'NR==1 {for (i = 1; i <= NF; ++i) if ($i == "dev") {print $(i + 1); exit}}')"
   host_uplink_gateway6="$(ip -6 route show default 2>/dev/null | awk 'NR==1 {for (i = 1; i <= NF; ++i) if ($i == "via") {print $(i + 1); exit}}')"
   if [[ -z "${host_uplink_if6}" ]]
   then
      host_uplink_if6="$(ip -6 route get 2607:f8b0:400a:801::2004 2>/dev/null | awk 'NR==1 {for (i = 1; i <= NF; ++i) if ($i == "dev") {print $(i + 1); exit}}')"
   fi
   if [[ -z "${host_uplink_if6}" ]]
   then
      host_uplink_if6="$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk 'NR==1 {for (i = 1; i <= NF; ++i) if ($i == "dev") {print $(i + 1); exit}}')"
   fi
   if [[ -z "${host_uplink_if6}" ]]
   then
      echo "FAIL: unable to resolve host default IPv6 uplink route for dev boundary NAT"
      return 1
   fi

   ip route replace table "${host_policy_table}" default via "${host_uplink_gateway}" dev "${host_uplink_if}"
   host_edge_policy_route_added=1
   ip rule add pref 99 from "${parent_edge_ip}/32" table "${host_policy_table}"
   host_edge_policy_rule_added=1

   if [[ -n "${host_uplink_gateway6}" ]]
   then
      ip -6 route replace table "${host_policy_table}" default via "${host_uplink_gateway6}" dev "${host_uplink_if6}"
   else
      ip -6 route replace table "${host_policy_table}" default dev "${host_uplink_if6}"
   fi
   host_edge_policy_route6_added=1
   ip -6 rule add pref 98 from "${fake_public6_subnet_cidr}" table "${host_policy_table}"
   host_edge_policy_rule6_added=1
   ip -6 rule add pref 97 from "${parent_edge_ip6}/128" table "${host_policy_table}"
   host_edge_policy_rule6_parent_added=1

   host_ip_forward_prev="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
   sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
   host_ip6_forward_prev="$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 0)"
   sysctl -q -w net.ipv6.conf.all.forwarding=1 >/dev/null

   "${iptables_cmd}" -t nat -A POSTROUTING -s "${parent_edge_ip}/32" ! -o "${host_edge_if}" -j MASQUERADE
   host_edge_rule_nat_added=1
   "${iptables_cmd}" -A FORWARD -i "${host_edge_if}" ! -o "${host_edge_if}" -j ACCEPT
   host_edge_rule_fwd_out_added=1
   "${iptables_cmd}" -A FORWARD ! -i "${host_edge_if}" -o "${host_edge_if}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
   host_edge_rule_fwd_in_added=1

   "${ip6tables_cmd}" -t nat -A POSTROUTING -s "${fake_public6_subnet_cidr}" -j MASQUERADE
   host_edge_rule_nat6_added=1
   "${ip6tables_cmd}" -t nat -A POSTROUTING -s "${parent_edge_ip6}/128" -j MASQUERADE
   host_edge_rule_nat6_parent_added=1
   "${ip6tables_cmd}" -A FORWARD -i "${host_edge_if}" ! -o "${host_edge_if}" -j ACCEPT
   host_edge_rule_fwd6_out_added=1
   "${ip6tables_cmd}" -A FORWARD ! -i "${host_edge_if}" -o "${host_edge_if}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
   host_edge_rule_fwd6_in_added=1

   ip netns exec "${parent_ns}" tc qdisc replace dev "${parent_edge_if}" clsact
   ip netns exec "${parent_ns}" tc filter replace dev "${parent_edge_if}" egress bpf da pinned "${egress_prog_pin}"
   ip netns exec "${parent_ns}" tc filter replace dev "${parent_edge_if}" ingress bpf da pinned "${ingress_prog_pin}"

   echo "BOUNDARY_FAKE_IPV4 enabled edge=${parent_edge_if} uplink4=${host_uplink_if} via4=${host_uplink_gateway} uplink6=${host_uplink_if6} via6=${host_uplink_gateway6:-none} gateway4=${switchboard_gateway_ip} gateway6=${switchboard_gateway_ip6} subnet4=${fake_ipv4_subnet_cidr} subnet6=${fake_public6_subnet_cidr}"
   return 0
}

if [[ "${enable_fake_ipv4_boundary}" == "1" ]]
then
   if ! setup_fake_ipv4_boundary
   then
      exit 1
   fi
fi

private4_to_ipv4()
{
   local private4="$1"
   if ! [[ "${private4}" =~ ^[0-9]+$ ]]
   then
      return 1
   fi

   local a=$((private4 & 255))
   local b=$(((private4 >> 8) & 255))
   local c=$(((private4 >> 16) & 255))
   local d=$(((private4 >> 24) & 255))
   printf '%d.%d.%d.%d' "${a}" "${b}" "${c}" "${d}"
}

refresh_fake_ipv4_gateway_route_from_primary_deploy()
{
   if [[ "${enable_fake_ipv4_boundary}" != "1" ]]
   then
      return 0
   fi

   local machine_private4=""
   local resolved_gateway=""
   local resolved_gateway6=""
   local matched_idx=-1

   for _attempt in $(seq 1 100)
   do
      machine_private4="$(
         rg -o --no-line-number 'schedule spinContainer deploymentID=[0-9]+ appID=[0-9]+ machinePrivate4=[0-9]+' \
            "${brain_log_root}"/brain*.stdout.log 2>/dev/null \
            | sed -E 's/.*machinePrivate4=([0-9]+).*/\1/' \
            | head -n 1 || true
      )"

      if [[ -n "${machine_private4}" ]]
      then
         break
      fi

      sleep 0.2
   done

   if [[ -z "${machine_private4}" ]]
   then
      echo "WARN: unable to resolve primary deploy machinePrivate4 for fake ipv4 route refresh"
      return 0
   fi

   if ! resolved_gateway="$(private4_to_ipv4 "${machine_private4}")"
   then
      echo "WARN: invalid machinePrivate4 for fake ipv4 route refresh: ${machine_private4}"
      return 0
   fi

   if ! ip netns exec "${parent_ns}" ip route replace "${fake_ipv4_subnet_cidr}" via "${resolved_gateway}" dev prodigy-br0 >/dev/null 2>&1
   then
      echo "WARN: failed to refresh fake ipv4 route via ${resolved_gateway}"
      return 0
   fi

   for i in $(seq 0 $((${#assigned_brain_ips[@]} - 1)))
   do
      if [[ "${assigned_brain_ips[$i]}" == "${resolved_gateway}" ]]
      then
         matched_idx="${i}"
         break
      fi
   done

   if [[ "${matched_idx}" -ge 0 && "${matched_idx}" -lt "${#assigned_brain_ips6[@]}" ]]
   then
      resolved_gateway6="${assigned_brain_ips6[$matched_idx]}"

      if ! ip netns exec "${parent_ns}" ip -6 route replace "${fake_public6_subnet_cidr}" via "${resolved_gateway6}" dev prodigy-br0 >/dev/null 2>&1
      then
         echo "WARN: failed to refresh fake public6 route via ${resolved_gateway6}"
      fi
   fi

   if [[ "${switchboard_gateway_ip}" != "${resolved_gateway}" ]]
   then
      echo "BOUNDARY_FAKE_IPV4 route_update old_gateway=${switchboard_gateway_ip} new_gateway=${resolved_gateway} machinePrivate4=${machine_private4}"
   fi

   switchboard_gateway_ip="${resolved_gateway}"
   if [[ -n "${resolved_gateway6}" ]]
   then
      switchboard_gateway_ip6="${resolved_gateway6}"
   fi
   return 0
}

resolve_second_deploy_machine_fragment_from_logs()
{
   local private6_addr=""
   local last_hextet=""
   local hextet_value=0
   local machine_fragment=0

   for _attempt in $(seq 1 120)
   do
      private6_addr="$(
         rg -o --no-line-number 'createContainer plan deploymentID=[0-9]+ appID=[0-9]+ .*private6=[^/ ]+' \
            "${brain_log_root}"/brain*.stdout.log 2>/dev/null \
            | sed -E 's/.*private6=([^ ]+).*/\1/' \
            | tail -n 1 || true
      )"

      if [[ -n "${private6_addr}" ]]
      then
         break
      fi

      sleep 0.2
   done

   if [[ -z "${private6_addr}" ]]
   then
      return 1
   fi

   last_hextet="${private6_addr##*:}"
   if [[ -z "${last_hextet}" ]] || ! [[ "${last_hextet}" =~ ^[0-9a-fA-F]{1,4}$ ]]
   then
      return 1
   fi

   hextet_value=$((16#${last_hextet}))
   machine_fragment=$(((hextet_value >> 8) & 255))
   if [[ "${machine_fragment}" -le 0 || "${machine_fragment}" -gt 255 ]]
   then
      return 1
   fi

   echo "${machine_fragment}"
   return 0
}

mac_to_hex_words()
{
   local mac="$1"
   if [[ "${mac}" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]]
   then
      echo "${mac}" | tr '[:upper:]' '[:lower:]' | tr ':' ' '
      return 0
   fi

   return 1
}

find_map_id_for_prog()
{
   local ns="$1"
   local prog_id="$2"
   local target_name="$3"
   local map_ids_csv=""
   local map_id=""

   map_ids_csv="$(
      ip netns exec "${ns}" bpftool prog show id "${prog_id}" 2>/dev/null \
         | sed -n 's/.*map_ids //p' \
         | head -n 1 \
         | tr -d '[:space:]'
   )"

   if [[ -z "${map_ids_csv}" ]]
   then
      return 1
   fi

   IFS=',' read -r -a _map_ids <<< "${map_ids_csv}"
   for map_id in "${_map_ids[@]}"
   do
      map_id="$(printf '%s' "${map_id}" | tr -d '[:space:]')"
      if ! [[ "${map_id}" =~ ^[0-9]+$ ]]
      then
         continue
      fi

      local map_name=""
      map_name="$(
         ip netns exec "${ns}" bpftool map show id "${map_id}" 2>/dev/null \
            | awk '
               {
                  for (i = 1; i <= NF; ++i)
                  {
                     if ($i == "name" && (i + 1) <= NF)
                     {
                        print $(i + 1);
                        exit;
                     }
                  }
               }
            '
      )"

      if [[ -z "${map_name}" ]]
      then
         continue
      fi

      # BPF map names are capped at 15 bytes by the kernel, so bpftool can
      # report a truncated map_name (for example "local_container" for
      # "local_container_subnet_map"). Accept exact and prefix matches.
      if [[ "${map_name}" == "${target_name}" || "${target_name}" == "${map_name}"* || "${map_name}" == "${target_name}"* ]]
      then
         echo "${map_id}"
         return 0
      fi
   done

   return 1
}

configure_dev_switchboard_balancer_on_gateway()
{
   if [[ "${enable_fake_ipv4_boundary}" != "1" ]]
   then
      return 0
   fi

   if [[ -z "${switchboard_balancer_ebpf}" ]]
   then
      echo "WARN: PRODIGY_DEV_SWITCHBOARD_BALANCER_EBPF not set; skipping dev switchboard balancer attach"
      return 0
   fi

   if [[ ! -f "${switchboard_balancer_ebpf}" ]]
   then
      echo "FAIL: switchboard balancer eBPF object missing: ${switchboard_balancer_ebpf}"
      return 1
   fi

   local gateway_idx=-1
   local i=0
   for i in $(seq 0 $((${#assigned_brain_ips[@]} - 1)))
   do
      if [[ "${assigned_brain_ips[$i]}" == "${switchboard_gateway_ip}" ]]
      then
         gateway_idx="${i}"
         break
      fi
   done

   if [[ "${gateway_idx}" -lt 0 ]]
   then
      echo "FAIL: unable to resolve gateway brain index for switchboard_gateway_ip=${switchboard_gateway_ip}"
      return 1
   fi

   local gateway_ns="${child_names[$gateway_idx]}"

   local already_attached=0
   if ip netns exec "${gateway_ns}" bpftool net 2>/dev/null | rg -q 'xdp[[:space:]].*balancer_ingress'
   then
      already_attached=1
   fi

   local native_attach_err=""
   local generic_attach_err=""
   local native_attach_rc=0
   local generic_attach_rc=0
   local attach_mode=""
   if [[ "${already_attached}" -eq 1 ]]
   then
      attach_mode="existing"
   else
      ip netns exec "${gateway_ns}" ip link set dev bond0 xdp off >/dev/null 2>&1 || true
      native_attach_err="$(
         ip netns exec "${gateway_ns}" ip link set dev bond0 xdp obj "${switchboard_balancer_ebpf}" sec xdp 2>&1 >/dev/null
      )"
      native_attach_rc=$?
      if [[ "${native_attach_rc}" -eq 0 ]]
      then
         attach_mode="xdp"
      else
         generic_attach_err="$(
            ip netns exec "${gateway_ns}" ip link set dev bond0 xdpgeneric obj "${switchboard_balancer_ebpf}" sec xdp 2>&1 >/dev/null
         )"
         generic_attach_rc=$?
         if [[ "${generic_attach_rc}" -eq 0 ]]
         then
            attach_mode="xdpgeneric"
         else
            echo "WARN: unable to attach dev switchboard balancer on ${gateway_ns}/bond0 native_rc=${native_attach_rc} native_err='${native_attach_err}' generic_rc=${generic_attach_rc} generic_err='${generic_attach_err}'"
            return 0
         fi
      fi
   fi

   local prog_id=""
   prog_id="$(
      ip netns exec "${gateway_ns}" ip -d link show dev bond0 2>/dev/null \
         | awk '
            /prog\/xdp id/ {
               for (i = 1; i <= NF; ++i) {
                  if ($i == "id") {
                     print $(i + 1);
                     exit;
                  }
               }
            }
         '
   )"

   if [[ -z "${prog_id}" ]]
   then
      prog_id="$(
         ip netns exec "${gateway_ns}" bpftool net 2>/dev/null \
            | awk '
               / id / {
                  for (i = 1; i <= NF; ++i) {
                     if ($i == "id") {
                        print $(i + 1);
                        exit;
                     }
                  }
               }
            '
      )"
   fi

   if [[ -z "${prog_id}" ]]
   then
      echo "WARN: unable to resolve attached xdp program id for ${gateway_ns}/bond0"
      return 0
   fi

   local local_subnet_map_id=""
   local mac_map_id=""
   local gateway_mac_map_id=""
   local_subnet_map_id="$(find_map_id_for_prog "${gateway_ns}" "${prog_id}" "local_container_subnet_map" || true)"
   mac_map_id="$(find_map_id_for_prog "${gateway_ns}" "${prog_id}" "mac_map" || true)"
   gateway_mac_map_id="$(find_map_id_for_prog "${gateway_ns}" "${prog_id}" "gateway_mac_map" || true)"

   if [[ -z "${local_subnet_map_id}" || -z "${mac_map_id}" || -z "${gateway_mac_map_id}" ]]
   then
      echo "WARN: unable to resolve required balancer map ids (local=${local_subnet_map_id} mac=${mac_map_id} gateway=${gateway_mac_map_id})"
      return 0
   fi

   local local_mac=""
   local gateway_mac=""
   local local_mac_hex=""
   local gateway_mac_hex=""
   local local_subnet_hex=""
   local subnet_source="fallback_gateway_ipv4"
   local dpfx_hex=""
   local machine_hex=""
   local key_hex="00 00 00 00"
   local host_ingress_prog_id=""
   local host_local_subnet_map_id=""
   local host_local_subnet_hex=""
   local host_local_subnet_lookup=""
   local host_dpfx=""
   local host_mpfx_csv=""
   local host_mpfx0=""
   local host_mpfx1=""
   local host_mpfx2=""
   local lookup_preview=""
   local machine_fragment_fallback="${switchboard_gateway_ip##*.}"

   local_mac="$(ip netns exec "${gateway_ns}" cat /sys/class/net/bond0/address 2>/dev/null || true)"
   gateway_mac="$(ip netns exec "${gateway_ns}" ip neigh show 10.0.0.1 dev bond0 2>/dev/null | awk '/lladdr/ {print $5; exit}')"
   if [[ -z "${gateway_mac}" ]]
   then
      ip netns exec "${gateway_ns}" ping -c1 -W1 10.0.0.1 >/dev/null 2>&1 || true
      gateway_mac="$(ip netns exec "${gateway_ns}" ip neigh show 10.0.0.1 dev bond0 2>/dev/null | awk '/lladdr/ {print $5; exit}')"
   fi

   if [[ -z "${gateway_mac}" ]]
   then
      # In this harness topology, 10.0.0.1 is parent_ns/prodigy-br0.
      # Fall back to the bridge MAC if ARP table priming is delayed.
      gateway_mac="$(ip netns exec "${parent_ns}" cat /sys/class/net/prodigy-br0/address 2>/dev/null || true)"
   fi

   if ! local_mac_hex="$(mac_to_hex_words "${local_mac}")"
   then
      echo "WARN: unable to parse local bond0 MAC in ${gateway_ns}: ${local_mac}"
      return 0
   fi

   if ! gateway_mac_hex="$(mac_to_hex_words "${gateway_mac}")"
   then
      echo "WARN: unable to parse gateway MAC in ${gateway_ns}: ${gateway_mac}"
      return 0
   fi

   host_ingress_prog_id="$(
      ip netns exec "${gateway_ns}" bpftool net 2>/dev/null \
         | awk '
            /tcx\/ingress/ && /host_ingress_router/ {
               for (i = 1; i <= NF; ++i) {
                  if ($i == "prog_id" && (i + 1) <= NF) {
                     print $(i + 1);
                     exit;
                  }
               }
            }
         '
   )"

   if [[ -z "${host_ingress_prog_id}" ]]
   then
      host_ingress_prog_id="$(
         ip netns exec "${gateway_ns}" bpftool prog show 2>/dev/null \
            | awk '
               /name host_ingress_router/ {
                  gsub(":", "", $1);
                  print $1;
                  exit;
               }
            '
      )"
   fi

   if [[ -n "${host_ingress_prog_id}" ]]
   then
      host_local_subnet_map_id="$(find_map_id_for_prog "${gateway_ns}" "${host_ingress_prog_id}" "local_container_subnet_map" || true)"
      if [[ -n "${host_local_subnet_map_id}" ]]
      then
         host_local_subnet_lookup="$(
            ip netns exec "${gateway_ns}" bpftool map lookup id "${host_local_subnet_map_id}" key hex ${key_hex} 2>/dev/null || true
         )"

         if [[ -n "${host_local_subnet_lookup}" ]]
         then
            host_dpfx="$(printf '%s\n' "${host_local_subnet_lookup}" | sed -n 's/.*"dpfx":[[:space:]]*\([0-9]\+\).*/\1/p' | head -n 1)"
            host_mpfx_csv="$(printf '%s\n' "${host_local_subnet_lookup}" | sed -n 's/.*"mpfx":[[:space:]]*\[\([^]]*\).*/\1/p' | head -n 1)"

            if [[ -n "${host_dpfx}" && -n "${host_mpfx_csv}" ]]
            then
               IFS=',' read -r host_mpfx0 host_mpfx1 host_mpfx2 _unused_mpfx <<< "${host_mpfx_csv}"
               host_mpfx0="${host_mpfx0//[^0-9]/}"
               host_mpfx1="${host_mpfx1//[^0-9]/}"
               host_mpfx2="${host_mpfx2//[^0-9]/}"

               if [[ "${host_dpfx}" =~ ^[0-9]+$ ]] && [[ "${host_mpfx0}" =~ ^[0-9]+$ ]] && [[ "${host_mpfx1}" =~ ^[0-9]+$ ]] && [[ "${host_mpfx2}" =~ ^[0-9]+$ ]]
               then
                  if [[ "${host_dpfx}" -ge 0 && "${host_dpfx}" -le 255 && "${host_mpfx0}" -ge 0 && "${host_mpfx0}" -le 255 && "${host_mpfx1}" -ge 0 && "${host_mpfx1}" -le 255 && "${host_mpfx2}" -ge 0 && "${host_mpfx2}" -le 255 ]]
                  then
                     printf -v host_local_subnet_hex '%02x %02x %02x %02x' "${host_dpfx}" "${host_mpfx0}" "${host_mpfx1}" "${host_mpfx2}"
                  fi
               fi
            fi
         fi
      fi
   fi

   if [[ -n "${host_local_subnet_hex}" ]]
   then
      local_subnet_hex="${host_local_subnet_hex}"
      subnet_source="host_ingress_local_subnet_map"
   else
      if ! [[ "${machine_fragment_fallback}" =~ ^[0-9]+$ ]] || [[ "${machine_fragment_fallback}" -le 0 ]] || [[ "${machine_fragment_fallback}" -gt 255 ]]
      then
         echo "FAIL: invalid machine fragment derived from switchboard gateway IP ${switchboard_gateway_ip}"
         return 1
      fi

      printf -v dpfx_hex '%02x' "${fragment}"
      printf -v machine_hex '%02x' "${machine_fragment_fallback}"
      local_subnet_hex="${dpfx_hex} 00 00 ${machine_hex}"
      lookup_preview="$(printf '%s' "${host_local_subnet_lookup}" | tr '\n' ' ' | tr -d '"' | sed 's/[[:space:]]\+/ /g' | cut -c1-160)"
      echo "WARN: unable to read host_ingress local_container_subnet_map in ${gateway_ns}; host_prog=${host_ingress_prog_id:-none} host_map=${host_local_subnet_map_id:-none} lookup=${lookup_preview:-none} fallback subnet=${local_subnet_hex}"
   fi

   if [[ -n "${switchboard_balancer_machine_fragment_override}" ]]
   then
      if [[ "${switchboard_balancer_machine_fragment_override}" =~ ^[0-9]+$ ]] && [[ "${switchboard_balancer_machine_fragment_override}" -gt 0 ]] && [[ "${switchboard_balancer_machine_fragment_override}" -le 255 ]]
      then
         local local_subnet_b0=""
         local local_subnet_b1=""
         local local_subnet_b2=""
         local _local_subnet_b3=""
         read -r local_subnet_b0 local_subnet_b1 local_subnet_b2 _local_subnet_b3 <<< "${local_subnet_hex}"
         printf -v machine_hex '%02x' "${switchboard_balancer_machine_fragment_override}"
         local_subnet_hex="${local_subnet_b0} ${local_subnet_b1} ${local_subnet_b2} ${machine_hex}"
         subnet_source="${subnet_source}+machine_override"
      else
         echo "WARN: invalid switchboard_balancer_machine_fragment_override=${switchboard_balancer_machine_fragment_override}; ignoring override"
      fi
   fi

   local local_subnet_update_err=""
   if ! local_subnet_update_err="$(ip netns exec "${gateway_ns}" bpftool map update id "${local_subnet_map_id}" key hex ${key_hex} value hex ${local_subnet_hex} 2>&1)"
   then
      echo "WARN: unable to update local_container_subnet_map in ${gateway_ns} err='${local_subnet_update_err}'"
      return 0
   fi

   # Keep all host_ingress_router local-subnet maps aligned with balancer so
   # local-pass encapsulated packets are recognized and redirected into netkit.
   local host_prog_candidate=""
   for host_prog_candidate in $(
      ip netns exec "${gateway_ns}" bpftool prog show 2>/dev/null \
         | awk '
            /name host_ingress_router/ {
               gsub(":", "", $1);
               print $1;
            }
         '
   )
   do
      if ! [[ "${host_prog_candidate}" =~ ^[0-9]+$ ]]
      then
         continue
      fi

      local host_candidate_map_id=""
      host_candidate_map_id="$(find_map_id_for_prog "${gateway_ns}" "${host_prog_candidate}" "local_container_subnet_map" || true)"
      if [[ -z "${host_candidate_map_id}" ]]
      then
         continue
      fi

      local host_candidate_update_err=""
      if ! host_candidate_update_err="$(ip netns exec "${gateway_ns}" bpftool map update id "${host_candidate_map_id}" key hex ${key_hex} value hex ${local_subnet_hex} 2>&1)"
      then
         echo "WARN: unable to sync host_ingress local_container_subnet_map in ${gateway_ns} prog=${host_prog_candidate} map=${host_candidate_map_id} err='${host_candidate_update_err}'"
      fi
   done

   local mac_update_err=""
   if ! mac_update_err="$(ip netns exec "${gateway_ns}" bpftool map update id "${mac_map_id}" key hex ${key_hex} value hex ${local_mac_hex} 2>&1)"
   then
      echo "WARN: unable to update mac_map in ${gateway_ns} err='${mac_update_err}'"
      return 0
   fi

   local gateway_mac_update_err=""
   if ! gateway_mac_update_err="$(ip netns exec "${gateway_ns}" bpftool map update id "${gateway_mac_map_id}" key hex ${key_hex} value hex ${gateway_mac_hex} 2>&1)"
   then
      echo "WARN: unable to update gateway_mac_map in ${gateway_ns} err='${gateway_mac_update_err}'"
      return 0
   fi

   echo "SWITCHBOARD_BALANCER_DEV_ATTACH success ns=${gateway_ns} if=bond0 mode=${attach_mode} prog_id=${prog_id} subnet=${local_subnet_hex} subnet_source=${subnet_source} local_mac=${local_mac} gateway_mac=${gateway_mac}"
   return 0
}

attach_dev_switchboard_balancer_to_namespace()
{
   local target_ns="$1"

   if [[ -z "${switchboard_balancer_ebpf}" ]]
   then
      echo "WARN: PRODIGY_DEV_SWITCHBOARD_BALANCER_EBPF not set; skipping preattached switchboard balancer attach"
      return 0
   fi

   if [[ ! -f "${switchboard_balancer_ebpf}" ]]
   then
      echo "FAIL: switchboard balancer eBPF object missing: ${switchboard_balancer_ebpf}"
      return 1
   fi

   if ip netns exec "${target_ns}" bpftool net 2>/dev/null | rg -q 'xdp[[:space:]].*balancer_ingress'
   then
      echo "SWITCHBOARD_BALANCER_PREATTACHED existing ns=${target_ns} if=bond0"
      return 0
   fi

   local native_attach_err=""
   local generic_attach_err=""
   local native_attach_rc=0
   local generic_attach_rc=0
   local attach_mode=""

   ip netns exec "${target_ns}" ip link set dev bond0 xdp off >/dev/null 2>&1 || true
   native_attach_err="$(
      ip netns exec "${target_ns}" ip link set dev bond0 xdp obj "${switchboard_balancer_ebpf}" sec xdp 2>&1 >/dev/null
   )"
   native_attach_rc=$?
   if [[ "${native_attach_rc}" -eq 0 ]]
   then
      attach_mode="xdp"
   else
      generic_attach_err="$(
         ip netns exec "${target_ns}" ip link set dev bond0 xdpgeneric obj "${switchboard_balancer_ebpf}" sec xdp 2>&1 >/dev/null
      )"
      generic_attach_rc=$?
      if [[ "${generic_attach_rc}" -eq 0 ]]
      then
         attach_mode="xdpgeneric"
      else
         echo "FAIL: unable to preattach switchboard balancer on ${target_ns}/bond0 native_rc=${native_attach_rc} native_err='${native_attach_err}' generic_rc=${generic_attach_rc} generic_err='${generic_attach_err}'"
         return 1
      fi
   fi

   echo "SWITCHBOARD_BALANCER_PREATTACHED success ns=${target_ns} if=bond0 mode=${attach_mode}"
   return 0
}

configure_dev_switchboard_balancers_on_nodes()
{
   if [[ "${allow_bpf_attach}" != "1" ]]
   then
      return 0
   fi

   local target_ns=""
   for target_ns in "${child_names[@]}"
   do
      if ! attach_dev_switchboard_balancer_to_namespace "${target_ns}"
      then
         return 1
      fi
   done

   return 0
}

ns_index()
{
   local candidate="$1"
   local idx=1
   for ns in "${child_names[@]}"
   do
      if [[ "${ns}" == "${candidate}" ]]
      then
         echo "${idx}"
         return 0
      fi
      idx=$((idx + 1))
   done

   echo "0"
   return 1
}

dump_fake_ipv4_path_diagnostics()
{
   if [[ "${enable_fake_ipv4_boundary}" != "1" ]]
   then
      return 0
   fi

   if [[ -z "${switchboard_gateway_ip}" ]]
   then
      echo "DEV_FAKE_ROUTE_DIAG skipped: switchboard_gateway_ip is empty"
      return 0
   fi

   local gateway_idx=-1
   local i=0
   for i in $(seq 0 $((${#assigned_brain_ips[@]} - 1)))
   do
      if [[ "${assigned_brain_ips[$i]}" == "${switchboard_gateway_ip}" ]]
      then
         gateway_idx="${i}"
         break
      fi
   done

   if [[ "${gateway_idx}" -lt 0 || "${gateway_idx}" -ge "${#child_names[@]}" ]]
   then
      echo "DEV_FAKE_ROUTE_DIAG skipped: unable to resolve gateway namespace for ${switchboard_gateway_ip}"
      return 0
   fi

   local gateway_ns="${child_names[$gateway_idx]}"
   local key_hex="00 00 00 00"
   local balancer_prog_id=""
   local host_ingress_prog_id=""
   local dev_stats_map_id=""
   local balancer_local_subnet_map_id=""
   local host_local_subnet_map_id=""

   echo "--- DEV_FAKE_ROUTE_DIAG begin gateway_ns=${gateway_ns} parent_ns=${parent_ns} gateway_ip=${switchboard_gateway_ip} gateway_ip6=${switchboard_gateway_ip6:-none} ---"
   echo "--- DEV_FAKE_ROUTE_DIAG parent routes v4 ---"
   ip netns exec "${parent_ns}" ip route show 2>/dev/null || true
   echo "--- DEV_FAKE_ROUTE_DIAG parent routes v6 ---"
   ip netns exec "${parent_ns}" ip -6 route show 2>/dev/null || true
   echo "--- DEV_FAKE_ROUTE_DIAG gateway routes v4 ---"
   ip netns exec "${gateway_ns}" ip route show 2>/dev/null || true
   echo "--- DEV_FAKE_ROUTE_DIAG gateway routes v6 ---"
   ip netns exec "${gateway_ns}" ip -6 route show 2>/dev/null || true

   if [[ -n "${parent_edge_if}" ]]
   then
      local parent_tc_prog_ids=""
      echo "--- DEV_FAKE_ROUTE_DIAG parent tc ${parent_edge_if} ---"
      ip netns exec "${parent_ns}" tc -s qdisc show dev "${parent_edge_if}" 2>/dev/null || true
      ip netns exec "${parent_ns}" tc -s filter show dev "${parent_edge_if}" ingress 2>/dev/null || true
      ip netns exec "${parent_ns}" tc -s filter show dev "${parent_edge_if}" egress 2>/dev/null || true
      parent_tc_prog_ids="$(
         {
            ip netns exec "${parent_ns}" tc -s filter show dev "${parent_edge_if}" ingress 2>/dev/null || true
            ip netns exec "${parent_ns}" tc -s filter show dev "${parent_edge_if}" egress 2>/dev/null || true
         } \
         | awk '
            / id / {
               for (i = 1; i <= NF; ++i) {
                  if ($i == "id" && (i + 1) <= NF) {
                     print $(i + 1);
                  }
               }
            }
         ' \
         | sort -u
      )"

      local boundary_prog_id=""
      for boundary_prog_id in ${parent_tc_prog_ids}
      do
         if ! [[ "${boundary_prog_id}" =~ ^[0-9]+$ ]]
         then
            continue
         fi

         local boundary_nat_stats_map_id=""
         boundary_nat_stats_map_id="$(find_map_id_for_prog "${parent_ns}" "${boundary_prog_id}" "nat4_stats" || true)"
         if [[ -n "${boundary_nat_stats_map_id}" ]]
         then
            echo "DEV_FAKE_ROUTE_DIAG boundary_prog_id=${boundary_prog_id} nat4_stats_map_id=${boundary_nat_stats_map_id}"
            echo "--- DEV_FAKE_ROUTE_DIAG boundary nat4_stats dump ---"
            ip netns exec "${parent_ns}" bpftool map dump id "${boundary_nat_stats_map_id}" 2>/dev/null || true
            break
         fi
      done
   fi

   balancer_prog_id="$(
      ip netns exec "${gateway_ns}" ip -d link show dev bond0 2>/dev/null \
         | awk '
            /prog\/xdp id/ {
               for (i = 1; i <= NF; ++i) {
                  if ($i == "id") {
                     print $(i + 1);
                     exit;
                  }
               }
            }
         '
   )"

   if [[ -z "${balancer_prog_id}" ]]
   then
      balancer_prog_id="$(
         ip netns exec "${gateway_ns}" bpftool net 2>/dev/null \
            | awk '
               /xdp/ && / id / {
                  for (i = 1; i <= NF; ++i) {
                     if ($i == "id") {
                        print $(i + 1);
                        exit;
                     }
                  }
               }
            '
      )"
   fi

   echo "DEV_FAKE_ROUTE_DIAG balancer_prog_id=${balancer_prog_id:-none}"
   if [[ -n "${balancer_prog_id}" ]]
   then
      dev_stats_map_id="$(find_map_id_for_prog "${gateway_ns}" "${balancer_prog_id}" "dev_fake_route_stats" || true)"
      balancer_local_subnet_map_id="$(find_map_id_for_prog "${gateway_ns}" "${balancer_prog_id}" "local_container_subnet_map" || true)"

      echo "DEV_FAKE_ROUTE_DIAG balancer_map_ids dev_stats=${dev_stats_map_id:-none} local_subnet=${balancer_local_subnet_map_id:-none}"

      if [[ -n "${dev_stats_map_id}" ]]
      then
         echo "--- DEV_FAKE_ROUTE_DIAG balancer dev_fake_route_stats dump ---"
         ip netns exec "${gateway_ns}" bpftool map dump id "${dev_stats_map_id}" 2>/dev/null || true
      fi

      if [[ -n "${balancer_local_subnet_map_id}" ]]
      then
         echo "--- DEV_FAKE_ROUTE_DIAG balancer local_container_subnet_map[0] ---"
         ip netns exec "${gateway_ns}" bpftool map lookup id "${balancer_local_subnet_map_id}" key hex ${key_hex} 2>/dev/null || true
      fi
   fi

   host_ingress_prog_id="$(
      ip netns exec "${gateway_ns}" bpftool net 2>/dev/null \
         | awk '
            /tcx\/ingress/ && /host_ingress_router/ {
               for (i = 1; i <= NF; ++i) {
                  if ($i == "prog_id" && (i + 1) <= NF) {
                     print $(i + 1);
                     exit;
                  }
               }
            }
         '
   )"

   if [[ -z "${host_ingress_prog_id}" ]]
   then
      host_ingress_prog_id="$(
         ip netns exec "${gateway_ns}" bpftool prog show 2>/dev/null \
            | awk '
               /name host_ingress_router/ {
                  gsub(":", "", $1);
                  print $1;
                  exit;
               }
            '
      )"
   fi

   echo "DEV_FAKE_ROUTE_DIAG host_ingress_prog_id=${host_ingress_prog_id:-none}"
   if [[ -n "${host_ingress_prog_id}" ]]
   then
      host_local_subnet_map_id="$(find_map_id_for_prog "${gateway_ns}" "${host_ingress_prog_id}" "local_container_subnet_map" || true)"
      local host_dev_stats_map_id=""
      host_dev_stats_map_id="$(find_map_id_for_prog "${gateway_ns}" "${host_ingress_prog_id}" "dev_host_route_stats" || true)"
      echo "DEV_FAKE_ROUTE_DIAG host_ingress_local_subnet_map_id=${host_local_subnet_map_id:-none}"
      echo "DEV_FAKE_ROUTE_DIAG host_ingress_dev_host_route_stats_map_id=${host_dev_stats_map_id:-none}"
      if [[ -n "${host_local_subnet_map_id}" ]]
      then
         echo "--- DEV_FAKE_ROUTE_DIAG host_ingress local_container_subnet_map[0] ---"
         ip netns exec "${gateway_ns}" bpftool map lookup id "${host_local_subnet_map_id}" key hex ${key_hex} 2>/dev/null || true
      fi

      if [[ -n "${host_dev_stats_map_id}" ]]
      then
         echo "--- DEV_FAKE_ROUTE_DIAG host_ingress dev_host_route_stats dump ---"
         ip netns exec "${gateway_ns}" bpftool map dump id "${host_dev_stats_map_id}" 2>/dev/null || true
      fi
   fi

   if [[ -n "${host_ingress_prog_id}" ]]
   then
      local host_counter_map_id=""
      local host_packet_map_id=""
      host_counter_map_id="$(find_map_id_for_prog "${gateway_ns}" "${host_ingress_prog_id}" "packet_counter_map" || true)"
      host_packet_map_id="$(find_map_id_for_prog "${gateway_ns}" "${host_ingress_prog_id}" "packet_map" || true)"
      if [[ -n "${host_counter_map_id}" ]]
      then
         echo "DEV_FAKE_ROUTE_DIAG host_ingress_packet_counter_map_id=${host_counter_map_id}"
         ip netns exec "${gateway_ns}" bpftool map lookup id "${host_counter_map_id}" key hex ${key_hex} 2>/dev/null || true
      fi

      if [[ -n "${host_packet_map_id}" ]]
      then
         local host_packet_tmp=""
         host_packet_tmp="$(mktemp "${tmpdir}/host_ingress_packet_map.XXXXXX")"
         if ip netns exec "${gateway_ns}" bpftool map dump id "${host_packet_map_id}" >"${host_packet_tmp}" 2>/dev/null
         then
            local ipip_count="0"
            local ip6in6_count="0"
            local private_outer_hits="0"
            ipip_count="$(rg -c '"proto":[[:space:]]*4([,}])' "${host_packet_tmp}" 2>/dev/null || echo 0)"
            ip6in6_count="$(rg -c '"proto":[[:space:]]*41([,}])' "${host_packet_tmp}" 2>/dev/null || echo 0)"
            private_outer_hits="$(rg -c '"dest":[[:space:]]*\\[253,248,217,76,124,51,226,110,202,75' "${host_packet_tmp}" 2>/dev/null || echo 0)"
            echo "DEV_FAKE_ROUTE_DIAG host_ingress_packet_map_id=${host_packet_map_id} ipip_frames=${ipip_count} ip6in6_frames=${ip6in6_count} private_outer_dest_hits=${private_outer_hits}"
         fi
      fi
   fi

   echo "--- DEV_FAKE_ROUTE_DIAG container router (attached netkit programs across brains) ---"
   local container_ns=""
   for container_ns in "${child_names[@]}"
   do
      while IFS= read -r netkit_binding
      do
         if [[ -z "${netkit_binding}" ]]
         then
            continue
         fi

         local dev_name=""
         local attach_type=""
         local container_prog_name=""
         local attached_prog_id=""
         read -r dev_name attach_type container_prog_name attached_prog_id <<< "${netkit_binding}"

         if [[ -z "${attached_prog_id}" ]] || ! [[ "${attached_prog_id}" =~ ^[0-9]+$ ]]
         then
            continue
         fi

         case "${container_prog_name}" in
            container_egress_router|container_ingress_router)
               ;;
            *)
               continue
               ;;
         esac

         local policy_map_id=""
         local stats_map_id=""
         policy_map_id="$(find_map_id_for_prog "${container_ns}" "${attached_prog_id}" "container_network_policy_map" || true)"
         stats_map_id="$(find_map_id_for_prog "${container_ns}" "${attached_prog_id}" "container_router_stats_map" || true)"

         echo "DEV_FAKE_ROUTE_DIAG ns=${container_ns} dev=${dev_name} attach=${attach_type} container_prog id=${attached_prog_id} name=${container_prog_name:-unknown} policy_map=${policy_map_id:-none} stats_map=${stats_map_id:-none}"

         if [[ -n "${policy_map_id}" ]]
         then
            ip netns exec "${container_ns}" bpftool map lookup id "${policy_map_id}" key hex ${key_hex} 2>/dev/null || true
         fi

         if [[ -n "${stats_map_id}" ]]
         then
            ip netns exec "${container_ns}" bpftool map dump id "${stats_map_id}" 2>/dev/null || true
         fi
      done < <(
         ip netns exec "${container_ns}" bpftool net 2>/dev/null \
            | awk '
               /netkit\/(primary|peer)/ {
                  dev = $1;
                  sub(/\(.*/, "", dev);
                  prog_name = $3;
                  prog_id = "";

                  for (i = 1; i <= NF; ++i) {
                     if ($i == "prog_id" && (i + 1) <= NF) {
                        prog_id = $(i + 1);
                        break;
                     }
                  }

                  if (prog_id != "") {
                     print dev, $2, prog_name, prog_id;
                  }
               }
            '
      )
   done

   echo "--- DEV_FAKE_ROUTE_DIAG end ---"
}

master_listener_in_ns()
{
   local ns="$1"

   if master_unix_listener_in_ns "${ns}"
   then
      return 0
   fi

   ip netns exec "${ns}" ss -ltn 2>/dev/null | rg -q '240\.1\.0\.1:314'
}

master_unix_listener_in_ns()
{
   local ns="$1"
   [[ -n "${mothership_socket_path}" ]] || return 1
   ip netns exec "${ns}" ss -lxn 2>/dev/null | rg -F -q -- "${mothership_socket_path}"
}

dump_master_listener_state()
{
   local ns="$1"
   echo "--- ${ns} tcp listeners ---"
   ip netns exec "${ns}" ss -ltn 2>/dev/null || true
   echo "--- ${ns} unix listeners ---"
   ip netns exec "${ns}" ss -lxn 2>/dev/null || true
}

master_listener_indices_once()
{
   local csv=""
   for idx in $(seq 1 "${brains}")
   do
      local ns="${child_names[$((idx - 1))]}"
      if master_listener_in_ns "${ns}"
      then
         if [[ -n "${csv}" ]]
         then
            csv="${csv},${idx}"
         else
            csv="${idx}"
         fi
      fi
   done

   if [[ -z "${csv}" ]]
   then
      return 1
   fi

   echo "${csv}"
   return 0
}

discover_master_ns_once()
{
   for ns in "${child_names[@]}"
   do
      if master_listener_in_ns "${ns}"
      then
         echo "${ns}"
         return 0
      fi
   done

   return 1
}

wait_for_master_ns()
{
   local attempts="$1"

   for attempt in $(seq 1 "${attempts}")
   do
      local ns
      if ns="$(discover_master_ns_once)"
      then
         echo "${ns}"
         return 0
      fi

      sleep 0.2
   done

   return 1
}

count_established_peer_links_in_ns()
{
   local ns="$1"
   ip netns exec "${ns}" ss -tan 2>/dev/null | awk '$1=="ESTAB" && ($4 ~ /:313$/ || $5 ~ /:313$/) {c++} END {print c+0}'
}

peer_transport_family_pattern()
{
      case "${brain_bootstrap_family}" in
         private6)
            printf '%s' '[fd00:10::'
            ;;
         public6)
            if [[ "${enable_fake_ipv4_boundary}" == "1" ]]
            then
               printf '%s' '[2602:fac0:0:12ab:34cd::'
            else
               printf '%s' '[2001:db8:100::'
            fi
            ;;
         multihome6)
            printf '%s' '[fd00:10::'
            ;;
      *)
         return 1
         ;;
   esac
}

peer_links_match_bootstrap_family_in_ns()
{
   local ns="$1"
   local pattern=""
   if ! pattern="$(peer_transport_family_pattern)"
   then
      return 0
   fi

   ip netns exec "${ns}" ss -tan 2>/dev/null \
      | awk '$1=="ESTAB" && ($4 ~ /:313$/ || $5 ~ /:313$/)' \
      | rg -F -q -- "${pattern}"
}

wait_for_peer_mesh_bootstrap_family()
{
   local attempts="$1"
   local ns=""

   for attempt in $(seq 1 "${attempts}")
   do
      local all_match=1
      for ns in "${child_names[@]}"
      do
         if ! peer_links_match_bootstrap_family_in_ns "${ns}"
         then
            all_match=0
            break
         fi
      done

      if [[ "${all_match}" -eq 1 ]]
      then
         return 0
      fi

      sleep 0.2
   done

   return 1
}

count_established_neuron_links_in_ns()
{
   local ns="$1"
   ip netns exec "${ns}" ss -tan 2>/dev/null | awk '$1=="ESTAB" && ($4 ~ /:312$/ || $5 ~ /:312$/) {c++} END {print c+0}'
}

brain_link_is_up_in_ns()
{
   local ns="$1"
   local state
   state="$(ip netns exec "${ns}" cat /sys/class/net/bond0/operstate 2>/dev/null || echo down)"
   [[ "${state}" == "up" || "${state}" == "unknown" ]]
}

quorum_peer_requirement()
{
   if [[ "${brains}" == "3" ]]
   then
      echo "1"
   else
      echo "0"
   fi
}

master_has_quorum_in_ns()
{
   local ns="$1"
   if ! brain_link_is_up_in_ns "${ns}"
   then
      return 1
   fi

   local required
   required="$(quorum_peer_requirement)"
   local established
   established="$(count_established_peer_links_in_ns "${ns}")"
   [[ "${established}" -ge "${required}" ]]
}

master_control_plane_requirement()
{
   if [[ "${brains}" == "3" ]]
   then
      echo "1"
   else
      echo "0"
   fi
}

master_has_control_plane_in_ns()
{
   local ns="$1"

   if master_unix_listener_in_ns "${ns}"
   then
      # Unix-socket-only control mode does not rely on a separate :312 transport.
      return 0
   fi

   local required
   required="$(master_control_plane_requirement)"
   local established
   established="$(count_established_neuron_links_in_ns "${ns}")"
   [[ "${established}" -ge "${required}" ]]
}

quorum_master_indices_once()
{
   local csv=""
   for idx in $(seq 1 "${brains}")
   do
      local ns="${child_names[$((idx - 1))]}"
      if master_listener_in_ns "${ns}" && master_has_quorum_in_ns "${ns}" && master_has_control_plane_in_ns "${ns}"
      then
         if [[ -n "${csv}" ]]
         then
            csv="${csv},${idx}"
         else
            csv="${idx}"
         fi
      fi
   done

   if [[ -z "${csv}" ]]
   then
      return 1
   fi

   echo "${csv}"
   return 0
}

wait_for_quorum_master_indices()
{
   local attempts="$1"

   for attempt in $(seq 1 "${attempts}")
   do
      local indices
      if indices="$(quorum_master_indices_once)"
      then
         echo "${indices}"
         return 0
      fi

      sleep 0.2
   done

   return 1
}

wait_for_single_quorum_master_indices_stable()
{
   local attempts="$1"
   local min_streak="${2:-10}"
   local streak=0
   local stable_csv=""

   for attempt in $(seq 1 "${attempts}")
   do
      local indices=""
      if indices="$(quorum_master_indices_once)"
      then
         local count
         count="$(csv_count_indices "${indices}")"
         if [[ "${count}" -eq 1 ]]
         then
            if [[ "${indices}" == "${stable_csv}" ]]
            then
               streak=$((streak + 1))
            else
               stable_csv="${indices}"
               streak=1
            fi

            if [[ "${streak}" -ge "${min_streak}" ]]
            then
               echo "${stable_csv}"
               return 0
            fi
         else
            streak=0
            stable_csv=""
         fi
      else
         streak=0
         stable_csv=""
      fi

      sleep 0.2
   done

   return 1
}

wait_for_single_master_listener_indices_stable()
{
   local attempts="$1"
   local min_streak="${2:-10}"
   local streak=0
   local stable_csv=""

   for attempt in $(seq 1 "${attempts}")
   do
      local indices=""
      if indices="$(master_listener_indices_once)"
      then
         local count
         count="$(csv_count_indices "${indices}")"
         if [[ "${count}" -eq 1 ]]
         then
            if [[ "${indices}" == "${stable_csv}" ]]
            then
               streak=$((streak + 1))
            else
               stable_csv="${indices}"
               streak=1
            fi

            if [[ "${streak}" -ge "${min_streak}" ]]
            then
               echo "${stable_csv}"
               return 0
            fi
         else
            streak=0
            stable_csv=""
         fi
      else
         streak=0
         stable_csv=""
      fi

      sleep 0.2
   done

   return 1
}

wait_for_no_quorum_master_stable()
{
   local attempts="$1"
   local min_streak="${2:-10}"
   local streak=0

   for attempt in $(seq 1 "${attempts}")
   do
      if quorum_master_indices_once >/dev/null
      then
         streak=0
      else
         streak=$((streak + 1))
         if [[ "${streak}" -ge "${min_streak}" ]]
         then
            return 0
         fi
      fi

      sleep 0.2
   done

   return 1
}

csv_has_index()
{
   local csv="$1"
   local idx="$2"
   [[ ",${csv}," == *",${idx},"* ]]
}

csv_has_other_than()
{
   local csv="$1"
   local baseline_idx="$2"
   IFS=',' read -r -a members <<< "${csv}"
   for member in "${members[@]}"
   do
      if [[ -z "${member}" ]]
      then
         continue
      fi

      if [[ "${member}" != "${baseline_idx}" ]]
      then
         return 0
      fi
   done

   return 1
}

csv_count_indices()
{
   local csv="$1"
   local count=0
   IFS=',' read -r -a members <<< "${csv}"
   for member in "${members[@]}"
   do
      if [[ -n "${member}" ]]
      then
         count=$((count + 1))
      fi
   done

   echo "${count}"
}

first_index_from_csv()
{
   local csv="$1"
   IFS=',' read -r -a members <<< "${csv}"
   for member in "${members[@]}"
   do
      if [[ -n "${member}" ]]
      then
         echo "${member}"
         return 0
      fi
   done

   echo "0"
   return 1
}

filter_quorum_indices_by_cluster_report()
{
   local csv="$1"

   if [[ -z "${csv}" || -z "${mothership_bin}" ]]
   then
      echo "${csv}"
      return 0
   fi

   local report_log="${tmpdir}/mothership.clusterreport.filter.log"
   local reported_csv=""
   local master_ip=""
   local filtered=""
   local idx=0

   if ! run_cluster_report_from_any_ns "${report_log}" 3
   then
      echo "${csv}"
      return 0
   fi

   while IFS= read -r master_ip
   do
      if [[ -z "${master_ip}" ]]
      then
         continue
      fi

      for idx in $(seq 1 "${brains}")
      do
         if [[ "${assigned_brain_ips[$((idx - 1))]}" != "${master_ip}" ]]
         then
            continue
         fi

         if [[ -n "${reported_csv}" ]]
         then
            reported_csv="${reported_csv},${idx}"
         else
            reported_csv="${idx}"
         fi
         break
      done
   done < <(
      awk '
         /^[[:space:]]*Machine:/ {
            current_ip = "";
            if (match($0, /10\.0\.0\.[0-9]+/))
            {
               current_ip = substr($0, RSTART, RLENGTH);
            }
            next;
         }
         current_ip != "" && /^[[:space:]]*lifecycle / {
            if ($0 ~ /currentMaster=1/)
            {
               print current_ip;
            }
            current_ip = "";
         }
      ' "${report_log}"
   )

   if [[ -n "${reported_csv}" ]]
   then
      echo "${reported_csv}"
   else
      echo "${csv}"
   fi

   return 0
}

all_peers_connected_once()
{
   local excluded_csv="${1:-}"
   local quorum_mode="${2:-0}"
   local candidates=0
   local connected=0

   for idx in $(seq 1 "${brains}")
   do
      if [[ -n "${excluded_csv}" ]] && csv_has_index "${excluded_csv}" "${idx}"
      then
         continue
      fi

      candidates=$((candidates + 1))

      local ns="${child_names[$((idx - 1))]}"
      established="$(ip netns exec "${ns}" ss -tan 2>/dev/null | awk '$1=="ESTAB" && ($4 ~ /:313$/ || $5 ~ /:313$/) {c++} END {print c+0}')"
      if [[ "${established}" -gt 0 ]]
      then
         connected=$((connected + 1))
      elif [[ "${quorum_mode}" != "1" ]]
      then
         return 1
      fi
   done

   if [[ "${quorum_mode}" == "1" ]]
   then
      if [[ "${candidates}" -le 0 ]]
      then
         return 1
      fi

      local required=$((candidates / 2 + 1))
      if [[ "${connected}" -lt "${required}" ]]
      then
         return 1
      fi
   fi

   return 0
}

all_peers_connected_with_full_mesh_once()
{
   local excluded_csv="${1:-}"
   local candidates=0

   for idx in $(seq 1 "${brains}")
   do
      if [[ -n "${excluded_csv}" ]] && csv_has_index "${excluded_csv}" "${idx}"
      then
         continue
      fi

      candidates=$((candidates + 1))
   done

   if [[ "${candidates}" -le 1 ]]
   then
      return 0
   fi

   local required_links=$((candidates - 1))
   for idx in $(seq 1 "${brains}")
   do
      if [[ -n "${excluded_csv}" ]] && csv_has_index "${excluded_csv}" "${idx}"
      then
         continue
      fi

      local ns="${child_names[$((idx - 1))]}"
      local established=0
      established="$(count_established_peer_links_in_ns "${ns}")"
      if [[ "${established}" -lt "${required_links}" ]]
      then
         return 1
      fi
   done

   return 0
}

wait_for_peer_mesh()
{
   local attempts="$1"
   local excluded_csv="${2:-}"
   local quorum_mode="${3:-0}"

   for attempt in $(seq 1 "${attempts}")
   do
      if all_peers_connected_once "${excluded_csv}" "${quorum_mode}"
      then
         return 0
      fi

      sleep 0.2
   done

   return 1
}

wait_for_full_peer_mesh()
{
   local attempts="$1"
   local excluded_csv="${2:-}"

   for attempt in $(seq 1 "${attempts}")
   do
      if all_peers_connected_with_full_mesh_once "${excluded_csv}"
      then
         return 0
      fi

      sleep 0.2
   done

   return 1
}

run_cluster_report_from_any_ns()
{
   local output_log="$1"
   local timeout_s="${2:-3}"

   if [[ -z "${mothership_bin}" ]]
   then
      return 1
   fi

   # Prefer the currently selected configure namespace, then fall back to every
   # known brain namespace so report checks survive leader movement.
   local candidates=()
   if [[ -n "${configure_ns:-}" ]]
   then
      candidates+=("${configure_ns}")
   fi

   local ns=""
   for ns in "${child_names[@]}"
   do
      if [[ -n "${configure_ns:-}" && "${ns}" == "${configure_ns}" ]]
      then
         continue
      fi
      candidates+=("${ns}")
   done

   local candidate_ns=""
   for candidate_ns in "${candidates[@]}"
   do
      if timeout --preserve-status -k 2s "${timeout_s}"s \
         ip netns exec "${candidate_ns}" \
         env PRODIGY_STATE_DB=/containers/var/lib/prodigy/state PRODIGY_MOTHERSHIP_SOCKET="${mothership_socket_path}" "${mothership_bin}" clusterReport local \
         >"${output_log}" 2>&1
      then
         configure_ns="${candidate_ns}"
         for idx in "${!child_names[@]}"
         do
            if [[ "${child_names[$idx]}" == "${candidate_ns}" ]]
            then
               configure_index=$((idx + 1))
               configure_ip="${assigned_brain_ips[$idx]}"
               break
            fi
         done

         return 0
      fi
   done

   return 1
}

extract_application_id_from_plan_json()
{
   local plan_json="$1"
   local app_id_line=""
   local app_id=""

   if [[ ! -f "${plan_json}" ]]
   then
      return 1
   fi

   app_id_line="$(rg -m 1 -o '"applicationID"[[:space:]]*:[[:space:]]*[0-9]+' "${plan_json}" 2>/dev/null || true)"
   if [[ -z "${app_id_line}" ]]
   then
      return 1
   fi

   app_id="$(echo "${app_id_line}" | rg -m 1 -o '[0-9]+' || true)"
   if [[ -z "${app_id}" ]]
   then
      return 1
   fi

   echo "${app_id}"
   return 0
}

reserve_application_id_for_plan()
{
   local ns="$1"
   local plan_json="$2"
   local log_suffix="$3"
   local app_name=""
   local reserve_json=""
   local reserve_log=""
   local reserve_rc=0
   local assigned_app_id=""
   local resolved_plan_json=""
   local reserve_attempts="${PRODIGY_DEV_RESERVE_ATTEMPTS:-8}"
   local reserve_success=0
   local attempt=0
   local reserve_ns=""
   local -a reserve_namespaces=()

   app_name="$(extract_application_name_for_reservation_from_plan_json "${plan_json}" || true)"
   if [[ -z "${app_name}" ]]
   then
      app_name="HarnessApp.${log_suffix}"
   fi

   reserve_json="{\"applicationName\":\"${app_name}\"}"
   reserve_log="${tmpdir}/mothership.reserve.${log_suffix}.log"

   if ! [[ "${reserve_attempts}" =~ ^[0-9]+$ ]] || [[ "${reserve_attempts}" -le 0 ]]
   then
      reserve_attempts=1
   fi

   reserve_namespaces=("${ns}")
   for reserve_ns in "${child_names[@]}"
   do
      if [[ -n "${reserve_ns}" && "${reserve_ns}" != "${ns}" ]]
      then
         reserve_namespaces+=("${reserve_ns}")
      fi
   done

   for attempt in $(seq 1 "${reserve_attempts}")
   do
      for reserve_ns in "${reserve_namespaces[@]}"
      do
         reserve_rc=0
         timeout --preserve-status -k 2s 6s \
            ip netns exec "${reserve_ns}" \
            env PRODIGY_STATE_DB=/containers/var/lib/prodigy/state PRODIGY_MOTHERSHIP_SOCKET="${mothership_socket_path}" "${mothership_bin}" reserveApplicationID local "${reserve_json}" \
            >"${reserve_log}" 2>&1 || reserve_rc=$?

         if rg -q "reserveApplicationID success=1" "${reserve_log}"
         then
            reserve_success=1
            break 2
         fi
      done

      if [[ "${attempt}" -lt "${reserve_attempts}" ]]
      then
         sleep 0.25
      fi
   done

   if [[ "${reserve_success}" -ne 1 ]] || ! rg -q "reserveApplicationID success=1" "${reserve_log}"
   then
      if [[ "${reserve_rc}" -ne 0 ]]
      then
         echo "FAIL: mothership reserveApplicationID command failed for plan=${plan_json}" >&2
      else
         echo "FAIL: reserveApplicationID did not succeed for plan=${plan_json}" >&2
      fi

      sed -n '1,160p' "${reserve_log}" >&2 || true
      return 1
   fi

   assigned_app_id="$(rg -o 'appID=[0-9]+' "${reserve_log}" | head -n 1 | sed 's/[^0-9]//g' || true)"
   if [[ -z "${assigned_app_id}" ]] || ! [[ "${assigned_app_id}" =~ ^[0-9]+$ ]] || [[ "${assigned_app_id}" -le 0 || "${assigned_app_id}" -gt 65535 ]]
   then
      echo "FAIL: reserveApplicationID returned invalid appID for plan=${plan_json}" >&2
      sed -n '1,160p' "${reserve_log}" >&2 || true
      return 1
   fi

   resolved_plan_json="${tmpdir}/deploy.plan.${log_suffix}.resolved.json"
   cp -f "${plan_json}" "${resolved_plan_json}"

   perl -0pi -e 's/("config"\s*:\s*\{.*?"applicationID"\s*:\s*)(\d+|"[^"]+")/${1}'"${assigned_app_id}"'/s' "${resolved_plan_json}"
   perl -0pi -e 's/("tls"\s*:\s*\{.*?"applicationID"\s*:\s*)(\d+|"[^"]+")/${1}'"${assigned_app_id}"'/s' "${resolved_plan_json}"
   perl -0pi -e 's/("apiCredentials"\s*:\s*\{.*?"applicationID"\s*:\s*)(\d+|"[^"]+")/${1}'"${assigned_app_id}"'/s' "${resolved_plan_json}"

   echo "${resolved_plan_json}"
   return 0
}

extract_service_kind_for_plan_json()
{
   local plan_json="$1"
   local stateful_line=""
   local stateful_value=""
   local config_type_line=""
   local config_type_value=""

   if [[ ! -f "${plan_json}" ]]
   then
      return 1
   fi

   stateful_line="$(rg -m 1 -o '"isStateful"[[:space:]]*:[[:space:]]*(true|false)' "${plan_json}" 2>/dev/null || true)"
   if [[ -n "${stateful_line}" ]]
   then
      stateful_value="$(echo "${stateful_line}" | sed -E 's/.*:[[:space:]]*(true|false).*/\1/' || true)"
      if [[ "${stateful_value}" == "true" ]]
      then
         echo "stateful"
         return 0
      fi
   fi

   config_type_line="$(rg -m 1 -o '"type"[[:space:]]*:[[:space:]]*"ApplicationType::[^"]+"' "${plan_json}" 2>/dev/null || true)"
   if [[ -n "${config_type_line}" ]]
   then
      config_type_value="$(echo "${config_type_line}" | sed -E 's/.*"type"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' || true)"
      if [[ "${config_type_value}" == "ApplicationType::stateful" ]]
      then
         echo "stateful"
         return 0
      fi
   fi

   echo "stateless"
   return 0
}

extract_symbolic_service_refs_from_plan_json()
{
   local plan_json="$1"

   if [[ ! -f "${plan_json}" ]]
   then
      return 1
   fi

   rg -o '"service"[[:space:]]*:[[:space:]]*"\$\{(service|svc):[^"]+\}"' "${plan_json}" 2>/dev/null \
      | sed -E 's/.*"\$\{(service|svc):([^}]+)\}".*/\2/' \
      | sort -u
}

reserve_service_ids_for_plan()
{
   local ns="$1"
   local plan_json="$2"
   local resolved_plan_json="$3"
   local log_suffix="$4"
   local reserve_attempts="${PRODIGY_DEV_RESERVE_ATTEMPTS:-8}"
   local reserve_service_kind=""
   local reserve_ns=""
   local reserve_success=0
   local reserve_rc=0
   local attempt=0
   local ref_body=""
   local application_name=""
   local service_spec=""
   local service_name=""
   local reserve_json=""
   local reserve_log=""
   local source_plan_app_name=""
   local resolved_plan_app_id=""
   local -a reserve_namespaces=()
   local -a service_refs=()

   if [[ ! -f "${plan_json}" ]]
   then
      echo "FAIL: reserveServiceID plan path does not exist: ${plan_json}" >&2
      return 1
   fi

   mapfile -t service_refs < <(extract_symbolic_service_refs_from_plan_json "${plan_json}" || true)
   if [[ "${#service_refs[@]}" -eq 0 ]]
   then
      return 0
   fi

   reserve_service_kind="$(extract_service_kind_for_plan_json "${plan_json}" || true)"
   if [[ "${reserve_service_kind}" != "stateful" ]]
   then
      reserve_service_kind="stateless"
   fi

   source_plan_app_name="$(
      rg -m 1 -o '"applicationID"[[:space:]]*:[[:space:]]*"\$\{(application|app):[^"]+\}"' "${plan_json}" 2>/dev/null \
         | sed -E 's/.*"\$\{(application|app):([^}]+)\}".*/\2/' \
         | head -n 1 \
         || true
   )"
   resolved_plan_app_id="$(extract_application_id_from_plan_json "${resolved_plan_json}" || true)"

   if ! [[ "${reserve_attempts}" =~ ^[0-9]+$ ]] || [[ "${reserve_attempts}" -le 0 ]]
   then
      reserve_attempts=1
   fi

   reserve_namespaces=("${ns}")
   for reserve_ns in "${child_names[@]}"
   do
      if [[ -n "${reserve_ns}" && "${reserve_ns}" != "${ns}" ]]
      then
         reserve_namespaces+=("${reserve_ns}")
      fi
   done

   for ref_body in "${service_refs[@]}"
   do
      if [[ -z "${ref_body}" || "${ref_body}" != */* ]]
      then
         echo "FAIL: invalid symbolic service reference in plan=${plan_json}: ${ref_body}" >&2
         return 1
      fi

      application_name="${ref_body%%/*}"
      service_spec="${ref_body#*/}"
      service_name="${service_spec}"
      if [[ "${service_spec}" =~ ^(.+)\.group[0-9]+$ ]]
      then
         service_name="${BASH_REMATCH[1]}"
      fi

      if [[ -n "${resolved_plan_app_id}" && -n "${source_plan_app_name}" && "${application_name}" == "${source_plan_app_name}" ]]
      then
         reserve_json="{\"applicationID\":${resolved_plan_app_id},\"applicationName\":\"${application_name}\",\"serviceName\":\"${service_name}\",\"kind\":\"${reserve_service_kind}\"}"
      else
         reserve_json="{\"applicationName\":\"${application_name}\",\"serviceName\":\"${service_name}\",\"kind\":\"${reserve_service_kind}\"}"
      fi
      reserve_log="${tmpdir}/mothership.reserve.service.${log_suffix}.$(echo "${application_name}.${service_name}" | tr -c 'A-Za-z0-9._-' '_').log"
      reserve_success=0
      reserve_rc=0

      for attempt in $(seq 1 "${reserve_attempts}")
      do
         for reserve_ns in "${reserve_namespaces[@]}"
         do
            reserve_rc=0
            timeout --preserve-status -k 2s 6s \
               ip netns exec "${reserve_ns}" \
               "${mothership_bin}" reserveServiceID dev "${reserve_json}" \
               >"${reserve_log}" 2>&1 || reserve_rc=$?

            if rg -q "reserveServiceID success=1" "${reserve_log}"
            then
               reserve_success=1
               break 2
            fi
         done

         if [[ "${attempt}" -lt "${reserve_attempts}" ]]
         then
            sleep 0.25
         fi
      done

      if [[ "${reserve_success}" -ne 1 ]] || ! rg -q "reserveServiceID success=1" "${reserve_log}"
      then
         if [[ "${reserve_rc}" -ne 0 ]]
         then
            echo "FAIL: mothership reserveServiceID command failed for plan=${plan_json} service=${application_name}/${service_name}" >&2
         else
            echo "FAIL: reserveServiceID did not succeed for plan=${plan_json} service=${application_name}/${service_name}" >&2
         fi

         echo "reserveServiceID sourcePlanApp=${source_plan_app_name} resolvedPlanAppID=${resolved_plan_app_id} request=${reserve_json}" >&2
         sed -n '1,160p' "${reserve_log}" >&2 || true
         return 1
      fi

      echo "MOTHERSHIP_SERVICE_RESERVE success plan=${plan_json} service=${application_name}/${service_name} kind=${reserve_service_kind}"
   done

   return 0
}

extract_application_name_for_reservation_from_plan_json()
{
   local plan_json="$1"
   local plan_app_id=""
   local symbolic_app_line=""
   local symbolic_app_name=""
   local binary_line=""
   local binary_path=""
   local binary_name=""
   local safe_name=""

   if [[ ! -f "${plan_json}" ]]
   then
      return 1
   fi

   symbolic_app_line="$(rg -m 1 -o '"applicationID"[[:space:]]*:[[:space:]]*"\$\{(application|app):[^"]+\}"' "${plan_json}" 2>/dev/null || true)"
   if [[ -n "${symbolic_app_line}" ]]
   then
      symbolic_app_name="$(echo "${symbolic_app_line}" | sed -E 's/.*"\$\{(application|app):([^}]+)\}".*/\2/' || true)"
      if [[ -n "${symbolic_app_name}" ]]
      then
         echo "${symbolic_app_name}"
         return 0
      fi
   fi

   plan_app_id="$(extract_application_id_from_plan_json "${plan_json}" || true)"
   case "${plan_app_id}" in
      2)
         echo "Pulse"
         return 0
         ;;
      3)
         echo "Hot"
         return 0
         ;;
      4)
         echo "Cold"
         return 0
         ;;
      5)
         echo "Radar"
         return 0
         ;;
      6)
         echo "Nametag"
         return 0
         ;;
      7)
         echo "Telnyx"
         return 0
         ;;
      8)
         echo "AppleNotifs"
         return 0
         ;;
   esac

   binary_name="$(basename "${plan_json}")"
   binary_name="${binary_name%%.*}"

   safe_name="$(echo "${binary_name}" | tr '/:@ ' '-' | tr -cd 'A-Za-z0-9._-')"
   if [[ -z "${safe_name}" ]]
   then
      safe_name="app"
   fi

   echo "HarnessApp.${safe_name}"
   return 0
}

probe_pingpong_in_parent_ns()
{
   local ip="$1"
   local port="$2"
   local payload="$3"
   local expected="$4"

   ip netns exec "${parent_ns}" \
      env PRODIGY_PING_IP="${ip}" PRODIGY_PING_PORT="${port}" PRODIGY_PING_PAYLOAD="${payload}" PRODIGY_PING_EXPECT="${expected}" \
      timeout --preserve-status -k 1s 3s bash -lc '
         exec 3<>"/dev/tcp/${PRODIGY_PING_IP}/${PRODIGY_PING_PORT}" || exit 1
         printf "%s\n" "${PRODIGY_PING_PAYLOAD}" >&3

         if ! IFS= read -r -t 2 response <&3
         then
            exit 2
         fi

         [[ "${response}" == "${PRODIGY_PING_EXPECT}" ]]
      ' >/dev/null 2>&1
}

emit_pingpong_traffic_in_parent_ns()
{
   local ip="$1"
   local port="$2"
   local payload="$3"
   local timeout_s="${4:-0.35}"

   # Load generation does not require a response readback. Keep it short so
   # report windows do not stall on transient connection failures.
   ip netns exec "${parent_ns}" \
      env PRODIGY_PING_IP="${ip}" PRODIGY_PING_PORT="${port}" PRODIGY_PING_PAYLOAD="${payload}" \
      timeout --preserve-status -k 1s "${timeout_s}"s bash -lc '
         exec 3<>"/dev/tcp/${PRODIGY_PING_IP}/${PRODIGY_PING_PORT}" || exit 1
         printf "%s\n" "${PRODIGY_PING_PAYLOAD}" >&3
      ' >/dev/null 2>&1
}

probe_pingpong_response_in_parent_ns()
{
   local ip="$1"
   local port="$2"
   local payload="$3"

   ip netns exec "${parent_ns}" \
      env PRODIGY_PING_IP="${ip}" PRODIGY_PING_PORT="${port}" PRODIGY_PING_PAYLOAD="${payload}" \
      timeout --preserve-status -k 1s 3s bash -lc '
         exec 3<>"/dev/tcp/${PRODIGY_PING_IP}/${PRODIGY_PING_PORT}" || exit 1
         printf "%s\n" "${PRODIGY_PING_PAYLOAD}" >&3

         if ! IFS= read -r -t 2 response <&3
         then
            exit 2
         fi

         printf "%s" "${response}"
      ' 2>/dev/null
}

deploy_mesh_probe_success_ips=""
deploy_mesh_probe_debug=""

extract_mesh_stat_value()
{
   local stats_line="$1"
   local key="$2"
   local token=""

   for token in ${stats_line}
   do
      if [[ "${token}" == "${key}="* ]]
      then
         echo "${token#*=}"
         return 0
      fi
   done

   return 1
}

validate_mesh_stats_line()
{
   local stats_line="$1"
   local expected_mode="$2"
   local expected_brains="$3"
   local mode=""
   local ready=""
   local brains=""
   local active_subs=""
   local active_ads=""
   local sub_activates=""
   local sub_deactivates=""
   local ad_activates=""
   local ad_deactivates=""
   local sub_probe_success=""
   local sub_probe_fail=""
   local sub_probe_stage=""
   local sub_probe_errno=""
   local min_required_subs=1
   local max_allowed_subs="${expected_brains}"

   mode="$(extract_mesh_stat_value "${stats_line}" "mode" || true)"
   ready="$(extract_mesh_stat_value "${stats_line}" "ready" || true)"
   brains="$(extract_mesh_stat_value "${stats_line}" "brains" || true)"
   active_subs="$(extract_mesh_stat_value "${stats_line}" "activeSubs" || true)"
   active_ads="$(extract_mesh_stat_value "${stats_line}" "activeAds" || true)"
   sub_activates="$(extract_mesh_stat_value "${stats_line}" "subActivates" || true)"
   sub_deactivates="$(extract_mesh_stat_value "${stats_line}" "subDeactivates" || true)"
   ad_activates="$(extract_mesh_stat_value "${stats_line}" "adActivates" || true)"
   ad_deactivates="$(extract_mesh_stat_value "${stats_line}" "adDeactivates" || true)"
   sub_probe_success="$(extract_mesh_stat_value "${stats_line}" "subProbeSuccess" || true)"
   sub_probe_fail="$(extract_mesh_stat_value "${stats_line}" "subProbeFail" || true)"
   sub_probe_stage="$(extract_mesh_stat_value "${stats_line}" "subProbeStage" || true)"
   sub_probe_errno="$(extract_mesh_stat_value "${stats_line}" "subProbeErrno" || true)"

   if [[ "${mode}" != "${expected_mode}" ]]
   then
      echo "mode mismatch expected=${expected_mode} got=${mode:-missing}"
      return 1
   fi

   if [[ "${ready}" != "1" ]]
   then
      echo "ready must be 1 (got=${ready:-missing})"
      return 1
   fi

   if [[ "${brains}" != "${expected_brains}" ]]
   then
      echo "brains mismatch expected=${expected_brains} got=${brains:-missing}"
      return 1
   fi

   if ! [[ "${active_subs}" =~ ^[0-9]+$ && "${active_ads}" =~ ^[0-9]+$ && "${sub_activates}" =~ ^[0-9]+$ && "${sub_deactivates}" =~ ^[0-9]+$ && "${ad_activates}" =~ ^[0-9]+$ && "${ad_deactivates}" =~ ^[0-9]+$ && "${sub_probe_success}" =~ ^[0-9]+$ && "${sub_probe_fail}" =~ ^[0-9]+$ && "${sub_probe_stage}" =~ ^[0-9]+$ && "${sub_probe_errno}" =~ ^-?[0-9]+$ ]]
   then
      echo "missing or non-numeric mesh stats fields"
      return 1
   fi

   if [[ "${expected_mode}" == "all" ]]
   then
      min_required_subs=$((expected_brains - 1))
      if [[ "${min_required_subs}" -lt 1 ]]
      then
         min_required_subs=1
      fi

      # All-mode can legitimately observe extra subscriptions when background
      # control-plane workloads are also advertising the same mesh service.
      # Keep a bounded ceiling so we still catch runaway bookkeeping growth.
      max_allowed_subs=$((expected_brains + 2))
   fi

   if [[ "${expected_mode}" == "radar" ]]
   then
      min_required_subs=1
      max_allowed_subs=$((expected_brains + 2))
   fi

   if [[ "${active_subs}" -lt "${min_required_subs}" || "${active_subs}" -gt "${max_allowed_subs}" ]]
   then
      echo "activeSubs out of range got=${active_subs} expected=${min_required_subs}..${max_allowed_subs}"
      return 1
   fi

   if [[ "${sub_probe_success}" -lt "${min_required_subs}" || "${sub_probe_success}" -gt "${max_allowed_subs}" ]]
   then
      echo "subProbeSuccess out of range got=${sub_probe_success} expected=${min_required_subs}..${max_allowed_subs}"
      return 1
   fi

   if [[ "${sub_probe_fail}" -ne 0 ]]
   then
      echo "subProbeFail must be 0 (got=${sub_probe_fail})"
      return 1
   fi

   if [[ "${expected_mode}" == "radar" && "${sub_probe_stage}" -ne 0 ]]
   then
      echo "radar subProbeStage must be 0 when ready (got=${sub_probe_stage})"
      return 1
   fi

   if [[ "${expected_mode}" == "radar" && "${sub_probe_errno}" -ne 0 ]]
   then
      echo "radar subProbeErrno must be 0 when ready (got=${sub_probe_errno})"
      return 1
   fi

   if [[ "${expected_mode}" != "radar" && "${active_ads}" -lt 1 ]]
   then
      echo "activeAds must be >= 1 (got=${active_ads})"
      return 1
   fi

   if [[ "${sub_activates}" -lt "${active_subs}" || "${sub_deactivates}" -gt "${sub_activates}" ]]
   then
      echo "subscription activation/deactivation counters invalid (active=${active_subs} activates=${sub_activates} deactivates=${sub_deactivates})"
      return 1
   fi

   if [[ "${ad_activates}" -lt "${active_ads}" || "${ad_deactivates}" -gt "${ad_activates}" ]]
   then
      echo "advertisement activation/deactivation counters invalid (active=${active_ads} activates=${ad_activates} deactivates=${ad_deactivates})"
      return 1
   fi

   return 0
}

probe_deploy_mesh_stats()
{
   local attempts="${1:-180}"
   local expected_mode="${deploy_mesh_mode}"
   local require_all="${deploy_mesh_require_all}"
   local expected_brains="${brains}"
   local required_ok=1
   local ok_count=0
   local stats_response=""
   local validation_error=""
   local ip=""
   local debug_lines=""
   local ok_ips=""

   deploy_mesh_probe_success_ips=""
   deploy_mesh_probe_debug=""

   if [[ -z "${expected_mode}" ]]
   then
      return 0
   fi

   if [[ "${require_all}" == "1" ]]
   then
      required_ok="${#assigned_brain_ips[@]}"
   fi

   for attempt in $(seq 1 "${attempts}")
   do
      ok_count=0
      debug_lines=""
      ok_ips=""

      for ip in "${assigned_brain_ips[@]}"
      do
         if stats_response="$(probe_pingpong_response_in_parent_ns "${ip}" "${deploy_ping_port}" "stats")"
         then
            if validation_error="$(validate_mesh_stats_line "${stats_response}" "${expected_mode}" "${expected_brains}" 2>&1)"
            then
               ok_count=$((ok_count + 1))
               if [[ -n "${ok_ips}" ]]
               then
                  ok_ips="${ok_ips},${ip}"
               else
                  ok_ips="${ip}"
               fi
            else
               debug_lines+=$'ip='"${ip}"$' error='"${validation_error}"$' stats='"${stats_response}"$'\n'
            fi
         else
            debug_lines+=$'ip='"${ip}"$' error=no-response\n'
         fi
      done

      if [[ "${ok_count}" -ge "${required_ok}" ]]
      then
         deploy_mesh_probe_success_ips="${ok_ips}"
         deploy_mesh_probe_debug="${debug_lines}"
         return 0
      fi

      deploy_mesh_probe_debug="${debug_lines}"
      sleep 0.2
   done

   return 1
}

deploy_probe_success_ip=""
deploy_probe_success_ips=""

probe_deploy_ping_targets()
{
   local attempts="${1:-180}"

   deploy_probe_success_ip=""
   deploy_probe_success_ips=""

   if [[ "${deploy_ping_all}" == "1" ]]
   then
      declare -A ping_ok_by_ip=()

      for ip in "${assigned_brain_ips[@]}"
      do
         ping_ok_by_ip["${ip}"]=0
      done

      for attempt in $(seq 1 "${attempts}")
      do
         all_ok=1

         for ip in "${assigned_brain_ips[@]}"
         do
            if [[ "${ping_ok_by_ip["${ip}"]}" -eq 1 ]]
            then
               continue
            fi

            if probe_pingpong_in_parent_ns "${ip}" "${deploy_ping_port}" "${deploy_ping_payload}" "${deploy_ping_expect}"
            then
               ping_ok_by_ip["${ip}"]=1
            else
               all_ok=0
            fi
         done

         if [[ "${all_ok}" -eq 1 ]]
         then
            for ip in "${assigned_brain_ips[@]}"
            do
               if [[ -n "${deploy_probe_success_ips}" ]]
               then
                  deploy_probe_success_ips="${deploy_probe_success_ips},${ip}"
               else
                  deploy_probe_success_ips="${ip}"
               fi
            done

            return 0
         fi

         sleep 0.2
      done

      return 1
   fi

   for attempt in $(seq 1 "${attempts}")
   do
      for ip in "${assigned_brain_ips[@]}"
      do
         if probe_pingpong_in_parent_ns "${ip}" "${deploy_ping_port}" "${deploy_ping_payload}" "${deploy_ping_expect}"
         then
            deploy_probe_success_ip="${ip}"
            return 0
         fi
      done

      sleep 0.2
   done

   return 1
}

brain_latest_stdout_log()
{
   local idx="$1"
   local latest=""
   local latest_start=-1

   for candidate in "${brain_log_root}/brain${idx}.start"*.stdout.log
   do
      if [[ ! -f "${candidate}" ]]
      then
         continue
      fi

      if [[ "${candidate}" =~ \.start([0-9]+)\.stdout\.log$ ]]
      then
         local start_no="${BASH_REMATCH[1]}"
         if [[ "${start_no}" -gt "${latest_start}" ]]
         then
            latest_start="${start_no}"
            latest="${candidate}"
         fi
      fi
   done

   if [[ -z "${latest}" ]]
   then
      return 1
   fi

   echo "${latest}"
   return 0
}

brain_logs_contain_substring()
{
   local needle="$1"
   local log_path=""

   for log_path in "${brain_log_root}"/brain*.stdout.log
   do
      if [[ ! -f "${log_path}" ]]
      then
         continue
      fi

      if rg -q --fixed-strings "${needle}" "${log_path}" 2>/dev/null
      then
         return 0
      fi
   done

   return 1
}

container_traces_contain_substring()
{
   local needle="$1"
   local root=""
   local trace_file=""

   for root in "${brain_fs_roots[@]}"
   do
      if [[ -z "${root}" || ! -d "${root}" ]]
      then
         continue
      fi

      while IFS= read -r trace_file
      do
         if [[ -z "${trace_file}" || ! -f "${trace_file}" ]]
         then
            continue
         fi

         if rg -q --fixed-strings "${needle}" "${trace_file}" 2>/dev/null
         then
            return 0
         fi
      done < <(find "${root}" -maxdepth 6 -type f -name "pulse_battery_probe.trace.log" 2>/dev/null)
   done

   return 1
}

first_fixed_line_number()
{
   local file="$1"
   local pattern="$2"
   local match=""
   match="$(rg -n -m1 --fixed-strings "${pattern}" "${file}" 2>/dev/null || true)"
   if [[ -z "${match}" ]]
   then
      return 1
   fi

   echo "${match%%:*}"
   return 0
}

wait_for_fixed_line_number()
{
   local file="$1"
   local pattern="$2"
   local attempts="$3"
   local sleep_s="${4:-0.2}"
   local line=""

   for _ in $(seq 1 "${attempts}")
   do
      if line="$(first_fixed_line_number "${file}" "${pattern}")"
      then
         echo "${line}"
         return 0
      fi

      sleep "${sleep_s}"
   done

   return 1
}

snapshot_deploy_spin_counts()
{
   deploy_initial_spin_hosts=""
   deploy_initial_spin_counts=()

   for idx in $(seq 1 "${brains}")
   do
      local log_path=""
      local count=0

      if log_path="$(brain_latest_stdout_log "${idx}")"
      then
         count="$(rg -c --fixed-strings "neuron spinContainer deploymentID=" "${log_path}" 2>/dev/null || true)"
         if [[ -z "${count}" ]]
         then
            count=0
         fi
      fi

      deploy_initial_spin_counts[$((idx - 1))]="${count}"

      if [[ "${count}" -gt 0 ]]
      then
         if [[ -n "${deploy_initial_spin_hosts}" ]]
         then
            deploy_initial_spin_hosts="${deploy_initial_spin_hosts},${idx}"
         else
            deploy_initial_spin_hosts="${idx}"
         fi
      fi
   done

   local counts_display=""
   for idx in $(seq 1 "${brains}")
   do
      local value="${deploy_initial_spin_counts[$((idx - 1))]:-0}"
      if [[ -n "${counts_display}" ]]
      then
         counts_display="${counts_display},${idx}:${value}"
      else
         counts_display="${idx}:${value}"
      fi
   done

   local hosts_display="none"
   if [[ -n "${deploy_initial_spin_hosts}" ]]
   then
      hosts_display="${deploy_initial_spin_hosts}"
   fi

   echo "DEPLOY_SPIN_SNAPSHOT hosts=${hosts_display} counts=${counts_display}"
}

resolve_update_prodigy_bundle_path()
{
   local input_path="$1"
   resolve_prodigy_bundle_artifact_path_for_input "${input_path}"
}

verify_update_prodigy_sequence()
{
   local coordinator_log="$1"
   local expected_peer_echos="$2"
   local wait_attempts="${3:-200}"

   local begin_pattern="prodigy updateProdigy begin expectedPeerEchos=${expected_peer_echos}"
   local bundle_done_pattern="prodigy updateProdigy bundle-echo ${expected_peer_echos}/${expected_peer_echos}"
   local relinquish_begin_pattern="prodigy updateProdigy relinquish-begin peers=${expected_peer_echos}"
   local relinquish_done_pattern="prodigy updateProdigy relinquish-echo ${expected_peer_echos}/${expected_peer_echos}"

   local begin_line=0
   local bundle_done_line=0
   local relinquish_begin_line=0
   local relinquish_done_line=0

   if ! begin_line="$(wait_for_fixed_line_number "${coordinator_log}" "${begin_pattern}" "${wait_attempts}")"
   then
      echo "FAIL: updateProdigy order proof missing begin marker (${begin_pattern})"
      return 1
   fi

   if ! bundle_done_line="$(wait_for_fixed_line_number "${coordinator_log}" "${bundle_done_pattern}" "${wait_attempts}")"
   then
      echo "FAIL: updateProdigy order proof missing bundle completion marker (${bundle_done_pattern})"
      return 1
   fi

   if ! relinquish_begin_line="$(wait_for_fixed_line_number "${coordinator_log}" "${relinquish_begin_pattern}" "${wait_attempts}")"
   then
      echo "FAIL: updateProdigy order proof missing relinquish-begin marker (${relinquish_begin_pattern})"
      return 1
   fi

   if ! relinquish_done_line="$(wait_for_fixed_line_number "${coordinator_log}" "${relinquish_done_pattern}" "${wait_attempts}")"
   then
      echo "FAIL: updateProdigy order proof missing relinquish completion marker (${relinquish_done_pattern})"
      return 1
   fi

   if [[ "${begin_line}" -ge "${bundle_done_line}" || "${bundle_done_line}" -ge "${relinquish_begin_line}" || "${relinquish_begin_line}" -ge "${relinquish_done_line}" ]]
   then
      echo "FAIL: updateProdigy order violated (begin=${begin_line} bundle_done=${bundle_done_line} relinquish_begin=${relinquish_begin_line} relinquish_done=${relinquish_done_line})"
      return 1
   fi

   local bundle_echo_count=0
   bundle_echo_count="$(rg -c --fixed-strings "prodigy updateProdigy bundle-echo " "${coordinator_log}" 2>/dev/null || true)"
   if [[ -z "${bundle_echo_count}" ]]
   then
      bundle_echo_count=0
   fi

   if [[ "${bundle_echo_count}" -lt "${expected_peer_echos}" ]]
   then
      echo "FAIL: updateProdigy bundle echo count too low (seen=${bundle_echo_count}, expected_at_least=${expected_peer_echos})"
      return 1
   fi

   local relinquish_echo_count=0
   relinquish_echo_count="$(rg -c --fixed-strings "prodigy updateProdigy relinquish-echo " "${coordinator_log}" 2>/dev/null || true)"
   if [[ -z "${relinquish_echo_count}" ]]
   then
      relinquish_echo_count=0
   fi

   if [[ "${relinquish_echo_count}" -lt "${expected_peer_echos}" ]]
   then
      echo "FAIL: updateProdigy relinquish echo count too low (seen=${relinquish_echo_count}, expected_at_least=${expected_peer_echos})"
      return 1
   fi

   echo "UPDATE_ORDER begin=${begin_line} bundle_done=${bundle_done_line} relinquish_begin=${relinquish_begin_line} relinquish_done=${relinquish_done_line} bundle_echos=${bundle_echo_count} relinquish_echos=${relinquish_echo_count}"
   return 0
}

resolve_fault_targets()
{
   local baseline_master_index="$1"
   local raw_targets="$2"
   local resolved_csv=""
   local seen=","
   local follower_indices=()
   local idx_cursor=""

   for idx_cursor in $(seq 1 "${brains}")
   do
      if [[ "${idx_cursor}" -ne "${baseline_master_index}" ]]
      then
         follower_indices+=("${idx_cursor}")
      fi
   done

   IFS=',' read -r -a tokens <<< "${raw_targets}"
   for token in "${tokens[@]}"
   do
      token="${token//[[:space:]]/}"
      if [[ -z "${token}" ]]
      then
         continue
      fi

      local idx=""
      if [[ "${token}" == "master" ]]
      then
         idx="${baseline_master_index}"
      elif [[ "${token}" == "follower1" ]]
      then
         idx="${follower_indices[0]:-}"
      elif [[ "${token}" == "follower2" ]]
      then
         idx="${follower_indices[1]:-}"
      elif [[ "${token}" == "deployed" ]]
      then
         if [[ -z "${deploy_initial_spin_hosts}" ]]
         then
            echo "FAIL: --fault-targets token 'deployed' requires a successful deploy with observed spinContainer logs"
            return 1
         fi

         idx="$(first_index_from_csv "${deploy_initial_spin_hosts}" || true)"
         if [[ -z "${idx}" || "${idx}" == "0" ]]
         then
            echo "FAIL: --fault-targets token 'deployed' could not resolve a host index"
            return 1
         fi
      elif [[ "${token}" =~ ^[1-3]$ ]]
      then
         idx="${token}"
      else
         echo "FAIL: --fault-targets invalid token '${token}'"
         return 1
      fi

      if [[ -z "${idx}" ]]
      then
         echo "FAIL: --fault-targets token '${token}' could not resolve a host index"
         return 1
      fi

      if [[ "${idx}" -lt 1 || "${idx}" -gt "${brains}" ]]
      then
         echo "FAIL: --fault-targets resolved index '${idx}' is out of range"
         return 1
      fi

      if [[ "${seen}" == *",${idx},"* ]]
      then
         continue
      fi

      seen="${seen}${idx},"
      if [[ -n "${resolved_csv}" ]]
      then
         resolved_csv="${resolved_csv},${idx}"
      else
         resolved_csv="${idx}"
      fi
   done

   if [[ -z "${resolved_csv}" ]]
   then
      echo "FAIL: --fault-targets resolved to an empty set"
      return 1
   fi

   echo "${resolved_csv}"
   return 0
}

set_fault_links_state()
{
   local target_csv="$1"
   local state="$2"

   IFS=',' read -r -a targets <<< "${target_csv}"
   for idx in "${targets[@]}"
   do
      local parent_if="${parent_ifs[$((idx - 1))]}"
      local child_ns="${child_names[$((idx - 1))]}"

      if [[ "${state}" == "down" ]]
      then
         ip netns exec "${child_ns}" ip link set bond0 down
         ip netns exec "${parent_ns}" ip link set "${parent_if}" down
      else
         ip netns exec "${parent_ns}" ip link set "${parent_if}" up
         ip netns exec "${child_ns}" ip link set bond0 up
      fi
   done
}

run_brain()
{
   local ns="$1"
   local idx="$2"
   local runtime_s="${3:-${suite_runtime_s}}"
   local start_count="${brain_start_count[$((idx - 1))]:-0}"
   start_count=$((start_count + 1))
   brain_start_count[$((idx - 1))]="${start_count}"
   local stdout_log="${brain_log_root}/brain${idx}.start${start_count}.stdout.log"

   local -a run_env=(env "PRODIGY_DEV_MODE=1" "PRODIGY_HOST_NETNS_INO=${host_netns_ino}" "PRODIGY_BOOTSTRAP_BRAIN_COUNT=${brains}" "PRODIGY_DEV_SHARED_TRANSPORT_TLS_DIR=/containers/store/prodigy-transport-tls")
   if [[ -n "${runtime_host_ingress_ebpf}" ]]
   then
      run_env+=("PRODIGY_HOST_INGRESS_EBPF=${runtime_host_ingress_ebpf}")
   fi
   if [[ -n "${runtime_host_egress_ebpf}" ]]
   then
      run_env+=("PRODIGY_HOST_EGRESS_EBPF=${runtime_host_egress_ebpf}")
   fi
   if [[ "${allow_bpf_attach}" != "1" ]]
   then
      run_env+=("PRODIGY_HOST_INGRESS_EBPF=")
      run_env+=("PRODIGY_HOST_EGRESS_EBPF=")
   fi
   if [[ "${enable_fake_ipv4_boundary}" == "1" ]]
   then
      run_env+=("PRODIGY_DEV_FAKE_IPV4_MODE=1")
   fi
   if [[ "${allow_bpf_attach}" == "1" && -n "${runtime_switchboard_balancer_ebpf}" ]]
   then
      run_env+=("SWITCHBOARD_USE_PREATTACHED_XDP=1")
      run_env+=("SWITCHBOARD_BALANCER_OBJ=${runtime_switchboard_balancer_ebpf}")
   fi

   local brain_fs_root="${brain_fs_roots[$((idx - 1))]:-}"
   if [[ -z "${brain_fs_root}" || ! -d "${brain_fs_root}" ]]
   then
      echo "FAIL: missing filesystem root for brain index ${idx}: ${brain_fs_root}" >&2
      return 1
   fi

   if [[ -z "${brain_fs_shared_store}" || ! -d "${brain_fs_shared_store}" ]]
   then
      echo "FAIL: missing shared filesystem store for brain index ${idx}: ${brain_fs_shared_store}" >&2
      return 1
   fi

   local control_socket_root=""
   control_socket_root="$(dirname -- "${mothership_socket_path}")"
   if [[ -z "${control_socket_root}" || ! -d "${control_socket_root}" ]]
   then
      echo "FAIL: missing control socket root for brain index ${idx}: ${control_socket_root}" >&2
      return 1
   fi

   local role="neuron"
   if [[ "${idx}" -le "${brains}" ]]
   then
      role="brain"
   fi

   local boot_json
   boot_json="$(render_bootstrap_json "${idx}" "${role}")"

   local state_db_path="/containers/var/lib/prodigy/state"
   local runtime_prodigy_bin="/root/prodigy/prodigy"
   local -a brain_cmd=("${run_env[@]}" "PRODIGY_STATE_DB=${state_db_path}" stdbuf -oL -eL "${runtime_prodigy_bin}" --isolated --netdev=bond0 "--boot-json=${boot_json}")
   if [[ -n "${runtime_tunnel_ebpf}" ]]
   then
      brain_cmd+=("--tunnel-ebpf=${runtime_tunnel_ebpf}")
   fi

   local -a launch_prefix=(setsid)
   if [[ "${runner_mode}" != "persistent" ]]
   then
      launch_prefix+=(timeout --preserve-status -k 3s -s INT "${runtime_s}s")
   fi

   "${launch_prefix[@]}" \
      unshare -m -- bash -lc '
         set -euo pipefail
         fs_root="$1"
         ns_name="$2"
         fs_store="$3"
         control_socket_root="$4"
         shift 4

         mkdir -p /containers
         mkdir -p /mnt/prodigy-shared-store-host
         mkdir -p /mnt/prodigy-control-root
         mkdir -p /root
         mount --make-rprivate /
         mount --bind "${fs_store}" /mnt/prodigy-shared-store-host
         mount --bind "${control_socket_root}" /mnt/prodigy-control-root
         mount --bind "${fs_root}/root" /root
         mount --bind "${fs_root}" /containers
         mkdir -p "${control_socket_root}"
         mount --bind /mnt/prodigy-control-root "${control_socket_root}"
         mkdir -p /containers/store
         mount --bind /mnt/prodigy-shared-store-host /containers/store

         exec ip netns exec "${ns_name}" "$@"
      ' _ "${brain_fs_root}" "${ns}" "${brain_fs_shared_store}" "${control_socket_root}" "${brain_cmd[@]}" \
      >"${stdout_log}" 2>&1 &

   local pid="$!"
   pids+=("${pid}")
   active_pids[$((idx - 1))]="${pid}"
   pid_log_by_pid["${pid}"]="${stdout_log}"
}

remaining_runtime_seconds()
{
   local now_s
   now_s="$(date +%s)"
   local elapsed_s=$((now_s - suite_start_s))
   local remaining_s=$((suite_runtime_s - elapsed_s))
   if [[ "${remaining_s}" -lt 3 ]]
   then
      remaining_s=3
   fi

   echo "${remaining_s}"
}

terminate_all_brains()
{
   for pid in "${pids[@]}"
   do
      if [[ -z "${pid}" ]]
      then
         continue
      fi

      if kill -0 "${pid}" >/dev/null 2>&1
      then
         kill -INT -- "-${pid}" >/dev/null 2>&1 || kill -INT "${pid}" >/dev/null 2>&1 || true
         expected_nonzero_pid["${pid}"]=1
      fi
   done

   sleep 0.3

   for pid in "${pids[@]}"
   do
      if [[ -z "${pid}" ]]
      then
         continue
      fi

      if kill -0 "${pid}" >/dev/null 2>&1
      then
         kill -KILL -- "-${pid}" >/dev/null 2>&1 || kill -KILL "${pid}" >/dev/null 2>&1 || true
         expected_nonzero_pid["${pid}"]=1
      fi
   done
}

kill_fault_target_brains()
{
   local target_csv="$1"
   IFS=',' read -r -a targets <<< "${target_csv}"
   for idx in "${targets[@]}"
   do
      local pid="${active_pids[$((idx - 1))]:-}"
      if [[ -z "${pid}" ]]
      then
         continue
      fi

      if kill -0 "${pid}" >/dev/null 2>&1
      then
         kill -KILL -- "-${pid}" >/dev/null 2>&1 || kill -KILL "${pid}" >/dev/null 2>&1 || true
         expected_nonzero_pid["${pid}"]=1
      fi
   done
}

restart_fault_target_brains()
{
   local target_csv="$1"
   local runtime_s
   runtime_s="$(remaining_runtime_seconds)"

   IFS=',' read -r -a targets <<< "${target_csv}"
   for idx in "${targets[@]}"
   do
      run_brain "${child_names[$((idx - 1))]}" "${idx}" "${runtime_s}"
      sleep 0.3
   done
}

fault_phase_listener_indices="none"
fault_phase_quorum_indices="none"
fault_phase_changed=0
fault_phase_split_brain=0
fault_phase_split_quorum_indices="none"

record_fault_phase_sample()
{
   local baseline_master_index="$1"

   local listener_indices=""
   if listener_indices="$(master_listener_indices_once)"
   then
      fault_phase_listener_indices="${listener_indices}"
   fi

   local quorum_indices=""
   if quorum_indices="$(quorum_master_indices_once)"
   then
      local quorum_count
      quorum_count="$(csv_count_indices "${quorum_indices}")"
      fault_phase_quorum_indices="${quorum_indices}"
      if [[ "${quorum_count}" -gt 1 ]]
      then
         fault_phase_split_brain=1
         fault_phase_split_quorum_indices="${quorum_indices}"
      elif [[ "${quorum_count}" -eq 1 ]] && csv_has_other_than "${quorum_indices}" "${baseline_master_index}"
      then
         fault_phase_changed=1
      fi
   fi
}

if ! configure_dev_switchboard_balancers_on_nodes
then
   exit 1
fi

suite_start_s="$(date +%s)"
failed=0

echo "MASTER_SELECTION mode=self-elect"

# Start non-brain nodes first so the eventual master does not burn its initial
# neuron-control retry window against workers that are not listening yet.
# Brain order remains deterministic and neutral within the brain subset.
if [[ "${node_count}" -gt "${brains}" ]]
then
   for idx in $(seq $((brains + 1)) "${node_count}")
   do
      run_brain "${child_names[$((idx - 1))]}" "${idx}"
      sleep 0.5
   done
fi

for idx in $(seq 1 "${brains}")
do
   run_brain "${child_names[$((idx - 1))]}" "${idx}"
   sleep 0.5
done

if [[ "${runner_mode}" == "persistent" ]]
then
   leader_idx=0
   leader_ns=""

   if [[ "${brains}" -gt 1 ]]
   then
      if ! wait_for_peer_mesh 180
      then
         echo "FAIL: persistent test cluster peer connectivity did not become ready on :313"
         for idx in $(seq 1 "${brains}")
         do
            ns="${child_names[$((idx - 1))]}"
            echo "--- ${ns} sockets ---"
            ip netns exec "${ns}" ss -tan 2>/dev/null || true
         done
         exit 1
      fi

      leader_quorum_indices=""
      if leader_quorum_indices="$(wait_for_single_master_listener_indices_stable 180 5)"
      then
         leader_idx="$(first_index_from_csv "${leader_quorum_indices}" || true)"
         if [[ "${leader_idx}" -gt 0 ]]
         then
            leader_ns="${child_names[$((leader_idx - 1))]}"
         fi
      fi
   else
      leader_idx=1
      leader_ns="${child_names[0]}"
      for attempt in $(seq 1 180)
      do
         if [[ -S "${mothership_socket_path}" ]]
         then
            break
         fi
         sleep 0.2
      done
   fi

   if [[ "${leader_idx}" -le 0 || ! -S "${mothership_socket_path}" ]]
   then
      echo "FAIL: persistent test cluster did not produce a stable control socket"
      for idx in $(seq 1 "${brains}")
      do
         ns="${child_names[$((idx - 1))]}"
         dump_master_listener_state "${ns}" || true
      done
      exit 1
   fi

   write_persistent_manifest "${leader_idx}"
   echo "TEST_CLUSTER_READY controlSocket=${mothership_socket_path} manifest=${manifest_path} leaderIndex=${leader_idx} machines=${machines} brains=${brains}"

   while true
   do
      sleep 3600 &
      wait $! || true
   done
fi

if [[ "${brains}" == "3" ]]
then
   if ! wait_for_peer_mesh 120
   then
      echo "FAIL: 3-brain peer connectivity did not become ready on :313"
      for ns in "${child_names[@]}"
      do
         echo "--- ${ns} sockets ---"
         ip netns exec "${ns}" ss -tan 2>/dev/null || true
      done
      failed=1
   fi

   if [[ "${failed}" -eq 0 ]] && ! wait_for_peer_mesh_bootstrap_family 120
   then
      echo "FAIL: 3-brain peer connectivity on :313 did not stay on the requested ${brain_bootstrap_family} address family"
      for ns in "${child_names[@]}"
      do
         echo "--- ${ns} established peer links ---"
         ip netns exec "${ns}" ss -tan 2>/dev/null | awk '$1=="ESTAB" && ($4 ~ /:313$/ || $5 ~ /:313$/)' || true
      done
      failed=1
   fi

   leader_ready=0
   leader_ns=""
   leader_idx=0
   leader_quorum_indices=""
   if leader_quorum_indices="$(wait_for_single_master_listener_indices_stable 120 5)"
   then
      leader_idx="$(first_index_from_csv "${leader_quorum_indices}" || true)"
      if [[ "${leader_idx}" -gt 0 ]]
      then
         leader_ns="${child_names[$((leader_idx - 1))]}"
         leader_ready=1
      fi
   fi

   if [[ "${leader_ready}" -ne 1 ]]
   then
      echo "FAIL: no single quorum master control listener became stable"
      for ns in "${child_names[@]}"
      do
         dump_master_listener_state "${ns}"
      done
      failed=1
   else
      echo "MASTER_LISTENER ns=${leader_ns} index=${leader_idx} quorum=${leader_quorum_indices}"
   fi
fi

if [[ -n "${mothership_bin}" ]]
then
   fragment=$((RANDOM % 255 + 1))
   configured=0
   legacy_local_configure_invalid=0
   cluster_reported=0
   configure_ns=""
   configure_index=0
   configure_ip=""
   configure_quorum_indices=""
   listener_ready=0

   if [[ "${brains}" == "1" ]]
   then
      configure_index=1
      configure_ns="${child_names[0]}"
      configure_ip="${assigned_brain_ips[0]}"
   elif configure_quorum_indices="$(wait_for_single_master_listener_indices_stable 120 5)"
   then
      configure_index="$(first_index_from_csv "${configure_quorum_indices}" || true)"
      if [[ "${configure_index}" -gt 0 ]]
      then
         configure_ns="${child_names[$((configure_index - 1))]}"
         configure_ip="${assigned_brain_ips[$((configure_index - 1))]}"
      fi
   fi

   if [[ -z "${configure_ns}" ]]
   then
      echo "FAIL: unable to identify a single elected master for mothership configure"
      for ns in "${child_names[@]}"
      do
         dump_master_listener_state "${ns}"
      done
      failed=1
   fi

   if [[ -n "${configure_ns}" ]]
   then
      # Wait for the elected master's listener before attempting configure.
      for attempt in $(seq 1 120)
      do
         if master_listener_in_ns "${configure_ns}"
         then
            listener_ready=1
            break
         fi

         sleep 0.2
      done
   fi

   if [[ -n "${configure_ns}" && "${listener_ready}" -ne 1 ]]
   then
      echo "FAIL: elected master listener did not become ready in ${configure_ns}"
      for ns in "${child_names[@]}"
      do
         dump_master_listener_state "${ns}"
      done
      failed=1
   fi

   for attempt in $(seq 1 80)
   do
      if [[ "${brains}" != "1" ]]
      then
         current_quorum_indices="$(quorum_master_indices_once || true)"
         if [[ -n "${current_quorum_indices}" ]]
         then
            current_count="$(csv_count_indices "${current_quorum_indices}")"
            if [[ "${current_count}" -eq 1 ]]
            then
               current_index="$(first_index_from_csv "${current_quorum_indices}" || true)"
               if [[ "${current_index}" -gt 0 ]]
               then
                  configure_index="${current_index}"
                  configure_ns="${child_names[$((configure_index - 1))]}"
                  configure_ip="${assigned_brain_ips[$((configure_index - 1))]}"
                  configure_quorum_indices="${current_quorum_indices}"
               fi
            fi
         fi
      fi

      listener_ready=0
      if [[ -S "${mothership_socket_path}" ]]
      then
         listener_ready=1
      fi

      if [[ "${listener_ready}" -ne 1 ]]
      then
         sleep 0.2
         continue
      fi

      if timeout --preserve-status -k 2s 3s \
         ip netns exec "${configure_ns}" \
         env PRODIGY_STATE_DB=/containers/var/lib/prodigy/state PRODIGY_MOTHERSHIP_SOCKET="${mothership_socket_path}" "${mothership_bin}" configure local "${fragment}" dev-baremetal 8 16384 262144 "${mothership_autoscale_interval_seconds}" \
         >"${tmpdir}/mothership.configure.log" 2>&1
      then
         configured=1
         break
      fi

      if grep -q "operation invalid" "${tmpdir}/mothership.configure.log" 2>/dev/null
      then
         legacy_local_configure_invalid=1
         configured=1
         break
      fi

      sleep 0.2
   done

   if [[ "${listener_ready}" -eq 1 && "${configured}" -ne 1 ]]
   then
      echo "FAIL: mothership configure did not succeed"
      sed -n '1,160p' "${tmpdir}/mothership.configure.log"
      failed=1
   elif [[ "${listener_ready}" -eq 1 && "${configured}" -eq 1 ]]
   then
      if [[ "${legacy_local_configure_invalid}" -eq 1 ]]
      then
         echo "NOTE: skipping legacy mothership configure local path because the current mothership binary reports operation invalid"
         cluster_reported=1
      else
         for attempt in $(seq 1 80)
         do
            if run_cluster_report_from_any_ns "${tmpdir}/mothership.clusterreport.log" 3
            then
               cluster_reported=1
               break
            fi

            sleep 0.2
         done
      fi

      if [[ "${cluster_reported}" -ne 1 ]]
      then
         echo "FAIL: mothership clusterReport did not succeed after configure"
         sed -n '1,160p' "${tmpdir}/mothership.clusterreport.log"
         failed=1
      else
         configure_quorum_display="n/a"
         if [[ -n "${configure_quorum_indices}" ]]
         then
            configure_quorum_display="${configure_quorum_indices}"
         fi
         echo "MOTHERSHIP_BOOTSTRAP success index=${configure_index} ip=${configure_ip} fragment=${fragment} quorum=${configure_quorum_display}"

         if [[ "${failed}" -eq 0 && -n "${deploy_plan_json}" ]]
         then
            deploy_container_runtime_path="${deploy_container_zstd}"
            deploy_runtime_plan_json="${deploy_plan_json}"

            if ! ip netns exec "${configure_ns}" test -f "${deploy_container_runtime_path}" >/dev/null 2>&1
            then
               deploy_container_runtime_path="/root/prodigy.deploy.${RANDOM}.${$}.container.zst"
               cp -f "${deploy_container_zstd}" "${deploy_container_runtime_path}"
            fi

            if ! ip netns exec "${configure_ns}" test -f "${deploy_container_runtime_path}" >/dev/null 2>&1
            then
               echo "FAIL: deploy container blob is not visible inside configure namespace"
               echo "original=${deploy_container_zstd}"
               echo "runtime=${deploy_container_runtime_path}"
               failed=1
            fi

            deploy_ok=0

            if [[ "${failed}" -eq 0 ]]
            then
               if ! deploy_runtime_plan_json="$(reserve_application_id_for_plan "${configure_ns}" "${deploy_plan_json}" "primary")"
               then
                  failed=1
               fi
            fi

            if [[ "${failed}" -eq 0 ]]
            then
               if ! reserve_service_ids_for_plan "${configure_ns}" "${deploy_plan_json}" "${deploy_runtime_plan_json}" "primary"
               then
                  failed=1
               fi
            fi

            if [[ "${failed}" -eq 0 ]]
            then
               deploy_json_payload="$(tr '\n' ' ' < "${deploy_runtime_plan_json}")"
            fi

            if [[ "${failed}" -eq 0 ]]
            then
               for attempt in $(seq 1 "${deploy_attempts}")
               do
                  deploy_attempt_rc=0
                  timeout --preserve-status -k 3s "${deploy_attempt_timeout_s}"s \
                     ip netns exec "${configure_ns}" \
                     env PRODIGY_STATE_DB=/containers/var/lib/prodigy/state PRODIGY_MOTHERSHIP_SOCKET="${mothership_socket_path}" "${mothership_bin}" deploy local "${deploy_json_payload}" "${deploy_container_runtime_path}" \
                     >"${tmpdir}/mothership.deploy.log" 2>&1 || deploy_attempt_rc=$?

                  # A dev deploy may continue streaming status after acceptance and exceed
                  # the per-attempt timeout. Treat explicit acceptance as success and let
                  # the ping probe below validate real container readiness.
                  if rg -q "SpinApplicationResponseCode::okay" "${tmpdir}/mothership.deploy.log"
                  then
                     deploy_ok=1
                     break
                  fi

                  # Hard failure that did not even establish a request to master.
                  if [[ "${deploy_attempt_rc}" -eq 143 ]] && rg -q "failed to connect to mothership" "${tmpdir}/mothership.deploy.log"
                  then
                     break
                  fi

                  # Reject-path tests only need one completed non-accept attempt.
                  if [[ "${deploy_expect_accept}" == "0" ]]
                  then
                     break
                  fi

                  sleep 0.3
               done
            fi

            if [[ "${deploy_expect_accept}" == "1" ]]
            then
               if [[ "${deploy_ok}" -ne 1 ]]
               then
                  echo "FAIL: mothership deploy did not succeed"
                  sed -n '1,220p' "${tmpdir}/mothership.deploy.log"
                  failed=1
               else
                  echo "MOTHERSHIP_DEPLOY success plan=${deploy_plan_json} blob=${deploy_container_runtime_path}"
               fi
            else
               if [[ "${deploy_ok}" -eq 1 ]]
               then
                  echo "FAIL: mothership deploy unexpectedly succeeded"
                  sed -n '1,220p' "${tmpdir}/mothership.deploy.log"
                  failed=1
               elif [[ -n "${deploy_expect_text}" ]] && ! rg -q --fixed-strings "${deploy_expect_text}" "${tmpdir}/mothership.deploy.log"
               then
                  echo "FAIL: deploy rejection did not include expected text: ${deploy_expect_text}"
                  sed -n '1,220p' "${tmpdir}/mothership.deploy.log"
                  failed=1
               else
                  echo "MOTHERSHIP_DEPLOY expected_reject plan=${deploy_plan_json}"
               fi
            fi

            if [[ "${failed}" -eq 0 && "${deploy_ok}" -eq 1 ]]
            then
               refresh_fake_ipv4_gateway_route_from_primary_deploy
               configure_dev_switchboard_balancer_on_gateway || true
            fi

            if [[ "${failed}" -eq 0 && "${deploy_ok}" -eq 1 && -n "${deploy_second_plan_json}" ]]
            then
               if [[ "${deploy_second_start_s}" -gt 0 ]]
               then
                  sleep "${deploy_second_start_s}"
               fi

               deploy_second_container_runtime_path="${deploy_second_container_zstd}"
               deploy_second_runtime_plan_json="${deploy_second_plan_json}"

               if ! ip netns exec "${configure_ns}" test -f "${deploy_second_container_runtime_path}" >/dev/null 2>&1
               then
                  deploy_second_container_runtime_path="/root/prodigy.deploy.second.${RANDOM}.${$}.container.zst"
                  cp -f "${deploy_second_container_zstd}" "${deploy_second_container_runtime_path}"
               fi

               if ! ip netns exec "${configure_ns}" test -f "${deploy_second_container_runtime_path}" >/dev/null 2>&1
               then
                  echo "FAIL: second deploy container blob is not visible inside configure namespace"
                  echo "original=${deploy_second_container_zstd}"
                  echo "runtime=${deploy_second_container_runtime_path}"
                  failed=1
               fi

               deploy_second_ok=0

               if [[ "${failed}" -eq 0 ]]
               then
                  if ! deploy_second_runtime_plan_json="$(reserve_application_id_for_plan "${configure_ns}" "${deploy_second_plan_json}" "second")"
                  then
                     failed=1
                  fi
               fi

               if [[ "${failed}" -eq 0 ]]
               then
                  if ! reserve_service_ids_for_plan "${configure_ns}" "${deploy_second_plan_json}" "${deploy_second_runtime_plan_json}" "second"
                  then
                     failed=1
                  fi
               fi

               if [[ "${failed}" -eq 0 ]]
               then
                  deploy_second_json_payload="$(tr '\n' ' ' < "${deploy_second_runtime_plan_json}")"
               fi

               if [[ "${failed}" -eq 0 ]]
               then
                  for attempt in $(seq 1 "${deploy_attempts}")
                  do
                     deploy_second_attempt_rc=0
                     timeout --preserve-status -k 3s "${deploy_attempt_timeout_s}"s \
                        ip netns exec "${configure_ns}" \
                        env PRODIGY_STATE_DB=/containers/var/lib/prodigy/state PRODIGY_MOTHERSHIP_SOCKET="${mothership_socket_path}" "${mothership_bin}" deploy local "${deploy_second_json_payload}" "${deploy_second_container_runtime_path}" \
                        >"${tmpdir}/mothership.deploy.second.log" 2>&1 || deploy_second_attempt_rc=$?

                     if rg -q "SpinApplicationResponseCode::okay" "${tmpdir}/mothership.deploy.second.log"
                     then
                        deploy_second_ok=1
                        break
                     fi

                     if [[ "${deploy_second_attempt_rc}" -eq 143 ]] && rg -q "failed to connect to mothership" "${tmpdir}/mothership.deploy.second.log"
                     then
                        break
                     fi

                     # Reject-path tests only need one completed non-accept attempt.
                     if [[ "${deploy_second_expect_accept}" == "0" ]]
                     then
                        break
                     fi

                     sleep 0.3
                  done
               fi

               if [[ "${deploy_second_expect_accept}" == "1" ]]
               then
                  if [[ "${deploy_second_ok}" -ne 1 ]]
                  then
                     echo "FAIL: mothership second deploy did not succeed"
                     sed -n '1,220p' "${tmpdir}/mothership.deploy.second.log"
                     failed=1
                  else
                     echo "MOTHERSHIP_DEPLOY_SECOND success plan=${deploy_second_plan_json} blob=${deploy_second_container_runtime_path}"
                  fi
               else
                  if [[ "${deploy_second_ok}" -eq 1 ]]
                  then
                     echo "FAIL: mothership second deploy unexpectedly succeeded"
                     sed -n '1,220p' "${tmpdir}/mothership.deploy.second.log"
                     failed=1
                  elif [[ -n "${deploy_second_expect_text}" ]] && ! rg -q --fixed-strings "${deploy_second_expect_text}" "${tmpdir}/mothership.deploy.second.log"
                  then
                     echo "FAIL: second deploy rejection did not include expected text: ${deploy_second_expect_text}"
                     sed -n '1,220p' "${tmpdir}/mothership.deploy.second.log"
                     failed=1
                  else
                     echo "MOTHERSHIP_DEPLOY_SECOND expected_reject plan=${deploy_second_plan_json}"
                  fi
               fi
            fi

            if [[ "${failed}" -eq 0 && "${enable_fake_ipv4_boundary}" == "1" && "${deploy_second_expect_accept}" == "1" && "${deploy_second_ok}" -eq 1 ]]
            then
               second_machine_fragment="$(resolve_second_deploy_machine_fragment_from_logs || true)"
               if [[ -n "${second_machine_fragment}" ]]
               then
                  switchboard_balancer_machine_fragment_override="${second_machine_fragment}"
                  configure_dev_switchboard_balancer_on_gateway || true
                  echo "SWITCHBOARD_BALANCER_DEV_RESYNC machine_fragment=${second_machine_fragment}"
               else
                  echo "WARN: unable to resolve second deploy machine fragment for switchboard balancer resync"
               fi
            fi

            if [[ "${failed}" -eq 0 && "${deploy_ok}" -eq 1 && -n "${deploy_third_plan_json}" ]]
            then
               if [[ "${deploy_third_start_s}" -gt 0 ]]
               then
                  sleep "${deploy_third_start_s}"
               fi

               deploy_third_container_runtime_path="${deploy_third_container_zstd}"
               deploy_third_runtime_plan_json="${deploy_third_plan_json}"

               if ! ip netns exec "${configure_ns}" test -f "${deploy_third_container_runtime_path}" >/dev/null 2>&1
               then
                  deploy_third_container_runtime_path="/root/prodigy.deploy.third.${RANDOM}.${$}.container.zst"
                  cp -f "${deploy_third_container_zstd}" "${deploy_third_container_runtime_path}"
               fi

               if ! ip netns exec "${configure_ns}" test -f "${deploy_third_container_runtime_path}" >/dev/null 2>&1
               then
                  echo "FAIL: third deploy container blob is not visible inside configure namespace"
                  echo "original=${deploy_third_container_zstd}"
                  echo "runtime=${deploy_third_container_runtime_path}"
                  failed=1
               fi

               deploy_third_ok=0

               if [[ "${failed}" -eq 0 ]]
               then
                  if ! deploy_third_runtime_plan_json="$(reserve_application_id_for_plan "${configure_ns}" "${deploy_third_plan_json}" "third")"
                  then
                     failed=1
                  fi
               fi

               if [[ "${failed}" -eq 0 ]]
               then
                  if ! reserve_service_ids_for_plan "${configure_ns}" "${deploy_third_plan_json}" "${deploy_third_runtime_plan_json}" "third"
                  then
                     failed=1
                  fi
               fi

               if [[ "${failed}" -eq 0 ]]
               then
                  deploy_third_json_payload="$(tr '\n' ' ' < "${deploy_third_runtime_plan_json}")"
               fi

               if [[ "${failed}" -eq 0 ]]
               then
                  for attempt in $(seq 1 "${deploy_attempts}")
                  do
                     deploy_third_attempt_rc=0
                     timeout --preserve-status -k 3s "${deploy_attempt_timeout_s}"s \
                        ip netns exec "${configure_ns}" \
                        env PRODIGY_STATE_DB=/containers/var/lib/prodigy/state PRODIGY_MOTHERSHIP_SOCKET="${mothership_socket_path}" "${mothership_bin}" deploy local "${deploy_third_json_payload}" "${deploy_third_container_runtime_path}" \
                        >"${tmpdir}/mothership.deploy.third.log" 2>&1 || deploy_third_attempt_rc=$?

                     if rg -q "SpinApplicationResponseCode::okay" "${tmpdir}/mothership.deploy.third.log"
                     then
                        deploy_third_ok=1
                        break
                     fi

                     if [[ "${deploy_third_attempt_rc}" -eq 143 ]] && rg -q "failed to connect to mothership" "${tmpdir}/mothership.deploy.third.log"
                     then
                        break
                     fi

                     if [[ "${deploy_third_expect_accept}" == "0" ]]
                     then
                        break
                     fi

                     sleep 0.3
                  done
               fi

               if [[ "${deploy_third_expect_accept}" == "1" ]]
               then
                  if [[ "${deploy_third_ok}" -ne 1 ]]
                  then
                     echo "FAIL: mothership third deploy did not succeed"
                     sed -n '1,220p' "${tmpdir}/mothership.deploy.third.log"
                     failed=1
                  else
                     echo "MOTHERSHIP_DEPLOY_THIRD success plan=${deploy_third_plan_json} blob=${deploy_third_container_runtime_path}"
                  fi
               else
                  if [[ "${deploy_third_ok}" -eq 1 ]]
                  then
                     echo "FAIL: mothership third deploy unexpectedly succeeded"
                     sed -n '1,220p' "${tmpdir}/mothership.deploy.third.log"
                     failed=1
                  elif [[ -n "${deploy_third_expect_text}" ]] && ! rg -q --fixed-strings "${deploy_third_expect_text}" "${tmpdir}/mothership.deploy.third.log"
                  then
                     echo "FAIL: third deploy rejection did not include expected text: ${deploy_third_expect_text}"
                     sed -n '1,220p' "${tmpdir}/mothership.deploy.third.log"
                     failed=1
                  else
                     echo "MOTHERSHIP_DEPLOY_THIRD expected_reject plan=${deploy_third_plan_json}"
                  fi
               fi
            fi

            if [[ "${failed}" -eq 0 && "${deploy_ok}" -eq 1 && "${deploy_skip_probe}" == "0" ]]
            then
               # Prime basic request traffic so containers emit initial runtime metrics
               # before report-based autoscale assertions run.
               for _ in $(seq 1 60)
               do
                  for burst in $(seq 1 "${deploy_report_traffic_burst}")
                  do
                     for ip in "${assigned_brain_ips[@]}"
                     do
                        emit_pingpong_traffic_in_parent_ns "${ip}" "${deploy_ping_port}" "${deploy_ping_payload}" 0.35 >/dev/null 2>&1 || true
                     done
                  done
                  sleep 0.1
               done
            fi

            if [[ "${failed}" -eq 0 && "${deploy_ok}" -eq 1 && -n "${deploy_report_application}" ]]
            then
               report_ok=0
               report_max_healthy=0
               report_last_healthy=-1
               report_max_target=0
               report_last_target=-1
               report_max_shard_groups=0
               report_last_shard_groups=-1
               report_min_runtime_cores=-1
               report_min_runtime_memory_mb=-1
               report_min_runtime_storage_mb=-1
               report_max_runtime_cores=0
               report_max_runtime_memory_mb=0
               report_max_runtime_storage_mb=0
               report_runtime_constraints_requested=0
               report_floor_constraints_requested=0
               report_timed_out=0
               report_start_ms=$(( $(date +%s%N) / 1000000 ))
               report_deadline_ms=$((report_start_ms + deploy_report_max_seconds * 1000))
               report_stable_since_ms=0

               if [[ "${deploy_report_runtime_cores_min}" -gt 0 || "${deploy_report_runtime_memory_min_mb}" -gt 0 || "${deploy_report_runtime_storage_min_mb}" -gt 0 || "${deploy_report_runtime_cores_max_min}" -gt 0 || "${deploy_report_runtime_memory_max_min_mb}" -gt 0 || "${deploy_report_runtime_storage_max_min_mb}" -gt 0 ]]
               then
                  report_runtime_constraints_requested=1
               fi

               # Floor checks require a bounded minimum runtime window before pass.
               if [[ "${deploy_report_runtime_cores_min}" -gt 0 || "${deploy_report_runtime_memory_min_mb}" -gt 0 || "${deploy_report_runtime_storage_min_mb}" -gt 0 ]]
               then
                  report_floor_constraints_requested=1
               fi

               for attempt in $(seq 1 "${deploy_report_attempts}")
               do
                  report_now_ms=$(( $(date +%s%N) / 1000000 ))
                  if [[ "${report_now_ms}" -ge "${report_deadline_ms}" ]]
                  then
                     report_timed_out=1
                     break
                  fi

                  if [[ "${deploy_skip_probe}" == "0" ]]
                  then
                     for burst in $(seq 1 "${deploy_report_traffic_burst}")
                     do
                        for ip in "${assigned_brain_ips[@]}"
                        do
                           emit_pingpong_traffic_in_parent_ns "${ip}" "${deploy_ping_port}" "${deploy_ping_payload}" 0.35 >/dev/null 2>&1 || true
                        done
                     done
                  fi

                  if run_cluster_report_from_any_ns "${tmpdir}/mothership.clusterreport.log" 3
                  then
                     report_sample_max="$(
                        awk -v app="${deploy_report_application}" -v version="${deploy_report_version_id}" -v version_min="${deploy_report_version_min}" '
                           /^[[:space:]]*Application:[[:space:]]*/ {
                              name = $0;
                              sub(/^[[:space:]]*Application:[[:space:]]*/, "", name);
                              in_app = (name == app);
                              current_version = 0;
                              next;
                           }
                           in_app && match($0, /versionID:[[:space:]]*([0-9]+)/, m) {
                              current_version = m[1] + 0;
                              next;
                           }
                           in_app && (version == 0 || (version_min == 1 ? current_version >= version : current_version == version)) && match($0, /nHealthy:[[:space:]]*([0-9]+)/, m) {
                              healthy = m[1] + 0;
                              if (healthy > max) max = healthy;
                           }
                           END { print max + 0; }
                        ' "${tmpdir}/mothership.applicationreport.log"
                     )"

                     report_sample_last="$(
                        awk -v app="${deploy_report_application}" -v version="${deploy_report_version_id}" -v version_min="${deploy_report_version_min}" '
                           /^[[:space:]]*Application:[[:space:]]*/ {
                              name = $0;
                              sub(/^[[:space:]]*Application:[[:space:]]*/, "", name);
                              in_app = (name == app);
                              current_version = 0;
                              next;
                           }
                           in_app && match($0, /versionID:[[:space:]]*([0-9]+)/, m) {
                              current_version = m[1] + 0;
                              next;
                           }
                           in_app && (version == 0 || (version_min == 1 ? current_version >= version : current_version == version)) && match($0, /nHealthy:[[:space:]]*([0-9]+)/, m) {
                              last = m[1] + 0;
                              seen = 1;
                           }
                           END {
                              if (seen) print last + 0;
                              else print -1;
                           }
                        ' "${tmpdir}/mothership.applicationreport.log"
                     )"

                     if [[ "${report_sample_max}" -gt "${report_max_healthy}" ]]
                     then
                        report_max_healthy="${report_sample_max}"
                     fi

                     if [[ "${report_sample_last}" -ge 0 ]]
                     then
                        report_last_healthy="${report_sample_last}"
                     fi

                     report_target_sample_max="$(
                        awk -v app="${deploy_report_application}" -v version="${deploy_report_version_id}" -v version_min="${deploy_report_version_min}" '
                           /^[[:space:]]*Application:[[:space:]]*/ {
                              name = $0;
                              sub(/^[[:space:]]*Application:[[:space:]]*/, "", name);
                              in_app = (name == app);
                              current_version = 0;
                              next;
                           }
                           in_app && match($0, /versionID:[[:space:]]*([0-9]+)/, m) {
                              current_version = m[1] + 0;
                              next;
                           }
                           in_app && (version == 0 || (version_min == 1 ? current_version >= version : current_version == version)) && match($0, /nTarget:[[:space:]]*([0-9]+)/, m) {
                              target = m[1] + 0;
                              if (target > max) max = target;
                           }
                           END { print max + 0; }
                        ' "${tmpdir}/mothership.applicationreport.log"
                     )"

                     report_target_sample_last="$(
                        awk -v app="${deploy_report_application}" -v version="${deploy_report_version_id}" -v version_min="${deploy_report_version_min}" '
                           /^[[:space:]]*Application:[[:space:]]*/ {
                              name = $0;
                              sub(/^[[:space:]]*Application:[[:space:]]*/, "", name);
                              in_app = (name == app);
                              current_version = 0;
                              next;
                           }
                           in_app && match($0, /versionID:[[:space:]]*([0-9]+)/, m) {
                              current_version = m[1] + 0;
                              next;
                           }
                           in_app && (version == 0 || (version_min == 1 ? current_version >= version : current_version == version)) && match($0, /nTarget:[[:space:]]*([0-9]+)/, m) {
                              last = m[1] + 0;
                              seen = 1;
                           }
                           END {
                              if (seen) print last + 0;
                              else print -1;
                           }
                        ' "${tmpdir}/mothership.applicationreport.log"
                     )"

                     if [[ "${report_target_sample_max}" -gt "${report_max_target}" ]]
                     then
                        report_max_target="${report_target_sample_max}"
                     fi

                     if [[ "${report_target_sample_last}" -ge 0 ]]
                     then
                        report_last_target="${report_target_sample_last}"
                     fi

                     report_shard_groups_sample_max="$(
                        awk -v app="${deploy_report_application}" -v version="${deploy_report_version_id}" -v version_min="${deploy_report_version_min}" '
                           /^[[:space:]]*Application:[[:space:]]*/ {
                              name = $0;
                              sub(/^[[:space:]]*Application:[[:space:]]*/, "", name);
                              in_app = (name == app);
                              current_version = 0;
                              next;
                           }
                           in_app && match($0, /versionID:[[:space:]]*([0-9]+)/, m) {
                              current_version = m[1] + 0;
                              next;
                           }
                           in_app && (version == 0 || (version_min == 1 ? current_version >= version : current_version == version)) && match($0, /nShardGroups:[[:space:]]*([0-9]+)/, m) {
                              groups = m[1] + 0;
                              if (groups > max) max = groups;
                           }
                           END { print max + 0; }
                        ' "${tmpdir}/mothership.applicationreport.log"
                     )"

                     report_shard_groups_sample_last="$(
                        awk -v app="${deploy_report_application}" -v version="${deploy_report_version_id}" -v version_min="${deploy_report_version_min}" '
                           /^[[:space:]]*Application:[[:space:]]*/ {
                              name = $0;
                              sub(/^[[:space:]]*Application:[[:space:]]*/, "", name);
                              in_app = (name == app);
                              current_version = 0;
                              next;
                           }
                           in_app && match($0, /versionID:[[:space:]]*([0-9]+)/, m) {
                              current_version = m[1] + 0;
                              next;
                           }
                           in_app && (version == 0 || (version_min == 1 ? current_version >= version : current_version == version)) && match($0, /nShardGroups:[[:space:]]*([0-9]+)/, m) {
                              last = m[1] + 0;
                              seen = 1;
                           }
                           END {
                              if (seen) print last + 0;
                              else print -1;
                           }
                        ' "${tmpdir}/mothership.applicationreport.log"
                     )"

                     if [[ "${report_shard_groups_sample_max}" -gt "${report_max_shard_groups}" ]]
                     then
                        report_max_shard_groups="${report_shard_groups_sample_max}"
                     fi

                     if [[ "${report_shard_groups_sample_last}" -ge 0 ]]
                     then
                        report_last_shard_groups="${report_shard_groups_sample_last}"
                     fi

                     report_runtime_sample="$(
                        awk -v app="${deploy_report_application}" -v version="${deploy_report_version_id}" -v version_min="${deploy_report_version_min}" '
                           BEGIN {
                              min_cores = -1;
                              min_mem = -1;
                              min_stor = -1;
                              max_cores = 0;
                              max_mem = 0;
                              max_stor = 0;
                              seen = 0;
                           }
                           /^[[:space:]]*Application:[[:space:]]*/ {
                              name = $0;
                              sub(/^[[:space:]]*Application:[[:space:]]*/, "", name);
                              in_app = (name == app);
                              current_version = 0;
                              next;
                           }
                           in_app && match($0, /versionID:[[:space:]]*([0-9]+)/, m) {
                              current_version = m[1] + 0;
                              next;
                           }
                           in_app && (version == 0 || (version_min == 1 ? current_version >= version : current_version == version)) && match($0, /containerRuntime:[[:space:]]*cores=([0-9]+)[[:space:]]*memMB=([0-9]+)[[:space:]]*storMB=([0-9]+)/, m) {
                              cores = m[1] + 0;
                              mem = m[2] + 0;
                              stor = m[3] + 0;

                              if (min_cores < 0 || cores < min_cores) min_cores = cores;
                              if (min_mem < 0 || mem < min_mem) min_mem = mem;
                              if (min_stor < 0 || stor < min_stor) min_stor = stor;
                              if (cores > max_cores) max_cores = cores;
                              if (mem > max_mem) max_mem = mem;
                              if (stor > max_stor) max_stor = stor;
                              seen = 1;
                           }
                           END {
                              if (!seen)
                              {
                                 print "-1 -1 -1 0 0 0";
                              }
                              else
                              {
                                 printf "%d %d %d %d %d %d\n", min_cores, min_mem, min_stor, max_cores, max_mem, max_stor;
                              }
                           }
                        ' "${tmpdir}/mothership.applicationreport.log"
                     )"

                     read -r report_runtime_sample_min_cores report_runtime_sample_min_memory_mb report_runtime_sample_min_storage_mb report_runtime_sample_max_cores report_runtime_sample_max_memory_mb report_runtime_sample_max_storage_mb <<<"${report_runtime_sample}"

                     if [[ -z "${report_runtime_sample_min_cores}" ]]
                     then
                        report_runtime_sample_min_cores=-1
                        report_runtime_sample_min_memory_mb=-1
                        report_runtime_sample_min_storage_mb=-1
                        report_runtime_sample_max_cores=0
                        report_runtime_sample_max_memory_mb=0
                        report_runtime_sample_max_storage_mb=0
                     fi

                     if [[ "${report_runtime_sample_min_cores}" -ge 0 ]]
                     then
                        if [[ "${report_min_runtime_cores}" -lt 0 || "${report_runtime_sample_min_cores}" -lt "${report_min_runtime_cores}" ]]
                        then
                           report_min_runtime_cores="${report_runtime_sample_min_cores}"
                        fi

                        if [[ "${report_runtime_sample_min_memory_mb}" -lt "${report_min_runtime_memory_mb}" || "${report_min_runtime_memory_mb}" -lt 0 ]]
                        then
                           report_min_runtime_memory_mb="${report_runtime_sample_min_memory_mb}"
                        fi

                        if [[ "${report_runtime_sample_min_storage_mb}" -lt "${report_min_runtime_storage_mb}" || "${report_min_runtime_storage_mb}" -lt 0 ]]
                        then
                           report_min_runtime_storage_mb="${report_runtime_sample_min_storage_mb}"
                        fi
                     fi

                     if [[ "${report_runtime_sample_max_cores}" -gt "${report_max_runtime_cores}" ]]
                     then
                        report_max_runtime_cores="${report_runtime_sample_max_cores}"
                     fi

                     if [[ "${report_runtime_sample_max_memory_mb}" -gt "${report_max_runtime_memory_mb}" ]]
                     then
                        report_max_runtime_memory_mb="${report_runtime_sample_max_memory_mb}"
                     fi

                     if [[ "${report_runtime_sample_max_storage_mb}" -gt "${report_max_runtime_storage_mb}" ]]
                     then
                        report_max_runtime_storage_mb="${report_runtime_sample_max_storage_mb}"
                     fi

                     healthy_constraints_met=0
                     target_constraints_met=0
                     shard_constraints_met=1
                     runtime_constraints_met=1

                     if [[ "${report_max_healthy}" -ge "${deploy_report_min_healthy}" && "${report_max_healthy}" -ge "${deploy_report_max_healthy_min}" ]]
                     then
                        if [[ "${deploy_report_final_healthy_max}" == "-1" || ( "${report_last_healthy}" -ge 0 && "${report_last_healthy}" -le "${deploy_report_final_healthy_max}" ) ]]
                        then
                           healthy_constraints_met=1
                        fi
                     fi

                     if [[ "${report_max_target}" -ge "${deploy_report_min_target}" && "${report_max_target}" -ge "${deploy_report_max_target_min}" ]]
                     then
                        if [[ "${deploy_report_final_target_max}" == "-1" || ( "${report_last_target}" -ge 0 && "${report_last_target}" -le "${deploy_report_final_target_max}" ) ]]
                        then
                           target_constraints_met=1
                        fi
                     fi

                     if [[ "${report_max_shard_groups}" -lt "${deploy_report_min_shard_groups}" || "${report_max_shard_groups}" -lt "${deploy_report_max_shard_groups_min}" ]]
                     then
                        shard_constraints_met=0
                     fi

                     if [[ "${deploy_report_final_shard_groups_max}" != "-1" && ( "${report_last_shard_groups}" -lt 0 || "${report_last_shard_groups}" -gt "${deploy_report_final_shard_groups_max}" ) ]]
                     then
                        shard_constraints_met=0
                     fi

                     if [[ "${deploy_report_runtime_cores_min}" -gt 0 && ( "${report_min_runtime_cores}" -lt 0 || "${report_min_runtime_cores}" -lt "${deploy_report_runtime_cores_min}" ) ]]
                     then
                        runtime_constraints_met=0
                     fi

                     if [[ "${deploy_report_runtime_memory_min_mb}" -gt 0 && ( "${report_min_runtime_memory_mb}" -lt 0 || "${report_min_runtime_memory_mb}" -lt "${deploy_report_runtime_memory_min_mb}" ) ]]
                     then
                        runtime_constraints_met=0
                     fi

                     if [[ "${deploy_report_runtime_storage_min_mb}" -gt 0 && ( "${report_min_runtime_storage_mb}" -lt 0 || "${report_min_runtime_storage_mb}" -lt "${deploy_report_runtime_storage_min_mb}" ) ]]
                     then
                        runtime_constraints_met=0
                     fi

                     if [[ "${deploy_report_runtime_cores_max_min}" -gt 0 && "${report_max_runtime_cores}" -lt "${deploy_report_runtime_cores_max_min}" ]]
                     then
                        runtime_constraints_met=0
                     fi

                     if [[ "${deploy_report_runtime_memory_max_min_mb}" -gt 0 && "${report_max_runtime_memory_mb}" -lt "${deploy_report_runtime_memory_max_min_mb}" ]]
                     then
                        runtime_constraints_met=0
                     fi

                     if [[ "${deploy_report_runtime_storage_max_min_mb}" -gt 0 && "${report_max_runtime_storage_mb}" -lt "${deploy_report_runtime_storage_max_min_mb}" ]]
                     then
                        runtime_constraints_met=0
                     fi

                     if [[ "${healthy_constraints_met}" -eq 1 && "${target_constraints_met}" -eq 1 && "${shard_constraints_met}" -eq 1 && "${runtime_constraints_met}" -eq 1 ]]
                     then
                        report_now_ms=$(( $(date +%s%N) / 1000000 ))
                        if [[ "${report_stable_since_ms}" -eq 0 ]]
                        then
                           report_stable_since_ms="${report_now_ms}"
                        fi

                        report_elapsed_ms=$((report_now_ms - report_start_ms))
                        report_stable_ms=$((report_now_ms - report_stable_since_ms))
                        report_min_runtime_gate_ms=0
                        if [[ "${report_floor_constraints_requested}" -eq 1 ]]
                        then
                           report_min_runtime_gate_ms="${deploy_report_floor_min_runtime_ms}"
                        fi

                        if [[ "${report_elapsed_ms}" -ge "${report_min_runtime_gate_ms}" && "${report_stable_ms}" -ge "${deploy_report_success_hold_ms}" ]]
                        then
                           report_ok=1
                           break
                        fi
                     else
                        report_stable_since_ms=0
                     fi
                  else
                     report_stable_since_ms=0
                  fi

                  sleep "${deploy_report_poll_sleep_s}"
               done

               healthy_constraints_met=0
               target_constraints_met=0
               shard_constraints_met=1
               runtime_constraints_met=1

               if [[ "${report_max_healthy}" -ge "${deploy_report_min_healthy}" && "${report_max_healthy}" -ge "${deploy_report_max_healthy_min}" ]]
               then
                  if [[ "${deploy_report_final_healthy_max}" == "-1" || ( "${report_last_healthy}" -ge 0 && "${report_last_healthy}" -le "${deploy_report_final_healthy_max}" ) ]]
                  then
                     healthy_constraints_met=1
                  fi
               fi

               if [[ "${report_max_target}" -ge "${deploy_report_min_target}" && "${report_max_target}" -ge "${deploy_report_max_target_min}" ]]
               then
                  if [[ "${deploy_report_final_target_max}" == "-1" || ( "${report_last_target}" -ge 0 && "${report_last_target}" -le "${deploy_report_final_target_max}" ) ]]
                  then
                     target_constraints_met=1
                  fi
               fi

               if [[ "${report_max_shard_groups}" -lt "${deploy_report_min_shard_groups}" || "${report_max_shard_groups}" -lt "${deploy_report_max_shard_groups_min}" ]]
               then
                  shard_constraints_met=0
               fi

               if [[ "${deploy_report_final_shard_groups_max}" != "-1" && ( "${report_last_shard_groups}" -lt 0 || "${report_last_shard_groups}" -gt "${deploy_report_final_shard_groups_max}" ) ]]
               then
                  shard_constraints_met=0
               fi

               if [[ "${deploy_report_runtime_cores_min}" -gt 0 && ( "${report_min_runtime_cores}" -lt 0 || "${report_min_runtime_cores}" -lt "${deploy_report_runtime_cores_min}" ) ]]
               then
                  runtime_constraints_met=0
               fi

               if [[ "${deploy_report_runtime_memory_min_mb}" -gt 0 && ( "${report_min_runtime_memory_mb}" -lt 0 || "${report_min_runtime_memory_mb}" -lt "${deploy_report_runtime_memory_min_mb}" ) ]]
               then
                  runtime_constraints_met=0
               fi

               if [[ "${deploy_report_runtime_storage_min_mb}" -gt 0 && ( "${report_min_runtime_storage_mb}" -lt 0 || "${report_min_runtime_storage_mb}" -lt "${deploy_report_runtime_storage_min_mb}" ) ]]
               then
                  runtime_constraints_met=0
               fi

               if [[ "${deploy_report_runtime_cores_max_min}" -gt 0 && "${report_max_runtime_cores}" -lt "${deploy_report_runtime_cores_max_min}" ]]
               then
                  runtime_constraints_met=0
               fi

               if [[ "${deploy_report_runtime_memory_max_min_mb}" -gt 0 && "${report_max_runtime_memory_mb}" -lt "${deploy_report_runtime_memory_max_min_mb}" ]]
               then
                  runtime_constraints_met=0
               fi

               if [[ "${deploy_report_runtime_storage_max_min_mb}" -gt 0 && "${report_max_runtime_storage_mb}" -lt "${deploy_report_runtime_storage_max_min_mb}" ]]
               then
                  runtime_constraints_met=0
               fi

               if [[ "${healthy_constraints_met}" -eq 1 && "${target_constraints_met}" -eq 1 && "${shard_constraints_met}" -eq 1 && "${runtime_constraints_met}" -eq 1 ]]
               then
                  report_ok=1
               fi

               if [[ "${report_ok}" -ne 1 ]]
               then
                  if [[ "${report_timed_out}" -eq 1 ]]
                  then
                     echo "FAIL: deploy report checks exceeded timeout ${deploy_report_max_seconds}s"
                  fi
                  echo "FAIL: deployment report check failed for application=${deploy_report_application} versionID=${deploy_report_version_id} versionMin=${deploy_report_version_min} minHealthy=${deploy_report_min_healthy} maxHealthyMin=${deploy_report_max_healthy_min} finalHealthyMax=${deploy_report_final_healthy_max} minTarget=${deploy_report_min_target} maxTargetMin=${deploy_report_max_target_min} finalTargetMax=${deploy_report_final_target_max} minShardGroups=${deploy_report_min_shard_groups} maxShardGroupsMin=${deploy_report_max_shard_groups_min} finalShardGroupsMax=${deploy_report_final_shard_groups_max} runtimeMinCores=${deploy_report_runtime_cores_min} runtimeMinMemoryMB=${deploy_report_runtime_memory_min_mb} runtimeMinStorageMB=${deploy_report_runtime_storage_min_mb} runtimeMaxCoresMin=${deploy_report_runtime_cores_max_min} runtimeMaxMemoryMBMin=${deploy_report_runtime_memory_max_min_mb} runtimeMaxStorageMBMin=${deploy_report_runtime_storage_max_min_mb} observedMaxHealthy=${report_max_healthy} observedFinalHealthy=${report_last_healthy} observedMaxTarget=${report_max_target} observedFinalTarget=${report_last_target} observedMaxShardGroups=${report_max_shard_groups} observedFinalShardGroups=${report_last_shard_groups} observedRuntimeMinCores=${report_min_runtime_cores} observedRuntimeMinMemoryMB=${report_min_runtime_memory_mb} observedRuntimeMinStorageMB=${report_min_runtime_storage_mb} observedRuntimeMaxCores=${report_max_runtime_cores} observedRuntimeMaxMemoryMB=${report_max_runtime_memory_mb} observedRuntimeMaxStorageMB=${report_max_runtime_storage_mb}"
                  sed -n '1,220p' "${tmpdir}/mothership.applicationreport.log"
                  for idx in "${!brain_fs_roots[@]}"
                  do
                     brain_label="brain$((idx + 1))"
                     dump_brain_container_artifacts "${brain_label}" "${brain_fs_roots[$idx]}"
                     if log_path="$(brain_latest_stdout_log "$((idx + 1))" 2>/dev/null || true)" && [[ -n "${log_path}" && -f "${log_path}" ]]
                     then
                        echo "--- ${brain_label} stdout tail ---"
                        tail -n 200 "${log_path}" 2>/dev/null || true
                     fi
                  done
                  failed=1
               else
                  echo "DEPLOY_REPORT success application=${deploy_report_application} versionID=${deploy_report_version_id} versionMin=${deploy_report_version_min} minHealthy=${deploy_report_min_healthy} maxHealthyMin=${deploy_report_max_healthy_min} finalHealthyMax=${deploy_report_final_healthy_max} minTarget=${deploy_report_min_target} maxTargetMin=${deploy_report_max_target_min} finalTargetMax=${deploy_report_final_target_max} minShardGroups=${deploy_report_min_shard_groups} maxShardGroupsMin=${deploy_report_max_shard_groups_min} finalShardGroupsMax=${deploy_report_final_shard_groups_max} runtimeMinCores=${deploy_report_runtime_cores_min} runtimeMinMemoryMB=${deploy_report_runtime_memory_min_mb} runtimeMinStorageMB=${deploy_report_runtime_storage_min_mb} runtimeMaxCoresMin=${deploy_report_runtime_cores_max_min} runtimeMaxMemoryMBMin=${deploy_report_runtime_memory_max_min_mb} runtimeMaxStorageMBMin=${deploy_report_runtime_storage_max_min_mb} maxHealthy=${report_max_healthy} finalHealthy=${report_last_healthy} maxTarget=${report_max_target} finalTarget=${report_last_target} maxShardGroups=${report_max_shard_groups} finalShardGroups=${report_last_shard_groups} minRuntimeCores=${report_min_runtime_cores} minRuntimeMemoryMB=${report_min_runtime_memory_mb} minRuntimeStorageMB=${report_min_runtime_storage_mb} maxRuntimeCores=${report_max_runtime_cores} maxRuntimeMemoryMB=${report_max_runtime_memory_mb} maxRuntimeStorageMB=${report_max_runtime_storage_mb}"
               fi
            fi

            if [[ "${failed}" -eq 0 && "${deploy_skip_probe}" == "0" && "${deploy_skip_final_ping}" == "0" ]]
            then
               pingpong_ok=0
               if probe_deploy_ping_targets "${deploy_ping_attempts}"
               then
                  pingpong_ok=1
               fi

               if [[ "${pingpong_ok}" -ne 1 ]]
               then
                  echo "FAIL: deployed container did not answer ping-pong on port ${deploy_ping_port}"
                  for ip in "${assigned_brain_ips[@]}"
                  do
                     if probe_response="$(probe_pingpong_response_in_parent_ns "${ip}" "${deploy_ping_port}" "${deploy_ping_payload}")"
                     then
                        echo "DEPLOY_PINGPONG_DEBUG ip=${ip} got='${probe_response}' expected='${deploy_ping_expect}'"
                     else
                        echo "DEPLOY_PINGPONG_DEBUG ip=${ip} got='<no-response>' expected='${deploy_ping_expect}'"
                     fi

                     if stats_response="$(probe_pingpong_response_in_parent_ns "${ip}" "${deploy_ping_port}" "stats")"
                     then
                        echo "DEPLOY_PINGPONG_STATS ip=${ip} ${stats_response}"
                     else
                        echo "DEPLOY_PINGPONG_STATS ip=${ip} <no-response>"
                     fi
                  done
                  for ns in "${child_names[@]}"
                  do
                     echo "--- ${ns} listeners ---"
                     ip netns exec "${ns}" ss -ltn 2>/dev/null || true
                  done

                  for idx in "${!brain_fs_roots[@]}"
                  do
                     brain_label="brain$((idx + 1))"
                     dump_brain_container_artifacts "${brain_label}" "${brain_fs_roots[$idx]}"
                  done

                  sed -n '1,220p' "${tmpdir}/mothership.deploy.log"
                  failed=1
               else
                  if [[ "${deploy_ping_all}" == "1" ]]
                  then
                     echo "DEPLOY_PINGPONG success all_ips=${deploy_probe_success_ips} port=${deploy_ping_port} payload=${deploy_ping_payload} response=${deploy_ping_expect}"
                  else
                     echo "DEPLOY_PINGPONG success ip=${deploy_probe_success_ip} port=${deploy_ping_port} payload=${deploy_ping_payload} response=${deploy_ping_expect}"
                  fi

                  if [[ "${deploy_ping_emit_stats}" == "1" ]]
                  then
                     for ip in "${assigned_brain_ips[@]}"
                     do
                        if stats_response="$(probe_pingpong_response_in_parent_ns "${ip}" "${deploy_ping_port}" "stats")"
                        then
                           echo "DEPLOY_PINGPONG_STATS ip=${ip} ${stats_response}"
                        else
                           echo "DEPLOY_PINGPONG_STATS ip=${ip} <no-response>"
                        fi
                     done
                  fi
               fi
            elif [[ "${failed}" -eq 0 ]]
            then
               echo "DEPLOY_PINGPONG skipped deploy-skip-probe=1"
            fi

            if [[ "${failed}" -eq 0 && -n "${deploy_mesh_mode}" ]]
            then
               if probe_deploy_mesh_stats "${deploy_mesh_attempts}"
               then
                  require_all_text="0"
                  if [[ "${deploy_mesh_require_all}" == "1" ]]
                  then
                     require_all_text="1"
                  fi
                  echo "DEPLOY_MESH_STATS success mode=${deploy_mesh_mode} require_all=${require_all_text} validated_ips=${deploy_mesh_probe_success_ips}"
               else
                  echo "FAIL: mesh communication/bookkeeping probe failed mode=${deploy_mesh_mode} require_all=${deploy_mesh_require_all}"
                  if [[ -n "${deploy_mesh_probe_debug}" ]]
                  then
                     printf "%s" "${deploy_mesh_probe_debug}"
                  fi
                  failed=1
               fi
            fi

            if [[ "${failed}" -eq 0 ]]
            then
               snapshot_deploy_spin_counts
            fi
         fi
      fi
   fi
fi

if [[ "${brains}" == "3" && -n "${mothership_update_prodigy_input}" ]]
then
   if ! wait_for_full_peer_mesh 180
   then
      echo "FAIL: updateProdigy requires a full 3-brain peer mesh before dispatch"
      for ns in "${child_names[@]}"
      do
         established="$(count_established_peer_links_in_ns "${ns}")"
         echo "--- ${ns} sockets (peer_estab_313=${established}) ---"
         ip netns exec "${ns}" ss -tan 2>/dev/null || true
      done
      failed=1
   fi

if [[ "${failed}" -eq 0 ]]
then
   update_baseline_master_ns=""
   update_baseline_master_index=0
   update_baseline_quorum_indices=""
   update_baseline_quorum_count=0
   if update_baseline_quorum_indices="$(wait_for_single_quorum_master_indices_stable 120 5)"
   then
      update_baseline_quorum_count=1
      update_baseline_master_index="$(first_index_from_csv "${update_baseline_quorum_indices}" || true)"
      if [[ "${update_baseline_master_index}" -gt 0 ]]
      then
         update_baseline_master_ns="${child_names[$((update_baseline_master_index - 1))]}"
      fi
   elif update_baseline_quorum_indices="$(quorum_master_indices_once)"
   then
      update_baseline_quorum_count="$(csv_count_indices "${update_baseline_quorum_indices}")"
      update_baseline_master_index="$(first_index_from_csv "${update_baseline_quorum_indices}" || true)"
      if [[ "${update_baseline_master_index}" -gt 0 ]]
      then
         update_baseline_master_ns="${child_names[$((update_baseline_master_index - 1))]}"
      fi
   elif update_baseline_master_ns="$(wait_for_master_ns 120)"
   then
      update_baseline_master_index="$(ns_index "${update_baseline_master_ns}" || true)"
      update_baseline_quorum_indices=""
   fi

   if [[ "${update_baseline_quorum_count}" -gt 1 ]]
   then
      echo "FAIL: split-brain detected before updateProdigy (baseline_quorum=${update_baseline_quorum_indices})"
      failed=1
      update_baseline_master_ns=""
      update_baseline_master_index=0
   fi

   if [[ -z "${update_baseline_master_ns}" || "${update_baseline_master_index}" -le 0 ]]
   then
      echo "FAIL: unable to establish baseline master before mothership updateProdigy"
      failed=1
   else
      update_baseline_quorum_display="none"
      if [[ -n "${update_baseline_quorum_indices}" ]]
      then
         update_baseline_quorum_display="${update_baseline_quorum_indices}"
      fi

      echo "UPDATE_BASELINE master_ns=${update_baseline_master_ns} index=${update_baseline_master_index} quorum=${update_baseline_quorum_display}"
      echo "UPDATE_PLAN start=${mothership_update_start_s}s input=${mothership_update_prodigy_input}"

      if [[ "${mothership_update_start_s}" -gt 0 ]]
      then
         sleep "${mothership_update_start_s}"
      fi

      update_ns="${update_baseline_master_ns}"
      update_listener_ready=0
      for attempt in $(seq 1 80)
      do
         for ns in "${child_names[@]}"
         do
            if master_listener_in_ns "${ns}"
            then
               update_ns="${ns}"
               update_listener_ready=1
               break
            fi
         done

         if [[ "${update_listener_ready}" -eq 1 ]]
         then
            break
         fi

         sleep 0.2
      done

      if [[ "${update_listener_ready}" -ne 1 ]]
      then
         echo "FAIL: mothership updateProdigy could not locate active master listener"
         for ns in "${child_names[@]}"
         do
            dump_master_listener_state "${ns}"
         done
         failed=1
      elif timeout --preserve-status -k 3s 8s \
         ip netns exec "${update_ns}" \
         env PRODIGY_STATE_DB=/containers/var/lib/prodigy/state PRODIGY_MOTHERSHIP_SOCKET="${mothership_socket_path}" "${mothership_bin}" updateProdigy local "${mothership_update_prodigy_input}" \
         >"${tmpdir}/mothership.updateProdigy.log" 2>&1
      then
         echo "UPDATE_TRIGGERED ns=${update_ns} baseline_index=${update_baseline_master_index}"
      else
         echo "FAIL: mothership updateProdigy dispatch failed"
         sed -n '1,160p' "${tmpdir}/mothership.updateProdigy.log"
         failed=1
      fi

      if [[ "${failed}" -eq 0 ]]
      then
         update_dispatch_index="$(ns_index "${update_ns}" || true)"
         if [[ "${update_dispatch_index}" -le 0 ]]
         then
            echo "FAIL: unable to resolve dispatched update namespace index"
            failed=1
         elif [[ "${update_dispatch_index}" != "${update_baseline_master_index}" ]]
         then
            echo "FAIL: updateProdigy dispatch listener drifted from baseline master (baseline=${update_baseline_master_index}, dispatch=${update_dispatch_index})"
            failed=1
         fi

         update_expected_bundle_path="$(resolve_update_prodigy_bundle_path "${mothership_update_prodigy_input}")"
         if [[ ! -f "${update_expected_bundle_path}" ]]
         then
            echo "FAIL: resolved updateProdigy bundle does not exist: ${update_expected_bundle_path}"
            failed=1
         fi

         update_expected_bundle_bytes="$(stat -Lc '%s' "${update_expected_bundle_path}" 2>/dev/null || printf '0')"
         update_expected_bundle_sha256="$(sha256sum "${update_expected_bundle_path}" 2>/dev/null | awk '{print $1}' || true)"
         update_dispatched_line="$(rg -m1 --fixed-strings "updateProdigy dispatched:" "${tmpdir}/mothership.updateProdigy.log" || true)"
         if [[ -z "${update_dispatched_line}" ]]
         then
            echo "FAIL: mothership updateProdigy log is missing dispatched bundle metadata"
            failed=1
         else
            update_dispatched_bundle_bytes=0
            update_dispatched_bundle_path=""
            update_dispatched_bundle_sha256=""
            if [[ "${update_dispatched_line}" =~ bytes=([0-9]+)[[:space:]]path=([^[:space:]]+)[[:space:]]sha256=([0-9a-f]+)$ ]]
            then
               update_dispatched_bundle_bytes="${BASH_REMATCH[1]}"
               update_dispatched_bundle_path="${BASH_REMATCH[2]}"
               update_dispatched_bundle_sha256="${BASH_REMATCH[3]}"
            else
               echo "FAIL: mothership updateProdigy dispatched line could not be parsed: ${update_dispatched_line}"
               failed=1
            fi

            if [[ "${failed}" -eq 0 ]]
            then
               if [[ "${update_dispatched_bundle_bytes}" != "${update_expected_bundle_bytes}" ]]
               then
                  echo "FAIL: mothership updateProdigy payload byte mismatch (expected=${update_expected_bundle_bytes}, sent=${update_dispatched_bundle_bytes})"
                  failed=1
               fi

               if [[ "${update_dispatched_bundle_path}" != "${update_expected_bundle_path}" ]]
               then
                  echo "FAIL: mothership updateProdigy payload path mismatch (expected=${update_expected_bundle_path}, sent=${update_dispatched_bundle_path})"
                  failed=1
               fi

               if [[ "${update_dispatched_bundle_sha256}" != "${update_expected_bundle_sha256}" ]]
               then
                  echo "FAIL: mothership updateProdigy payload sha256 mismatch (expected=${update_expected_bundle_sha256}, sent=${update_dispatched_bundle_sha256})"
                  failed=1
               fi
            fi
         fi

         if [[ "${failed}" -eq 0 ]]
         then
            echo "UPDATE_BUNDLE bytes=${update_expected_bundle_bytes} path=${update_expected_bundle_path} sha256=${update_expected_bundle_sha256}"
         fi

         if [[ "${failed}" -eq 0 ]]
         then
            update_expected_peer_echos=$((brains - 1))
            update_coordinator_log=""
            if ! update_coordinator_log="$(brain_latest_stdout_log "${update_dispatch_index}")"
            then
               echo "FAIL: updateProdigy order proof missing coordinator brain log for index ${update_dispatch_index}"
               failed=1
            elif ! verify_update_prodigy_sequence "${update_coordinator_log}" "${update_expected_peer_echos}"
            then
               echo "--- coordinator update log (${update_coordinator_log}) ---"
               sed -n '1,200p' "${update_coordinator_log}"
               failed=1
            fi
         fi

         update_phase_attempts=$((post_fault_window_s * 5))
         if [[ "${update_phase_attempts}" -lt 1 ]]
         then
            update_phase_attempts=1
         fi

         update_phase_listener_indices="none"
         update_phase_quorum_indices="none"
         update_phase_changed=0
         update_phase_split_brain=0
         update_phase_split_quorum_indices="none"
         for attempt in $(seq 1 "${update_phase_attempts}")
         do
            listener_indices=""
            if listener_indices="$(master_listener_indices_once)"
            then
               update_phase_listener_indices="${listener_indices}"
            fi

            quorum_indices=""
            if quorum_indices="$(quorum_master_indices_once)"
            then
               quorum_count="$(csv_count_indices "${quorum_indices}")"
               update_phase_quorum_indices="${quorum_indices}"
               if [[ "${quorum_count}" -gt 1 ]]
               then
                  update_phase_split_brain=1
                  update_phase_split_quorum_indices="${quorum_indices}"
               elif [[ "${quorum_count}" -eq 1 ]] && csv_has_other_than "${quorum_indices}" "${update_baseline_master_index}"
               then
                  update_phase_changed=1
               fi
            fi

            sleep 0.2
         done

         echo "UPDATE_PHASE listeners=${update_phase_listener_indices} quorum=${update_phase_quorum_indices} changed=${update_phase_changed}"

         if [[ "${expect_master_change_during_fault}" == "1" ]]
         then
            if [[ "${update_phase_changed}" -ne 1 ]]
            then
               echo "FAIL: expected master change during updateProdigy (baseline=${update_baseline_master_index}, quorum_seen=${update_phase_quorum_indices})"
               failed=1
            fi
         elif [[ "${expect_master_change_during_fault}" == "0" ]]
         then
            if [[ "${update_phase_changed}" -ne 0 ]]
            then
               echo "FAIL: expected no master change during updateProdigy (baseline=${update_baseline_master_index}, quorum_seen=${update_phase_quorum_indices})"
               failed=1
            fi
         fi

         update_post_attempts=$((post_fault_window_s * 5))
         if [[ "${update_post_attempts}" -lt 1 ]]
         then
            update_post_attempts=1
         fi

         update_final_quorum_indices=""
         update_final_master_ns=""
         update_final_master_index=0
         update_final_quorum_count=0
         if update_final_quorum_indices="$(wait_for_single_quorum_master_indices_stable "${update_post_attempts}" 10)"
         then
            update_final_quorum_count=1
            update_final_master_index="$(first_index_from_csv "${update_final_quorum_indices}" || true)"
            if [[ "${update_final_master_index}" -gt 0 ]]
            then
               update_final_master_ns="${child_names[$((update_final_master_index - 1))]}"
            fi
         elif update_final_quorum_indices="$(quorum_master_indices_once)"
         then
            update_final_quorum_count="$(csv_count_indices "${update_final_quorum_indices}")"
         fi

         if [[ "${update_final_quorum_count}" -gt 1 ]]
         then
            update_filtered_quorum_indices="$(filter_quorum_indices_by_cluster_report "${update_final_quorum_indices}")"
            if [[ "${update_filtered_quorum_indices}" != "${update_final_quorum_indices}" ]]
            then
               update_final_quorum_indices="${update_filtered_quorum_indices}"
               update_final_quorum_count="$(csv_count_indices "${update_final_quorum_indices}")"
               if [[ "${update_final_quorum_count}" -eq 1 ]]
               then
                  update_final_master_index="$(first_index_from_csv "${update_final_quorum_indices}" || true)"
                  if [[ "${update_final_master_index}" -gt 0 ]]
                  then
                     update_final_master_ns="${child_names[$((update_final_master_index - 1))]}"
                  fi
               fi
            fi
         fi

         update_final_listener_indices="none"
         listener_indices=""
         if listener_indices="$(master_listener_indices_once)"
         then
            update_final_listener_indices="${listener_indices}"
         fi

         if [[ -n "${update_final_master_ns}" ]]
         then
            echo "UPDATE_RESULT master_ns=${update_final_master_ns} index=${update_final_master_index} listeners=${update_final_listener_indices} quorum=${update_final_quorum_indices}"
         else
            update_quorum_display="none"
            if [[ -n "${update_final_quorum_indices}" ]]
            then
               update_quorum_display="${update_final_quorum_indices}"
            fi
            echo "UPDATE_RESULT master_ns=none index=0 listeners=${update_final_listener_indices} quorum=${update_quorum_display}"
         fi

         if [[ "${expect_master_available}" == "1" ]]
         then
            if [[ "${update_final_quorum_count}" -eq 0 ]]
            then
               echo "FAIL: expected a quorum master after updateProdigy, but none was found"
               failed=1
            elif [[ "${update_final_quorum_count}" -gt 1 ]]
            then
               echo "FAIL: split-brain after updateProdigy (quorum=${update_final_quorum_indices})"
               failed=1
            fi
         elif [[ "${expect_master_available}" == "0" ]]
         then
            if ! wait_for_no_quorum_master_stable "${update_post_attempts}" 10
            then
               echo "FAIL: expected no quorum master after updateProdigy, but one remained available"
               for ns in "${child_names[@]}"
               do
                  established="$(count_established_peer_links_in_ns "${ns}")"
                  echo "--- ${ns} listeners (peer_estab_313=${established}) ---"
                  ip netns exec "${ns}" ss -ltn 2>/dev/null || true
               done
               failed=1
            fi
         fi

         update_final_master_changed=0
         if [[ "${update_final_quorum_count}" -eq 1 ]] && [[ "${update_final_master_index}" -gt 0 ]] && [[ "${update_final_master_index}" != "${update_baseline_master_index}" ]]
         then
            update_final_master_changed=1
         fi

         if [[ "${expect_master_change}" == "1" ]]
         then
            if [[ "${update_final_quorum_count}" -ne 1 || "${update_final_master_changed}" -ne 1 ]]
            then
               echo "FAIL: expected master change after updateProdigy (baseline=${update_baseline_master_index}, final_quorum=${update_final_quorum_indices:-none})"
               failed=1
            fi
         elif [[ "${expect_master_change}" == "0" ]]
         then
            if [[ "${update_final_quorum_count}" -gt 1 ]]
            then
               echo "FAIL: split-brain is incompatible with stable master after updateProdigy (baseline=${update_baseline_master_index}, final_quorum=${update_final_quorum_indices})"
               failed=1
            elif [[ "${update_final_quorum_count}" -eq 1 ]] && [[ "${update_final_master_index}" != "${update_baseline_master_index}" ]]
            then
               echo "FAIL: expected master to remain stable after updateProdigy (baseline=${update_baseline_master_index}, final_quorum=${update_final_quorum_indices})"
               failed=1
            fi
         fi

         if [[ "${expect_peer_recovery}" == "1" ]]
         then
            if ! wait_for_full_peer_mesh "${update_post_attempts}"
            then
               echo "FAIL: expected peer mesh to recover after updateProdigy"
               for ns in "${child_names[@]}"
               do
                  echo "--- ${ns} sockets ---"
                  ip netns exec "${ns}" ss -tan 2>/dev/null || true
               done
               failed=1
            fi
         fi
      fi
   fi
fi
fi

if [[ "${brains}" == "3" && -n "${fault_targets}" ]]
then
   baseline_master_ns=""
   baseline_master_index=0
   baseline_quorum_indices=""
   baseline_quorum_count=0
   baseline_split_brain=0
   for baseline_attempt in 1 2
   do
      baseline_master_ns=""
      baseline_master_index=0
      baseline_quorum_indices=""
      baseline_quorum_count=0

      if baseline_quorum_indices="$(wait_for_single_quorum_master_indices_stable 120 5)"
      then
         baseline_quorum_count=1
         baseline_master_index="$(first_index_from_csv "${baseline_quorum_indices}" || true)"
         if [[ "${baseline_master_index}" -gt 0 ]]
         then
            baseline_master_ns="${child_names[$((baseline_master_index - 1))]}"
         fi
      elif baseline_quorum_indices="$(quorum_master_indices_once)"
      then
         baseline_quorum_count="$(csv_count_indices "${baseline_quorum_indices}")"
         baseline_master_index="$(first_index_from_csv "${baseline_quorum_indices}" || true)"
         if [[ "${baseline_master_index}" -gt 0 ]]
         then
            baseline_master_ns="${child_names[$((baseline_master_index - 1))]}"
         fi
      elif baseline_master_ns="$(wait_for_master_ns 120)"
      then
         baseline_master_index="$(ns_index "${baseline_master_ns}" || true)"
         baseline_quorum_indices=""
      fi

      if [[ "${baseline_quorum_count}" -gt 1 ]]
      then
         baseline_split_brain=1
         break
      fi

      if [[ -n "${baseline_master_ns}" && "${baseline_master_index}" -gt 0 ]]
      then
         break
      fi

      if [[ "${baseline_attempt}" -lt 2 ]]
      then
         sleep 3
      fi
   done

   if [[ "${baseline_split_brain}" -eq 1 ]]
   then
      echo "FAIL: split-brain detected before fault injection (baseline_quorum=${baseline_quorum_indices})"
      failed=1
      baseline_master_ns=""
      baseline_master_index=0
   fi

   if [[ -z "${baseline_master_ns}" || "${baseline_master_index}" -le 0 ]]
   then
      echo "FAIL: unable to establish baseline master before fault injection"
      failed=1
   else
	      resolved_fault_targets=""
	      if ! resolved_fault_targets="$(resolve_fault_targets "${baseline_master_index}" "${fault_targets}")"
	      then
	         failed=1
	      elif [[ ! "${resolved_fault_targets}" =~ ^[0-9]+(,[0-9]+)*$ ]]
	      then
	         echo "FAIL: --fault-targets resolved invalid value '${resolved_fault_targets}'"
	         failed=1
	      else
	         baseline_quorum_display="none"
	         if [[ -n "${baseline_quorum_indices}" ]]
         then
            baseline_quorum_display="${baseline_quorum_indices}"
         fi

         echo "FAULT_BASELINE master_ns=${baseline_master_ns} index=${baseline_master_index} quorum=${baseline_quorum_display}"
         echo "FAULT_PLAN mode=${fault_mode} targets=${resolved_fault_targets} start=${fault_start_s}s duration=${fault_duration_s}s cycles=${fault_cycles} down=${fault_down_s}s up=${fault_up_s}s"

         if [[ "${fault_start_on_ready}" == "1" ]]
         then
            echo "FAULT_START trigger=ready sleep=0s"
         elif [[ "${fault_start_s}" -gt 0 ]]
         then
            sleep "${fault_start_s}"
         fi

         fault_phase_listener_indices="none"
         fault_phase_quorum_indices="none"
         fault_phase_changed=0
         fault_phase_split_brain=0
         fault_phase_split_quorum_indices="none"

         if [[ "${fault_mode}" == "link" ]]
         then
            set_fault_links_state "${resolved_fault_targets}" down
            echo "FAULT_APPLIED mode=link targets=${resolved_fault_targets} state=down"

            fault_phase_attempts=$((post_fault_window_s * 5))
            if [[ "${fault_duration_s}" -gt 0 ]]
            then
               fault_phase_attempts=$((fault_duration_s * 5))
            fi
            if [[ "${fault_phase_attempts}" -lt 1 ]]
            then
               fault_phase_attempts=1
            fi

            for attempt in $(seq 1 "${fault_phase_attempts}")
            do
               record_fault_phase_sample "${baseline_master_index}"
               sleep 0.2
            done

            if [[ "${fault_duration_s}" -gt 0 ]]
            then
               set_fault_links_state "${resolved_fault_targets}" up
               echo "FAULT_APPLIED mode=link targets=${resolved_fault_targets} state=up"
            fi
         elif [[ "${fault_mode}" == "crash" ]]
         then
            kill_fault_target_brains "${resolved_fault_targets}"
            echo "FAULT_APPLIED mode=crash targets=${resolved_fault_targets} state=crashed"

            fault_phase_attempts=$((post_fault_window_s * 5))
            if [[ "${fault_duration_s}" -gt 0 ]]
            then
               fault_phase_attempts=$((fault_duration_s * 5))
            fi
            if [[ "${fault_phase_attempts}" -lt 1 ]]
            then
               fault_phase_attempts=1
            fi

            for attempt in $(seq 1 "${fault_phase_attempts}")
            do
               record_fault_phase_sample "${baseline_master_index}"
               sleep 0.2
            done

            if [[ "${fault_duration_s}" -gt 0 ]]
            then
               restart_fault_target_brains "${resolved_fault_targets}"
               echo "FAULT_APPLIED mode=crash targets=${resolved_fault_targets} state=restarted"
            fi
         else
            for cycle in $(seq 1 "${fault_cycles}")
            do
               set_fault_links_state "${resolved_fault_targets}" down
               echo "FAULT_APPLIED mode=flap cycle=${cycle}/${fault_cycles} targets=${resolved_fault_targets} state=down"

               down_attempts=$((fault_down_s * 5))
               if [[ "${down_attempts}" -lt 1 ]]
               then
                  down_attempts=1
               fi
               for attempt in $(seq 1 "${down_attempts}")
               do
                  record_fault_phase_sample "${baseline_master_index}"
                  sleep 0.2
               done

               set_fault_links_state "${resolved_fault_targets}" up
               echo "FAULT_APPLIED mode=flap cycle=${cycle}/${fault_cycles} targets=${resolved_fault_targets} state=up"

               up_attempts=$((fault_up_s * 5))
               if [[ "${up_attempts}" -lt 1 ]]
               then
                  up_attempts=1
               fi
               for attempt in $(seq 1 "${up_attempts}")
               do
                  record_fault_phase_sample "${baseline_master_index}"
                  sleep 0.2
               done
            done
         fi

         echo "FAULT_PHASE listeners=${fault_phase_listener_indices} quorum=${fault_phase_quorum_indices} changed=${fault_phase_changed}"

         if [[ "${expect_master_change_during_fault}" == "1" ]]
         then
            if [[ "${fault_phase_changed}" -ne 1 ]]
            then
               echo "FAIL: expected master change during fault (baseline=${baseline_master_index}, quorum_seen=${fault_phase_quorum_indices})"
               failed=1
            fi
         elif [[ "${expect_master_change_during_fault}" == "0" ]]
         then
            if [[ "${fault_phase_changed}" -ne 0 ]]
            then
               echo "FAIL: expected no master change during fault (baseline=${baseline_master_index}, quorum_seen=${fault_phase_quorum_indices})"
               failed=1
            fi
         fi

         post_fault_attempts=$((post_fault_window_s * 5))
         if [[ "${post_fault_attempts}" -lt 1 ]]
         then
            post_fault_attempts=1
         fi

         final_listener_indices="none"
         listener_indices=""
         if listener_indices="$(master_listener_indices_once)"
         then
            final_listener_indices="${listener_indices}"
         fi

         final_quorum_indices=""
         final_master_ns=""
         final_master_index=0
         final_quorum_count=0
         if final_quorum_indices="$(wait_for_single_quorum_master_indices_stable "${post_fault_attempts}" 10)"
         then
            final_quorum_count=1
            final_master_index="$(first_index_from_csv "${final_quorum_indices}" || true)"
            if [[ "${final_master_index}" -gt 0 ]]
            then
               final_master_ns="${child_names[$((final_master_index - 1))]}"
            fi
         elif final_quorum_indices="$(quorum_master_indices_once)"
         then
            final_quorum_count="$(csv_count_indices "${final_quorum_indices}")"
         fi

         if [[ "${final_quorum_count}" -gt 1 ]]
         then
            filtered_quorum_indices="$(filter_quorum_indices_by_cluster_report "${final_quorum_indices}")"
            if [[ "${filtered_quorum_indices}" != "${final_quorum_indices}" ]]
            then
               final_quorum_indices="${filtered_quorum_indices}"
               final_quorum_count="$(csv_count_indices "${final_quorum_indices}")"
               if [[ "${final_quorum_count}" -eq 1 ]]
               then
                  final_master_index="$(first_index_from_csv "${final_quorum_indices}" || true)"
                  if [[ "${final_master_index}" -gt 0 ]]
                  then
                     final_master_ns="${child_names[$((final_master_index - 1))]}"
                  fi
               fi
            fi
         fi

         listener_indices=""
         if listener_indices="$(master_listener_indices_once)"
         then
            final_listener_indices="${listener_indices}"
         else
            final_listener_indices="none"
         fi

         if [[ -n "${final_master_ns}" ]]
         then
            echo "FAULT_RESULT master_ns=${final_master_ns} index=${final_master_index} listeners=${final_listener_indices} quorum=${final_quorum_indices}"
         else
            fault_quorum_display="none"
            if [[ -n "${final_quorum_indices}" ]]
            then
               fault_quorum_display="${final_quorum_indices}"
            fi
            echo "FAULT_RESULT master_ns=none index=0 listeners=${final_listener_indices} quorum=${fault_quorum_display}"
         fi

         if [[ "${expect_master_available}" == "1" ]]
         then
            if [[ "${final_quorum_count}" -eq 0 ]]
            then
               echo "FAIL: expected a quorum master after fault, but none was found"
               failed=1
            elif [[ "${final_quorum_count}" -gt 1 ]]
            then
               echo "FAIL: split-brain after fault (quorum=${final_quorum_indices})"
               for ns in "${child_names[@]}"
               do
                  established="$(count_established_peer_links_in_ns "${ns}")"
                  neurons_established="$(count_established_neuron_links_in_ns "${ns}")"
                  echo "--- ${ns} listeners (peer_estab_313=${established} neuron_estab_312=${neurons_established}) ---"
                  ip netns exec "${ns}" ss -ltn 2>/dev/null || true
               done
               failed=1
            fi
         elif [[ "${expect_master_available}" == "0" ]]
         then
            if ! wait_for_no_quorum_master_stable "${post_fault_attempts}" 10
            then
               echo "FAIL: expected no quorum master after fault, but one remained available"
               for ns in "${child_names[@]}"
               do
                  established="$(count_established_peer_links_in_ns "${ns}")"
                  echo "--- ${ns} listeners (peer_estab_313=${established}) ---"
                  ip netns exec "${ns}" ss -ltn 2>/dev/null || true
               done
               failed=1
            fi
         fi

         final_master_changed=0
         if [[ "${final_quorum_count}" -eq 1 ]] && [[ "${final_master_index}" -gt 0 ]] && [[ "${final_master_index}" != "${baseline_master_index}" ]]
         then
            final_master_changed=1
         fi

         if [[ "${expect_master_change}" == "1" ]]
         then
            if [[ "${final_quorum_count}" -ne 1 || "${final_master_changed}" -ne 1 ]]
            then
               echo "FAIL: expected master change after fault (baseline=${baseline_master_index}, final_quorum=${final_quorum_indices:-none})"
               failed=1
            fi
         elif [[ "${expect_master_change}" == "0" ]]
         then
            if [[ "${final_quorum_count}" -gt 1 ]]
            then
               echo "FAIL: split-brain is incompatible with stable master after fault (baseline=${baseline_master_index}, final_quorum=${final_quorum_indices})"
               failed=1
            elif [[ "${final_quorum_count}" -eq 1 ]] && [[ "${final_master_index}" != "${baseline_master_index}" ]]
            then
               echo "FAIL: expected master to remain stable after fault (baseline=${baseline_master_index}, final_quorum=${final_quorum_indices})"
               failed=1
            fi
         fi

         if [[ "${expect_peer_recovery}" == "1" ]]
         then
            peer_recovery_excluded_targets=""
            if [[ "${fault_mode}" == "crash" && "${fault_duration_s}" -le 0 ]]
            then
               peer_recovery_excluded_targets="${resolved_fault_targets}"
            fi

            if ! wait_for_peer_mesh "${post_fault_attempts}" "${peer_recovery_excluded_targets}" "1"
            then
               echo "FAIL: expected peer mesh to recover after fault"
               for ns in "${child_names[@]}"
               do
                  echo "--- ${ns} sockets ---"
                  ip netns exec "${ns}" ss -tan 2>/dev/null || true
               done
               failed=1
            fi
         fi

         if [[ "${deploy_ping_after_fault}" == "1" && "${failed}" -eq 0 && "${deploy_skip_probe}" == "0" && "${deploy_ping_port}" -gt 0 ]]
         then
            if probe_deploy_ping_targets "${post_fault_attempts}"
            then
               if [[ "${deploy_ping_all}" == "1" ]]
               then
                  echo "POST_FAULT_DEPLOY_PING success all_ips=${deploy_probe_success_ips} port=${deploy_ping_port} payload=${deploy_ping_payload} response=${deploy_ping_expect}"
               else
                  echo "POST_FAULT_DEPLOY_PING success ip=${deploy_probe_success_ip} port=${deploy_ping_port} payload=${deploy_ping_payload} response=${deploy_ping_expect}"
               fi

               if [[ "${deploy_ping_emit_stats}" == "1" ]]
               then
                  for ip in "${assigned_brain_ips[@]}"
                  do
                     if stats_response="$(probe_pingpong_response_in_parent_ns "${ip}" "${deploy_ping_port}" "stats")"
                     then
                        echo "POST_FAULT_DEPLOY_PING_STATS ip=${ip} ${stats_response}"
                     else
                        echo "POST_FAULT_DEPLOY_PING_STATS ip=${ip} <no-response>"
                     fi
                  done
               fi
            else
               echo "FAIL: post-fault deployment probe did not recover on port ${deploy_ping_port}"
               for ip in "${assigned_brain_ips[@]}"
               do
                  if probe_response="$(probe_pingpong_response_in_parent_ns "${ip}" "${deploy_ping_port}" "${deploy_ping_payload}")"
                  then
                     echo "POST_FAULT_DEPLOY_PING_DEBUG ip=${ip} got='${probe_response}' expected='${deploy_ping_expect}'"
                  else
                     echo "POST_FAULT_DEPLOY_PING_DEBUG ip=${ip} got='<no-response>' expected='${deploy_ping_expect}'"
                  fi

                  if stats_response="$(probe_pingpong_response_in_parent_ns "${ip}" "${deploy_ping_port}" "stats")"
                  then
                     echo "POST_FAULT_DEPLOY_PING_STATS ip=${ip} ${stats_response}"
                  else
                     echo "POST_FAULT_DEPLOY_PING_STATS ip=${ip} <no-response>"
                  fi
               done
               for ns in "${child_names[@]}"
               do
                  echo "--- ${ns} listeners ---"
                  ip netns exec "${ns}" ss -ltn 2>/dev/null || true
               done
               failed=1
            fi
         fi
      fi
   fi
fi

if [[ "${failed}" -eq 0 && "${#require_brain_log_substrings[@]}" -gt 0 ]]
then
   require_log_attempts="${PRODIGY_DEV_REQUIRE_BRAIN_LOG_ATTEMPTS:-${deploy_ping_attempts}}"
   if ! [[ "${require_log_attempts}" =~ ^[0-9]+$ ]] || [[ "${require_log_attempts}" -le 0 ]]
   then
      require_log_attempts=1
   fi

   for required_substring in "${require_brain_log_substrings[@]}"
   do
      require_log_found=0
      for _ in $(seq 1 "${require_log_attempts}")
      do
         if brain_logs_contain_substring "${required_substring}" || container_traces_contain_substring "${required_substring}"
         then
            require_log_found=1
            break
         fi

         sleep 0.2
      done

      if [[ "${require_log_found}" -eq 1 ]]
      then
         echo "BRAIN_LOG_ASSERT success substring='${required_substring}'"
         continue
      fi

      echo "FAIL: required brain log substring not found: ${required_substring}"
      for idx in $(seq 1 "${brains}")
      do
         if log_path="$(brain_latest_stdout_log "${idx}" 2>/dev/null || true)" && [[ -n "${log_path}" && -f "${log_path}" ]]
         then
            echo "--- ${log_path} ---"
            sed -n '1,120p' "${log_path}"
         fi
      done

      for root in "${brain_fs_roots[@]}"
      do
         if [[ -z "${root}" || ! -d "${root}" ]]
         then
            continue
         fi

         while IFS= read -r trace_file
         do
            if [[ -z "${trace_file}" || ! -f "${trace_file}" ]]
            then
               continue
            fi

            echo "--- ${trace_file} ---"
            sed -n '1,200p' "${trace_file}" 2>/dev/null || true
         done < <(find "${root}" -maxdepth 6 -type f -name "pulse_battery_probe.trace.log" 2>/dev/null | sort)
      done
      failed=1
      break
   done
fi

if [[ "${failed}" -ne 0 ]]
then
   dump_fake_ipv4_path_diagnostics || true
fi

terminate_all_brains

set +e
for i in "${!pids[@]}"
do
   wait "${pids[$i]}"
   status_codes[$i]=$?
done
set -e

for i in "${!pids[@]}"
do
   pid="${pids[$i]}"
   status="${status_codes[$i]:-0}"

   if [[ "${status}" -eq 0 ]]
   then
      continue
   fi

   if [[ -n "${expected_nonzero_pid[$pid]+x}" ]]
   then
      continue
   fi

   logfile="${pid_log_by_pid[$pid]:-}"
   echo "FAIL: brain process pid=${pid} returned ${status}"
   if [[ -n "${logfile}" && -f "${logfile}" ]]
   then
      sed -n '1,120p' "${logfile}"
   fi
   failed=1
done

if [[ "${failed}" -ne 0 ]]
then
   exit 1
fi

if [[ "${brains}" == "1" ]]
then
   echo "PASS: parent netns + 1 child brain completed"
else
   echo "PASS: parent netns + 3 child brains completed"
fi
