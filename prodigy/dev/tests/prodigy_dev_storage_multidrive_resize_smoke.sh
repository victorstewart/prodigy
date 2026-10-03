#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
PINGPONG_BIN="${3:-}"
test_mode="${4:-resize}"
storage_devices="${5:-2}"
upgrade_bundle="${6:-}"
case "${test_mode}" in
   resize) host_network=true ;;
   mount-only) host_network=false ;;
   legacy-handoff|legacy-recovery|legacy-recovery-zero|initial-health-zero|provider-handoff|bootstrap-supersession|follower-retained) host_network=false ;;
   *) echo "error: expected resize, mount-only, legacy-handoff, legacy-recovery, legacy-recovery-zero, initial-health-zero, provider-handoff, bootstrap-supersession or follower-retained mode" >&2; exit 2 ;;
esac
is_handoff=0
[[ "${test_mode}" != legacy-handoff && "${test_mode}" != legacy-recovery && "${test_mode}" != legacy-recovery-zero && "${test_mode}" != initial-health-zero && "${test_mode}" != provider-handoff && "${test_mode}" != bootstrap-supersession && "${test_mode}" != follower-retained ]] || is_handoff=1
[[ "${storage_devices}" == 0 || "${storage_devices}" == 2 ]] || { echo "error: expected zero or two storage devices" >&2; exit 2; }
[[ "${test_mode}" != resize || "${storage_devices}" == 2 ]] || { echo "error: resize requires two storage devices" >&2; exit 2; }
[[ "${is_handoff}" == 0 || "${storage_devices}" == 0 ]] || { echo "error: legacy handoff requires zero storage devices" >&2; exit 2; }
[[ "${test_mode}" == initial-health-zero || "${is_handoff}" == 0 || -s "${upgrade_bundle}" ]] || { echo "error: handoff update modes require an exact upgrade bundle" >&2; exit 2; }
[[ "${is_handoff}" == 0 || "${PRODIGY_STORAGE_HANDOFF_EXPECTED_RUNTIME_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || { echo "error: legacy handoff requires the sealed successor runtime hash" >&2; exit 2; }
if [[ "${test_mode}" == provider-handoff || "${test_mode}" == bootstrap-supersession || "${test_mode}" == follower-retained ]]; then
   old_bundle_sha="${PRODIGY_STORAGE_HANDOFF_EXPECTED_OLD_BUNDLE_SHA256:-}"
   [[ "${old_bundle_sha}" =~ ^[0-9a-f]{64}$ ]] || { echo "error: handoff mode requires sealed old bundle SHA" >&2; exit 2; }
   if [[ "${test_mode}" != follower-retained ]]; then
      create_mothership_bin="${PRODIGY_STORAGE_HANDOFF_CREATE_MOTHERSHIP_BIN:-}"
      [[ -x "${create_mothership_bin}" ]] || { echo "error: handoff mode requires executable sealed predecessor Mothership" >&2; exit 2; }
   fi
fi
if [[ "${test_mode}" == follower-retained ]]; then
   old_runtime_sha="${PRODIGY_STORAGE_HANDOFF_EXPECTED_OLD_RUNTIME_SHA256:-}"
   follower_fault_after_phase="${PRODIGY_STORAGE_HANDOFF_FAULT_AFTER_PHASE:-}"
   [[ "${old_runtime_sha}" =~ ^[0-9a-f]{64}$ ]] || { echo "error: follower-retained requires sealed old Prodigy executable SHA" >&2; exit 2; }
   case "${follower_fault_after_phase}" in
      ""|frozen|rootInstalled|workerReplaced) ;;
      *) echo "error: follower-retained fault phase must be frozen, rootInstalled, or workerReplaced" >&2; exit 2 ;;
   esac
   initial_bundle="${PRODIGY_STORAGE_HANDOFF_INITIAL_BUNDLE:-}"
   command -v sha256sum >/dev/null 2>&1 || { echo "error: follower-retained requires sha256sum" >&2; exit 2; }
   [[ -s "${initial_bundle}" && "$(sha256sum "${initial_bundle}" | awk '{print $1}')" == "${old_bundle_sha}" ]] || { echo "error: follower-retained requires the sealed old initial bundle" >&2; exit 2; }
fi
[[ "${test_mode}" == follower-retained || -z "${PRODIGY_STORAGE_HANDOFF_FAULT_AFTER_PHASE:-}" ]] || {
   echo "error: PRODIGY_STORAGE_HANDOFF_FAULT_AFTER_PHASE is follower-retained only" >&2; exit 2;
}
if [[ "${test_mode}" == bootstrap-supersession ]]; then
   interrupted_bundle="${PRODIGY_STORAGE_HANDOFF_INTERRUPTED_BUNDLE:-}"
   interrupted_bundle_sha="${PRODIGY_STORAGE_HANDOFF_EXPECTED_INTERRUPTED_BUNDLE_SHA256:-}"
   command -v sha256sum >/dev/null 2>&1 || { echo "error: bootstrap-supersession requires sha256sum" >&2; exit 2; }
   [[ -s "${interrupted_bundle}" && "${interrupted_bundle_sha}" =~ ^[0-9a-f]{64}$ ]] || { echo "error: bootstrap-supersession requires sealed interrupted bundle path and SHA" >&2; exit 2; }
   [[ "$(sha256sum "${interrupted_bundle}" | awk '{print $1}')" == "${interrupted_bundle_sha}" ]] || { echo "error: interrupted bundle bytes do not match sealed SHA" >&2; exit 2; }
   fault_duration_ms="${PRODIGY_STORAGE_HANDOFF_FAULT_DURATION_MS:-90000}"
   [[ "${fault_duration_ms}" =~ ^[0-9]+$ && "${fault_duration_ms}" -ge 60000 && "${fault_duration_ms}" -le 90000 ]] || { echo "error: bootstrap-supersession fault duration must be 60000..90000ms" >&2; exit 2; }
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/prodigy_dev_discombobulator_artifact_helpers.sh"
SCRIPT_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_STORAGE_MULTIDRIVE_RESIZE_SMOKE_MOUNT_NS_READY bash "${SCRIPT_SELF}" "$@"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${PINGPONG_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_pingpong_container [resize|mount-only|legacy-handoff|legacy-recovery|initial-health-zero|provider-handoff] [0|2 storage devices] [upgrade bundle]"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for isolated multi-drive storage smoke"
   exit 77
fi

deps=(awk btrfs cargo mkfs.btrfs mount umount stat zstd timeout ip nsenter python3 rg)
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
target_arch="$(prodigy_dev_detect_target_arch)"

if [[ "${test_mode}" == follower-retained && -n "${PRODIGY_STORAGE_HANDOFF_EVIDENCE_ROOT:-}" ]]
then
   [[ -d "${PRODIGY_STORAGE_HANDOFF_EVIDENCE_ROOT}" ]] || { echo "error: follower-retained evidence root does not exist" >&2; exit 2; }
   tmpdir="$(mktemp -d "${PRODIGY_STORAGE_HANDOFF_EVIDENCE_ROOT%/}/follower-retained.XXXXXX")"
else
   tmpdir="$(mktemp -d)"
fi
workspace_root="${tmpdir}/workspace"
manifest_path="${workspace_root}/test-cluster-manifest.json"
cluster_name="storage-multidrive-$(date -u +%Y%m%d-%H%M%S)"
mothership_db_path="${tmpdir}/mothership-storage.tidesdb"
keep_tmp="${PRODIGY_DEV_KEEP_TMP:-0}"
create_log="${tmpdir}/create_cluster.log"
deploy_log="${tmpdir}/deploy.log"
application_log="${tmpdir}/application_report.log"
cluster_report_log="${tmpdir}/cluster_report.log"
remove_log="${tmpdir}/remove_cluster.log"
btrfs_show_log="${tmpdir}/btrfs_filesystem_show.log"
traffic_log="${tmpdir}/traffic.log"

cluster_created=0
archive_workspace=0
owned_background_pids=()
follower_traffic_loop_pid=""
follower_traffic_stop=""

cleanup()
{
   local status=$?
   trap - EXIT
   set +e

   if [[ "${archive_workspace}" -eq 1 && -d "${workspace_root}" ]]
   then
      rm -rf "${tmpdir}/workspace-archive" >/dev/null 2>&1 || true
      mkdir -p "${tmpdir}/workspace-archive"
      env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         timeout 15s "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" >"${tmpdir}/precleanup-cluster.log" 2>&1
      env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         timeout 15s "${MOTHERSHIP_BIN}" containerLogs "${cluster_name}" Nametag 65536 >"${tmpdir}/precleanup-containers.log" 2>&1
      local runtime_logs=() index relative
      for index in $(seq 1 "${machine_count}")
      do
         for relative in "${index}/var/log/prodigy" "${index}/root/prodigy-crashreport.txt"
         do
            [[ ! -e "${workspace_root}/machines/${relative}" ]] || runtime_logs+=("${relative}")
         done
      done
      if [[ "${#runtime_logs[@]}" -gt 0 ]]
      then
         tar --sparse -cf "${tmpdir}/precleanup-runtime-logs.tar" -C "${workspace_root}/machines" -- "${runtime_logs[@]}"
         chmod 0600 "${tmpdir}/precleanup-runtime-logs.tar"
      fi
      # Read the running node's mounted owner before Mothership removes it.
      # Keep receipts and existing diagnostic logs, never sparse database payloads.
      python3 - "${manifest_path}" "${tmpdir}" <<'PY_STORAGE_TRACES'
import json, pathlib, stat, sys, tarfile
manifest, output = map(pathlib.Path, sys.argv[1:])
observations = []
archive = output / 'precleanup-storage-traces.tar'
try:
    nodes = json.loads(manifest.read_text())['nodes']
    with tarfile.open(archive, 'w') as tar:
        archive.chmod(0o600)
        for node in nodes:
            owner = pathlib.Path('/proc') / str(int(node['pid'])) / 'root/containers'
            record = dict(machineIndex=node['index'], pid=node['pid'], owner=str(owner), files=[], errors=[])
            observations.append(record)
            if not owner.is_dir():
                record['errors'].append('live container owner unavailable')
                continue
            candidates = list(owner.glob('.storage-handoffs/*/capture.txt'))
            candidates += list(owner.glob('*/rootfs/neuron.hosttrace.log'))
            for path in candidates:
                try:
                    metadata = path.lstat()
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8 * 1024 * 1024:
                        record['errors'].append(str(path.relative_to(owner)) + ': not a bounded regular diagnostic file')
                        continue
                    relative = str(path.relative_to(owner))
                    tar.add(path, arcname=str(node['index']) + '/containers/' + relative, recursive=False)
                    record['files'].append(dict(path=relative, bytes=metadata.st_size))
                except OSError as error:
                    record['errors'].append(str(error))
except (OSError, ValueError, KeyError) as error:
    observations.append(dict(error=str(error)))
(output / 'precleanup-storage-traces.json').write_text(json.dumps(observations, indent=2) + '\n')
PY_STORAGE_TRACES
      find "${workspace_root}" -maxdepth 1 -type f \( -name '*.log' -o -name '*.json' -o -name '*.ready' -o -name '*.failure' \) \
         -exec cp -a {} "${tmpdir}/workspace-archive/" \; >/dev/null 2>&1 || true
      find "${workspace_root}/virtual-datacenter.recovery" -maxdepth 2 -type f \( -name operation -o -name ready -o -name commit -o -name launch -o -name replaced -o -name complete -o -name failure -o -name provider.log -o -name selected-machine -o -name root-installed -o -name previous-boot.json -o -name successor-boot.json \) -size -8M \
         -exec cp --parents {} "${tmpdir}/workspace-archive/" \; >/dev/null 2>&1 || true
      python3 - "${manifest_path}" "${tmpdir}/process-identity" <<'PY_PROCESS_IDENTITY'
import json, pathlib, sys
manifest, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
for node in json.loads(manifest.read_text()).get('nodes', []):
    parent = pathlib.Path('/proc') / str(node['pid']); pids = {str(node['pid'])}
    try:
        for leaf in (parent / 'root/sys/fs/cgroup/containers.slice').glob('*.slice/leaf/cgroup.procs'):
            pids.update(leaf.read_text().split())
    except OSError: pass
    for pid in pids:
        proc = pathlib.Path('/proc') / pid
        try:
            (out / (pid + '.json')).write_text(json.dumps({'pid': int(pid), 'node': node.get('index'), 'exe': str((proc/'exe').readlink()), 'status': (proc/'status').read_text()[:16384], 'cgroup': (proc/'cgroup').read_text()[:8192]}, indent=2) + '\n')
        except OSError: pass
PY_PROCESS_IDENTITY
   fi

   # The retained-follower sampler owns a timeout-bounded probe subprocess. Ask
   # it to finish that probe before Mothership removes the cluster; killing only
   # its shell can leave the client process outside the generic PID cleanup.
   if [[ -n "${follower_traffic_loop_pid:-}" ]]
   then
      [[ -z "${follower_traffic_stop:-}" ]] || : > "${follower_traffic_stop}"
      wait "${follower_traffic_loop_pid}" >/dev/null 2>&1 || true
      filtered_background_pids=()
      for background_pid in "${owned_background_pids[@]}"
      do
         [[ "${background_pid}" == "${follower_traffic_loop_pid}" ]] || filtered_background_pids+=("${background_pid}")
      done
      owned_background_pids=("${filtered_background_pids[@]}")
      follower_traffic_loop_pid=""
   fi

   for background_pid in "${owned_background_pids[@]}"
   do
      kill "${background_pid}" >/dev/null 2>&1 || true
      wait "${background_pid}" >/dev/null 2>&1 || true
   done

   # Preserve only BPF object metadata for a failed retained-follower run.
   # This executes before Mothership owns teardown; every read is namespace
   # scoped and timeout-bounded, and any diagnostic failure keeps the original
   # test status and cleanup path intact.
   if [[ "${test_mode}" == follower-retained && "${status}" -ne 0 && -s "${manifest_path}" ]]
   then
      follower_bpf_diagnostics="${tmpdir}/follower-retained-bpf-diagnostics"
      mkdir -p "${follower_bpf_diagnostics}"
      timeout 45s bash -s -- "${manifest_path}" "${follower_machine_index:-}" "${follower_bpf_diagnostics}" <<'BASH_FOLLOWER_BPF_DIAGNOSTICS' >/dev/null 2>&1
set +e
manifest="$1"
selected="$2"
out="$3"
bpftool_bin="$(command -v bpftool 2>/dev/null || true)"
python3 - "${manifest}" "${selected}" >"${out}/runtime-pids.tsv" <<'PY_FOLLOWER_BPF_PIDS'
import json, pathlib, sys
manifest = pathlib.Path(sys.argv[1])
selected_index = sys.argv[2]
for node in json.loads(manifest.read_text()).get('nodes', []):
    index = str(node.get('index', ''))
    print('\t'.join((index, str(node.get('pid', '')), 'selected' if index == selected_index else 'other')))
PY_FOLLOWER_BPF_PIDS
while IFS=$'\t' read -r index pid role
do
    [[ "${index}" =~ ^[0-9]+$ && "${pid}" =~ ^[0-9]+$ ]] || continue
    prefix="${out}/machine-${index}-${role}"
    {
        printf 'machineIndex=%s\nruntimePID=%s\nrole=%s\n' "${index}" "${pid}" "${role}"
        [[ -d "/proc/${pid}" ]] || { printf 'runtimePresent=0\n'; continue; }
        printf 'runtimePresent=1\n'
        tr '\0' '\n' <"/proc/${pid}/environ" 2>/dev/null | \
            grep -E '^PRODIGY_HOST_(INGRESS|EGRESS)_EBPF=' || true
    } >"${prefix}.env.txt"
    grep -F ' /sys/fs/bpf ' "/proc/${pid}/mountinfo" >"${prefix}.bpf-mountinfo.txt" 2>&1 || true
    if [[ -z "${bpftool_bin}" ]]
    then
        printf 'bpftool unavailable on diagnostic host\n' >"${prefix}.bpftool-unavailable.txt"
        continue
    fi
    timeout 5s nsenter -t "${pid}" -m -n -- "${bpftool_bin}" -j map show >"${prefix}.maps.json" 2>&1 || true
    timeout 5s nsenter -t "${pid}" -m -n -- "${bpftool_bin}" -j prog show >"${prefix}.programs.json" 2>&1 || true
    timeout 5s nsenter -t "${pid}" -m -n -- "${bpftool_bin}" -j link show >"${prefix}.links.json" 2>&1 || true
    timeout 5s nsenter -t "${pid}" -m -n -- "${bpftool_bin}" -j net show >"${prefix}.net.json" 2>&1 || true
    pin_root="/proc/${pid}/root/sys/fs/bpf"
    pin_count=0
    if [[ -d "${pin_root}" ]]
    then
        while IFS= read -r pin
        do
            pin_count=$((pin_count + 1))
            [[ "${pin_count}" -le 128 ]] || break
            relative="${pin#${pin_root}}"
            safe_name="$(printf '%s' "${relative}" | tr '/ ' '__' | tr -cd '[:alnum:]_.-')"
            [[ -n "${safe_name}" ]] || safe_name="root-${pin_count}"
            timeout 3s nsenter -t "${pid}" -m -n -- "${bpftool_bin}" -j map show pinned "/sys/fs/bpf${relative}" \
                >"${prefix}.pinned-map-${pin_count}-${safe_name}.json" 2>&1 || true
        done < <(find "${pin_root}" -xdev -type f -print 2>/dev/null)
    fi
    printf 'pinnedMapMetadataAttempts=%s\n' "${pin_count}" >"${prefix}.pinned-maps.txt"
done <"${out}/runtime-pids.tsv"
BASH_FOLLOWER_BPF_DIAGNOSTICS
      follower_bpf_diagnostic_status=$?
      printf 'captureExitStatus=%s\n' "${follower_bpf_diagnostic_status}" >"${follower_bpf_diagnostics}/capture-status.txt"
   fi

   if [[ "${cluster_created}" -eq 1 ]]
   then
      if ! env \
         PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" removeCluster "${cluster_name}" \
         >"${remove_log}" 2>&1
      then
         echo "FAIL: Mothership removal failed; owned state retained" >&2
         status=1
         keep_tmp=1
      fi
   fi

   if [[ "${keep_tmp}" -eq 1 ]]
   then
      echo "KEEP_TMP: ${tmpdir}"
   else
      rm -rf "${tmpdir}"
   fi
   exit "${status}"
}
trap cleanup EXIT

mkdir -p "${workspace_root}"

application_id=6
version_id=$(( ($(date +%s%N) & 281474976710655) ))
if [[ "${version_id}" -le 0 ]]
then
   version_id=1
fi
deployment_id=$(( (application_id << 48) | version_id ))
machine_count=1
brain_count=1
application_type=stateless
is_stateful=false
expected_healthy=1
initial_healthy=1
initial_state=running
recovered_state=running
handoff_id=""
fake_ipv4_boundary=false
if [[ "${is_handoff}" == 1 ]]
then
   # Match the retained release topology: one controller and three workers.
   machine_count=4
   if [[ "${test_mode}" == follower-retained ]]
   then
      # This fixture is intentionally the exact master-plus-two-followers
      # topology accepted by recoverTestClusterFollowerBrain.
      machine_count=3
      brain_count=3
   fi
   if [[ "$test_mode" == bootstrap-supersession ]]
   then
      # Three replicas on three machines force one live application onto the
      # sole Brain. Four machines can place every replica on the workers and
      # would leave the local checkpoint preservation gate unexercised.
      machine_count=3
   fi
   expected_healthy=3
   initial_healthy=3
   if [[ "${test_mode}" == legacy-recovery || "${test_mode}" == legacy-recovery-zero || "${test_mode}" == initial-health-zero ]]
   then
      initial_healthy=1
      if [[ "${test_mode}" == legacy-recovery-zero || "${test_mode}" == initial-health-zero ]]
      then
         initial_healthy=0
      fi
      initial_state=deploying
      recovered_state=none
   fi
   application_type=stateful
   is_stateful=true
   handoff_id="$(tr -d '-' < /proc/sys/kernel/random/uuid)"
fi
if [[ "${test_mode}" == follower-retained ]]
then
   # The registered test-only routable prefix is the sole ingress endpoint for
   # the retained-follower traffic observation; containers remain non-host-net.
   fake_ipv4_boundary=true
fi

read -r -d '' CREATE_REQUEST <<EOF || true
{
  "name": "${cluster_name}",
  "deploymentMode": "test",
  "autoscaleIntervalSeconds": 3,
  "nBrains": ${brain_count},
  "machineSchemas": [
    {
      "schema": "bootstrap",
      "kind": "vm",
      "vmImageURI": "test://netns-local"
    }
  ],
  "test": {
    "workspaceRoot": "${workspace_root}",
    "machineCount": ${machine_count},
    "machineStorageMB": 8192,
    "storageDeviceCount": ${storage_devices},
    "storageDeviceMB": 1024,
    "brainBootstrapFamily": "ipv4",
    "enableFakeIpv4Boundary": ${fake_ipv4_boundary}
  }
}
EOF

create_mothership_bin="${create_mothership_bin:-${MOTHERSHIP_BIN}}"
create_arguments=("${CREATE_REQUEST}")
create_environment=()
if [[ "${test_mode}" == follower-retained ]]; then
   # Mothership validates and installs the exact old bundle through its normal
   # seed-first provider. The harness never stages or launches an old runtime.
   create_arguments+=("${initial_bundle}")
   # Hold failed creation only until this harness's EXIT trap observes it and
   # requests Mothership removal. This also covers interruption during create.
   create_environment+=(PRODIGY_MOTHERSHIP_KEEP_FAILED_TEST_CLUSTER=1)
   cluster_created=1
   archive_workspace=1
fi
if ! env \
   PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" "${create_environment[@]}" \
   "${create_mothership_bin}" createCluster "${create_arguments[@]}" \
   >"${create_log}" 2>&1
then
   echo "FAIL: createCluster test cluster failed"
   sed -n '1,200p' "${create_log}" || true
   exit 1
fi
cluster_created=1

for _ in $(seq 1 300)
do
   if [[ -s "${manifest_path}" ]]
   then
      break
   fi
   sleep 0.2
done

if [[ ! -s "${manifest_path}" ]]
then
   echo "FAIL: test cluster manifest did not become ready"
   sed -n '1,200p' "${create_log}" || true
   exit 1
fi

brain_pid="$(python3 - "${manifest_path}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
print(next((node.get("pid", 0) for node in manifest.get("nodes", []) if node.get("role") == "brain"), 0))
PY
)"

if ! [[ "${brain_pid}" =~ ^[0-9]+$ ]] || [[ "${brain_pid}" -le 0 ]] || ! kill -0 "${brain_pid}" >/dev/null 2>&1
then
   echo "FAIL: unable to parse live brain pid"
   exit 1
fi

if [[ "${is_handoff}" == 1 ]]
then
   # Use the same healthy/runtime-ready report predicates as the netns harness.
   # A manifest lists launched nodes before their asynchronous inventory arrives.
   machines_ready=0
   for _ in $(seq 1 120)
   do
      if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         timeout 8s "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" >"${cluster_report_log}" 2>&1
      then
         healthy_count="$(rg -c '^[[:space:]]*Machine: state=healthy ' "${cluster_report_log}" || true)"
         ready_count="$(rg -c '^[[:space:]]*lifecycle controlPlaneReachable=1 runtimeReady=1 ' "${cluster_report_log}" || true)"
         if [[ "${healthy_count:-0}" -eq "${machine_count}" && "${ready_count:-0}" -eq "${machine_count}" ]]
         then
            machines_ready=1
            break
         fi
      fi
      sleep 0.5
   done
   [[ "${machines_ready}" == 1 ]] || {
      archive_workspace=1
      echo "FAIL: declared worker inventory did not become ready before initial deployment" >&2
      exit 1
   }
fi

follower_wormhole_address=""
follower_wormhole_prefix_uuid=""
follower_ingress_machine_index=""
follower_ingress_machine_uuid=""
if [[ "${test_mode}" == follower-retained ]]
then
   read -r follower_ingress_machine_index follower_ingress_machine_uuid <<EOF
$(python3 - "${cluster_report_log}" "${manifest_path}" <<'PY_FOLLOWER_INGRESS_MACHINE'
import json, pathlib, re, sys
report, manifest = map(pathlib.Path, sys.argv[1:])
nodes = json.loads(manifest.read_text())['nodes']
by_address = {node['ipv4']: int(node['index']) for node in nodes}
blocks = re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)', report.read_text())
candidates = []
for block in blocks:
    identity = re.search(r'(?m)^[ \t]*identity uuid=(0x[0-9a-f]+) .*sshAddress=(\S+)', block)
    lifecycle = re.search(r'(?m)^[ \t]*lifecycle .*currentMaster=(\d)\b', block)
    assert identity and lifecycle and identity.group(2) in by_address, 'missing ready machine identity'
    if lifecycle.group(1) == '0':
        candidates.append((by_address[identity.group(2)], identity.group(1)))
assert candidates, 'fixture has no nonmaster ingress machine'
print(*min(candidates))
PY_FOLLOWER_INGRESS_MACHINE
)
EOF
   [[ "${follower_ingress_machine_index}" =~ ^[123]$ && "${follower_ingress_machine_uuid}" =~ ^0x[0-9a-fA-F]{1,32}$ ]] || {
      archive_workspace=1
      echo "FAIL: retained follower fixture could not bind a nonmaster ingress machine" >&2
      exit 1
   }
   follower_wormhole_register_log="${tmpdir}/follower-wormhole-register.log"
   follower_wormhole_request="$(printf '{"name":"retained-follower-%s","kind":"BGP","prefix":"198.18.0.1/32","usage":"wormholes","ingressScope":"singleMachine","machineUUID":"%s"}' "${handoff_id}" "${follower_ingress_machine_uuid}")"
   if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" registerRoutableSubnet "${cluster_name}" "${follower_wormhole_request}" \
      >"${follower_wormhole_register_log}" 2>&1
   then
      archive_workspace=1
      echo "FAIL: retained follower wormhole prefix registration failed" >&2
      sed -n '1,160p' "${follower_wormhole_register_log}" >&2 || true
      exit 1
   fi
   read -r follower_wormhole_prefix_uuid follower_wormhole_address <<EOF
$(python3 - "${follower_wormhole_register_log}" <<'PY_FOLLOWER_WORMHOLE_PREFIX'
import re, sys
text = open(sys.argv[1], encoding='utf-8', errors='replace').read()
uuid = re.search(r'\buuid=(0x[0-9a-fA-F]+|[0-9a-fA-F]+)', text)
prefix = re.search(r'\bprefix=([^\s]+)', text)
if not uuid or not prefix:
    raise SystemExit(1)
address = prefix.group(1).split('/', 1)[0]
if address != '198.18.0.1':
    raise SystemExit(1)
print(uuid.group(1), address)
PY_FOLLOWER_WORMHOLE_PREFIX
)
EOF
   if [[ ! "${follower_wormhole_prefix_uuid}" =~ ^(0x)?[0-9a-fA-F]{1,32}$ || "${follower_wormhole_address}" != 198.18.0.1 ]]
   then
      archive_workspace=1
      echo "FAIL: retained follower wormhole registration returned no exact test prefix" >&2
      sed -n '1,160p' "${follower_wormhole_register_log}" >&2 || true
      exit 1
   fi
fi

artifact_project_dir="${tmpdir}/storage-artifact"
discombobulator_file="${artifact_project_dir}/PingPongStorage.DiscombobuFile"
container_blob="${tmpdir}/storage.container.zst"
mkdir -p "${artifact_project_dir}"
cat > "${discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {bin} ./$(basename "${PINGPONG_BIN}") /root/pingpong_container
SURVIVE /root/pingpong_container
EOF
prodigy_dev_write_common_prodigy_assets "${discombobulator_file}"
if [[ "${is_handoff}" == 1 ]]
then
   printf 'ENV PINGPONG_STORAGE_HANDOFF_MODE=seed\nENV PINGPONG_STORAGE_HANDOFF_ID=%s\n' "${handoff_id}" >> "${discombobulator_file}"
   if [[ "${test_mode}" == legacy-recovery || "${test_mode}" == legacy-recovery-zero || "${test_mode}" == initial-health-zero ]]
   then
      # Recovery fixtures retain real seeded data owners while readiness is withheld.
      printf 'ENV PINGPONG_STORAGE_HANDOFF_WAIT_FOR_TRAFFIC=1\n' >> "${discombobulator_file}"
   fi
fi
cat >> "${discombobulator_file}" <<'EOF'
EXECUTE ["/root/pingpong_container"]
EOF

if ! prodigy_dev_run_discombobulator_build \
   "${artifact_project_dir}" \
   "${discombobulator_file}" \
   "${container_blob}" \
   "bin=$(dirname "${PINGPONG_BIN}")" \
   "ebpf=$(dirname "${PRODIGY_BIN}")"
then
   archive_workspace=1
   echo "FAIL: unable to build storage test artifact"
   exit 1
fi

plan_json="${tmpdir}/storage.plan.json"
# Use the runtime's app/slot/group prefix layout so group zero preserves five
# distinct stateful roles, as in the topology-upgrade fixture.
group_mask=$(( (1 << 10) - 1 ))
client_prefix=$(( (application_id << 48) | (1 << 40) | group_mask ))
sibling_prefix=$(( (application_id << 48) | (2 << 40) | group_mask ))
cousin_prefix=$(( (application_id << 48) | (3 << 40) | group_mask ))
seeding_prefix=$(( (application_id << 48) | (4 << 40) | group_mask ))
sharding_prefix=$(( (application_id << 48) | (5 << 40) | group_mask ))
cat > "${plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::${application_type}",
    "applicationID": ${application_id},
    "versionID": ${version_id},
    "architecture": "${target_arch}",
    "filesystemMB": 64,
    "storageMB": 256,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
    "sTilKillable": 30
  },
  "apiCredentials": {
    "applicationID": ${application_id},
    "requiredCredentialNames": []
  },
  "useHostNetworkNamespace": ${host_network},
  "minimumSubscriberCapacity": 1024,
  "isStateful": ${is_stateful},
  "stateful": {
    "clientPrefix": ${client_prefix}, "siblingPrefix": ${sibling_prefix}, "cousinPrefix": ${cousin_prefix},
    "seedingPrefix": ${seeding_prefix}, "shardingPrefix": ${sharding_prefix},
    "allowUpdateInPlace": true, "seedingAlways": false,
    "neverShard": true, "allMasters": false
  },
  "stateless": {
    "nBase": 1,
    "maxPerRackRatio": 1.0,
    "maxPerMachineRatio": 1.0,
    "moveableDuringCompaction": true
  },
  "verticalScalers": [
    {
      "name": "pingpong.requests",
      "resource": "ScalingDimension::storage",
      "increment": 256,
      "percentile": 90,
      "lookbackSeconds": 15,
      "threshold": 0.5,
      "minValue": 256,
      "maxValue": 512,
      "direction": "upscale"
    }
  ],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF

# The typed plan admits exactly one topology owner. The handoff workload must
# also stay at fixed resources rather than trigger the resize scenario.
python3 - "${plan_json}" "${test_mode}" <<'PY_STORAGE_PLAN'
import json, sys
with open(sys.argv[1]) as stream:
    plan = json.load(stream)
if sys.argv[2] in ('legacy-handoff', 'legacy-recovery', 'legacy-recovery-zero', 'initial-health-zero', 'provider-handoff', 'bootstrap-supersession', 'follower-retained'):
    plan.pop('stateless')
    plan['verticalScalers'] = []
else:
    plan.pop('stateful')
with open(sys.argv[1], 'w') as stream:
    json.dump(plan, stream)
PY_STORAGE_PLAN

follower_traffic_application_name=""
follower_traffic_application_id=""
follower_traffic_version_id="${version_id}"
follower_traffic_plan_json=""
follower_traffic_blob=""
if [[ "${test_mode}" == follower-retained ]]
then
   follower_traffic_application_name="RetainedFollowerTraffic"
   follower_traffic_reserve_log="${tmpdir}/follower-traffic-reserve-application.log"
   follower_traffic_reserve_request="$(printf '{"applicationName":"%s","createIfMissing":true}' "${follower_traffic_application_name}")"
   if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" reserveApplicationID "${cluster_name}" "${follower_traffic_reserve_request}" >"${follower_traffic_reserve_log}" 2>&1
   then
      archive_workspace=1
      echo "FAIL: retained follower traffic application reservation failed" >&2
      sed -n '1,160p' "${follower_traffic_reserve_log}" >&2 || true
      exit 1
   fi
   follower_traffic_application_id="$(rg -m1 -o 'appID=[1-9][0-9]*' "${follower_traffic_reserve_log}" | sed 's/appID=//')"
   [[ "${follower_traffic_application_id}" =~ ^[1-9][0-9]*$ ]] || {
      archive_workspace=1
      echo "FAIL: retained follower traffic reservation omitted application ID" >&2
      cat "${follower_traffic_reserve_log}" >&2 || true
      exit 1
   }
   follower_traffic_artifact_dir="${tmpdir}/traffic-artifact"
   follower_traffic_discombobulator_file="${follower_traffic_artifact_dir}/RetainedTraffic.DiscombobuFile"
   follower_traffic_blob="${tmpdir}/retained-traffic.container.zst"
   mkdir -p "${follower_traffic_artifact_dir}"
   cat > "${follower_traffic_discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {bin} ./$(basename "${PINGPONG_BIN}") /root/retained_traffic_container
SURVIVE /root/retained_traffic_container
EOF
   prodigy_dev_write_common_prodigy_assets "${follower_traffic_discombobulator_file}"
   cat >> "${follower_traffic_discombobulator_file}" <<'EOF_TRAFFIC_EXECUTE'
EXECUTE ["/root/retained_traffic_container"]
EOF_TRAFFIC_EXECUTE
   if ! prodigy_dev_run_discombobulator_build \
      "${follower_traffic_artifact_dir}" "${follower_traffic_discombobulator_file}" "${follower_traffic_blob}" \
      "bin=$(dirname "${PINGPONG_BIN}")" "ebpf=$(dirname "${PRODIGY_BIN}")"
   then
      archive_workspace=1
      echo "FAIL: unable to build retained follower stateless traffic artifact" >&2
      exit 1
   fi
   follower_traffic_plan_json="${tmpdir}/retained-traffic.plan.json"
   cat > "${follower_traffic_plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${follower_traffic_application_id},
    "versionID": ${follower_traffic_version_id},
    "architecture": "${target_arch}",
    "filesystemMB": 64,
    "storageMB": 64,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 2000,
    "sTilHealthcheck": 3,
    "sTilKillable": 30
  },
  "apiCredentials": {
    "applicationID": ${follower_traffic_application_id},
    "requiredCredentialNames": []
  },
  "useHostNetworkNamespace": false,
  "minimumSubscriberCapacity": 1024,
  "isStateful": false,
  "stateless": {
    "nBase": 1,
    "maxPerRackRatio": 1.0,
    "maxPerMachineRatio": 1.0,
    "moveableDuringCompaction": true
  },
  "wormholes": [{
    "name": "retained-ping",
    "source": "registeredRoutablePrefix",
    "routablePrefixUUID": "${follower_wormhole_prefix_uuid}",
    "externalPort": 19090,
    "containerPort": 19090,
    "layer4": "TCP",
    "isQuic": false
  }],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF
fi

if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" deploy "${cluster_name}" "$(cat "${plan_json}")" "${container_blob}" \
   >"${deploy_log}" 2>&1
then
   archive_workspace=1
   echo "FAIL: storage deployment failed"
   sed -n '1,200p' "${deploy_log}" || true
   exit 1
fi

if [[ "${test_mode}" == follower-retained ]] && ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" deploy "${cluster_name}" "$(cat "${follower_traffic_plan_json}")" "${follower_traffic_blob}" \
   >"${tmpdir}/follower-traffic-deploy.log" 2>&1
then
   archive_workspace=1
   echo "FAIL: retained follower stateless traffic deployment failed" >&2
   sed -n '1,200p' "${tmpdir}/follower-traffic-deploy.log" >&2 || true
   exit 1
fi

if [[ "${test_mode}" == legacy-recovery ]]
then
   # Reuse the fixture's ordinary ping/pong readiness path on exactly one owned
   # process. All replicas have seeded real data before accepting traffic.
   python3 - "${manifest_path}" "${PINGPONG_BIN}" >"${tmpdir}/seed-readiness-probe.log" 2>&1 <<'PY_SEED_TRAFFIC'
import hashlib, json, pathlib, subprocess, sys, time
manifest, binary = map(pathlib.Path, sys.argv[1:])
node = next(node for node in json.loads(manifest.read_text())['nodes'] if node['index'] == 2)
parent = pathlib.Path('/proc') / str(node['pid'])
expected = hashlib.sha256(binary.read_bytes()).hexdigest()
probe = "import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); s.settimeout(2); s.connect(('::1',19090)); s.sendall(b'ping\\n'); data=b''\nwhile not data.endswith(b'\\n'): data += s.recv(32)\nassert data == b'pong\\n',data\nprint('pong')"
deadline = time.monotonic() + 60
last = ''
while time.monotonic() < deadline:
    children = (parent / 'task' / str(node['pid']) / 'children').read_text().split()
    for pid in children:
        child = pathlib.Path('/proc') / pid
        try:
            if (child / 'exe').readlink().name != 'pingpong_container':
                continue
            assert hashlib.sha256((child / 'exe').read_bytes()).hexdigest() == expected
            assert (child / 'ns/net').readlink() != (parent / 'ns/net').readlink()
            result = subprocess.run(['nsenter', '--net=' + str(child / 'ns/net'), sys.executable, '-c', probe],
                                    capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                print('SEED_TRAFFIC_READY machineIndex=2 pid=' + pid + ' response=' + result.stdout.strip())
                sys.exit(0)
            last = result.stderr[-1000:]
        except (FileNotFoundError, ProcessLookupError, subprocess.TimeoutExpired) as error:
            last = str(error)
    time.sleep(0.5)
raise RuntimeError('owned seed replica did not serve its readiness probe: ' + last)
PY_SEED_TRAFFIC
fi

healthy=0
report_version_ready()
{
   python3 - "$1" "$2" "$3" "${4:-$3}" "${5:-running}" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
wanted, count, healthy = map(int, sys.argv[2:5])
state = sys.argv[5]
for block in re.split(r'(?m)^\s*versionID:\s*', text)[1:]:
    if int(block.splitlines()[0]) != wanted:
        continue
    def field(name):
        # Stateless reports print isStateful and nTarget on the same line.
        match = re.search(r'(?:^|\s)' + re.escape(name) + r':\s*(\S+)', block)
        return match[1] if match else None
    ready = (field('state') == 'DeploymentState::' + state and field('nDeployed') == str(count)
             and field('nHealthy') == str(healthy) and field('nCrashes') == '0'
             and (state == 'waitingToDeploy' or field('nTarget') == str(count)))
    sys.exit(0 if ready else 1)
sys.exit(1)
PY
}

for _ in $(seq 1 120)
do
   if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" Nametag \
      >"${application_log}" 2>&1
   then
      if report_version_ready "${application_log}" "${version_id}" "${expected_healthy}" "${initial_healthy}" "${initial_state}"
      then
         healthy=1
         break
      fi
   fi

   sleep 0.5
done

if [[ "${healthy}" -ne 1 ]]
then
   archive_workspace=1
   echo "FAIL: storage deployment never became healthy"
   sed -n '1,240p' "${application_log}" || true
   exit 1
fi

if [[ "${test_mode}" == follower-retained ]]
then
   follower_traffic_healthy=0
   for _ in $(seq 1 120)
   do
      if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" "${follower_traffic_application_name}" \
         >"${tmpdir}/follower-traffic-before-application.log" 2>&1 &&
         report_version_ready "${tmpdir}/follower-traffic-before-application.log" "${follower_traffic_version_id}" 1 1 running
      then
         follower_traffic_healthy=1
         break
      fi
      sleep 0.5
   done
   [[ "${follower_traffic_healthy}" == 1 ]] || {
      archive_workspace=1
      echo "FAIL: retained follower stateless traffic deployment never became healthy without crashes" >&2
      sed -n '1,240p' "${tmpdir}/follower-traffic-before-application.log" >&2 || true
      exit 1
   }
fi

if [[ "${is_handoff}" == 1 ]]
then
   archive_workspace=1
   observe_handoff()
   {
      python3 - "${manifest_path}" "${PINGPONG_BIN}" "${handoff_id}" "$1" "${tmpdir}" "${PRODIGY_STORAGE_HANDOFF_EXPECTED_RUNTIME_SHA256}" "${test_mode}" "${follower_machine_index:-0}" "${old_runtime_sha:-}" "${old_bundle_sha:-}" "${follower_target_bundle_sha:-}" <<'PY'
import hashlib, json, pathlib, re, sys
manifest, executable, identity, phase, output, runtime_hash, mode, selected_machine, source_runtime_hash, source_bundle_hash, target_bundle_hash = sys.argv[1:]
selected_machine = int(selected_machine)
root = pathlib.Path(output)
nodes = json.loads(pathlib.Path(manifest).read_text())['nodes']
expected_binary = hashlib.sha256(pathlib.Path(executable).read_bytes()).hexdigest()
before = json.loads((root / 'handoff-before.json').read_text()) if phase != 'before' else None
records = []
for node in nodes:
    parent = pathlib.Path('/proc') / str(node['pid'])
    observed_runtime = hashlib.sha256((parent / 'exe').read_bytes()).hexdigest()
    bundle_candidates = [parent / 'root/root/prodigy/prodigy.bundle.tar.zst',
                         pathlib.Path(manifest).parent / 'machines' / str(node['index']) / 'root/prodigy/prodigy.bundle.tar.zst']
    installed_bundle = next((candidate for candidate in bundle_candidates if candidate.is_file()), None)
    if mode == 'follower-retained':
        assert installed_bundle is not None, 'installed Prodigy bundle is not readable from the retained fixture'
        observed_bundle = hashlib.sha256(installed_bundle.read_bytes()).hexdigest()
    if mode == 'follower-retained' and phase == 'before':
        assert observed_runtime == source_runtime_hash, 'fixture is not running the sealed runtime19b executable'
        assert observed_bundle == source_bundle_hash, 'fixture does not contain the sealed runtime19b bundle'
    if phase == 'follower-step':
        prior = next((record for record in before if record['machineIndex'] == node['index']), None)
        assert prior is not None, 'missing source runtime record for machine'
        expected_runtime = runtime_hash if node['index'] == selected_machine else prior['runtimeSHA256']
        expected_bundle = target_bundle_hash if node['index'] == selected_machine else prior['bundleSHA256']
        assert observed_runtime == expected_runtime, 'follower replacement changed an unexpected runtime image'
        assert observed_bundle == expected_bundle, 'follower replacement changed an unexpected installed bundle'
    elif phase not in ('before', 'provider-step'):
        assert observed_runtime == runtime_hash, 'machine has wrong runtime bytes'
    children = []
    if mode in ('provider-handoff', 'bootstrap-supersession', 'follower-retained'):
        for leaf in (parent / 'root/sys/fs/cgroup/containers.slice').glob('*.slice/leaf/cgroup.procs'):
            children.extend(leaf.read_text().split())
    else:
        children = (parent / 'task' / str(node['pid']) / 'children').read_text().split()
    for pid in children:
        child = pathlib.Path('/proc') / pid
        try:
            if (child / 'exe').readlink().name != 'pingpong_container':
                continue
        except FileNotFoundError:
            continue
        assert hashlib.sha256((child / 'exe').read_bytes()).hexdigest() == expected_binary
        uuid = re.search(r'/containers\.slice/([0-9]+)\.slice/leaf(?:\n|$)', (child / 'cgroup').read_text())[1]
        live = child / 'root/storage'
        metadata = live.stat()
        file = live / 'kvdb/handoff-sparse'
        with file.open('rb') as stream:
            assert stream.read(32) == identity.encode()
            stream.seek(1 << 40); middle = stream.read(1)
            stream.seek((1 << 41) - 1); assert stream.read(1) == b'Z'
        assert file.stat().st_size == 1 << 41
        assert middle == (b'A' if phase == 'after' else b'M')
        owner = parent / 'root/containers'
        storage_relative = pathlib.Path('storage') / uuid
        if phase == 'before':
            # Current runtimes use the canonical storage owner. The sealed
            # legacy runtime keeps it under the container rootfs instead.
            candidates = [storage_relative, pathlib.Path(uuid) / 'rootfs/storage']
            matches = [p for p in candidates if (owner / p).exists()
                       and ((owner / p).stat().st_dev, (owner / p).stat().st_ino)
                           == (metadata.st_dev, metadata.st_ino)]
            assert matches, 'live storage does not match a known owner'
            storage_relative = matches[0]
        elif phase in ('upgraded', 'recovered', 'provider-step', 'follower-step'):
            storage_relative = pathlib.Path(next(r['storageRelativePath'] for r in before if r['uuid'] == uuid))
        if phase in ('before', 'upgraded', 'recovered', 'provider-step', 'follower-step'):
            original = owner / storage_relative
            assert (original.stat().st_dev, original.stat().st_ino) == (metadata.st_dev, metadata.st_ino)
        else:
            target = owner / storage_relative
            assert (target.stat().st_dev, target.stat().st_ino) == (metadata.st_dev, metadata.st_ino)
            assert file.stat().st_uid == metadata.st_uid
            assert any(line.split()[4] == '/storage' for line in (child / 'mountinfo').read_text().splitlines())
        starttime = (child / 'stat').read_text().rsplit(') ',1)[1].split()[19]
        parent_starttime = (parent / 'stat').read_text().rsplit(') ',1)[1].split()[19]
        records.append(dict(machineIndex=node['index'], parentPID=node['pid'], pid=int(pid), starttime=starttime, uuid=uuid,
                            device=metadata.st_dev, inode=metadata.st_ino, uid=metadata.st_uid, storageRelativePath=str(storage_relative),
                            networkNamespace=str((child / 'ns/net').readlink()),
                            cgroup=(child / 'cgroup').read_text(),
                            parentStarttime=parent_starttime,
                            parentNetworkNamespace=str((parent / 'ns/net').readlink()),
                            parentCgroup=(parent / 'cgroup').read_text(),
                            runtimeSHA256=observed_runtime,
                            bundleSHA256=observed_bundle if mode == 'follower-retained' else '',
                            applicationSHA256=expected_binary))
assert len(records) == 3, f'expected three real fixture replicas, got {len(records)}'
if mode == 'bootstrap-supersession' and phase == 'before':
    assert any(r['machineIndex'] == 1 for r in records), 'checkpoint fixture must include a Brain-local application'

if phase in ('upgraded', 'recovered', 'provider-step', 'follower-step'):
    assert sorted((r['pid'], r['starttime'], r['uuid'], r['device'], r['inode'], r['networkNamespace'], r['cgroup']) for r in records) == \
           sorted((r['pid'], r['starttime'], r['uuid'], r['device'], r['inode'], r['networkNamespace'], r['cgroup']) for r in before), 'bundle upgrade changed live app/storage/network owners'
if phase == 'after':
    assert not ({r['pid'] for r in before} & {r['pid'] for r in records})
    for old in before:
        node = next(n for n in nodes if n['index'] == old['machineIndex'])
        owner = pathlib.Path('/proc') / str(node['pid']) / 'root/containers'
        source = owner / old['storageRelativePath']
        assert (source.stat().st_dev, source.stat().st_ino) == (old['device'], old['inode'])
        with (source / 'kvdb/handoff-sparse').open('rb') as stream:
            assert stream.read(32) == identity.encode()
            stream.seek(1 << 40); assert stream.read(1) == b'M', 'rollback source was modified'
        receipts = list((owner / '.storage-handoffs').glob(old['uuid'] + '-*/capture.txt'))
        assert len(receipts) == 1
        receipt = receipts[0].read_text()
        assert 'method=reflink-always\n' in receipt and 'sourceRetained=true\n' in receipt
        assert 'sourceInode=' + str(old['inode']) + '\n' in receipt
        (root / ('capture-' + old['uuid'] + '.txt')).write_text(receipt)
(root / ('handoff-' + phase + '.json')).write_text(json.dumps(records, indent=2) + '\n')
print('HANDOFF_OBSERVATION_PASS', phase, 'replicas=3')
PY
   }
   run_successor_handoff()
   {
      local active_state="$1"
   # A second Discombobulator artifact reads the data before signaling healthy;
   # the harness never seeds or modifies a live container's storage.
   sed 's/PINGPONG_STORAGE_HANDOFF_MODE=seed/PINGPONG_STORAGE_HANDOFF_MODE=verify/' \
      "${discombobulator_file}" > "${artifact_project_dir}/Verify.DiscombobuFile"
   prodigy_dev_run_discombobulator_build "${artifact_project_dir}" "${artifact_project_dir}/Verify.DiscombobuFile" \
      "${tmpdir}/verify.container.zst" "bin=$(dirname "${PINGPONG_BIN}")" "ebpf=$(dirname "${PRODIGY_BIN}")"
   python3 - "${plan_json}" "${tmpdir}/verify.plan.json" <<'PY'
import json, sys
with open(sys.argv[1]) as stream:
    plan = json.load(stream)
plan['config']['versionID'] += 1
with open(sys.argv[2], 'w') as stream:
    json.dump(plan, stream)
PY
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" deploy "${cluster_name}" "$(cat "${tmpdir}/verify.plan.json")" \
      "${tmpdir}/verify.container.zst" >"${tmpdir}/verify-deploy.log" 2>&1
   if [[ -n "${active_state}" ]]
   then
      queued=0
      for _ in $(seq 1 120)
      do
         if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
            timeout 8s "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" Nametag >"${tmpdir}/recovery-admission-report.log" 2>&1 &&
            report_version_ready "${tmpdir}/recovery-admission-report.log" "${version_id}" 3 "${initial_healthy}" "${active_state}" &&
            report_version_ready "${tmpdir}/recovery-admission-report.log" "$((version_id + 1))" 0 0 waitingToDeploy
         then
            queued=1
            break
         fi
         sleep 0.5
      done
      [[ "${queued}" == 1 ]] || { echo "FAIL: exact retained 3/${initial_healthy} predecessor and empty waiting successor not observed" >&2; exit 1; }
      python3 - "${version_id}" "${tmpdir}/verify.container.zst" "${tmpdir}/recovery-request.json" <<'PY_RECOVERY_REQUEST'
import hashlib, json, pathlib, sys, uuid
version, blob, output = sys.argv[1:]
request = dict(applicationName='Nametag', applicationID=6, activeVersionID=int(version),
               successorVersionID=int(version) + 1, operationID=str(uuid.uuid4()),
               successorBlobSHA256=hashlib.sha256(pathlib.Path(blob).read_bytes()).hexdigest())
pathlib.Path(output).write_text(json.dumps(request) + '\n')
PY_RECOVERY_REQUEST
      for admission in initial retry
      do
         env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
            timeout 15s "${MOTHERSHIP_BIN}" recoverMaterializedStatefulDeployment "${cluster_name}" \
            "$(cat "${tmpdir}/recovery-request.json")" >"${tmpdir}/recovery-${admission}.log" 2>&1
         python3 - "${tmpdir}/recovery-request.json" "${tmpdir}/recovery-${admission}.log" <<'PY_RECOVERY_ACCEPTED'
import json, pathlib, re, sys
request = json.loads(pathlib.Path(sys.argv[1]).read_text())
text = pathlib.Path(sys.argv[2]).read_text()
line = next((line for line in text.splitlines() if line.startswith('recoverMaterializedStatefulDeployment accepted=')), '')
fields = dict(re.findall(r'(\w+)=([^\s]*)', line))
assert fields.get('accepted') == '1' and fields.get('failure') == '', line
assert fields.get('operationID') == request['operationID'], line
assert int(fields['appID']) == request['applicationID']
for name in ('activeVersionID', 'successorVersionID'):
    assert int(fields[name]) == request[name]
    deployment = name.replace('VersionID', 'DeploymentID')
    assert int(fields[deployment]) == ((request['applicationID'] << 48) | request[name])
assert int(fields['durableGeneration']) > 0, line
print('RECOVERY_API_ACCEPTED', pathlib.Path(sys.argv[2]).name, request['operationID'])
PY_RECOVERY_ACCEPTED
      done
   fi
   # Each replacement waits for actual predecessor exit, then actual health.
   # Budget every serial stop grace; a fixed one-minute loop cuts off replica 3.
   handoff_wait_seconds="$(python3 - "${plan_json}" "${expected_healthy}" <<'PY_HANDOFF_WAIT'
import json, sys
with open(sys.argv[1]) as stream:
    config = json.load(stream)['config']
per_replica = config['sTilKillable'] + (config['msTilHealthy'] + 999) // 1000 + config['sTilHealthcheck']
print(int(sys.argv[2]) * per_replica + 30)
PY_HANDOFF_WAIT
)"
   healthy=0
   handoff_started=${SECONDS}
   handoff_deadline=$((handoff_started + handoff_wait_seconds))
   attempt=0
   while (( SECONDS < handoff_deadline ))
   do
      attempt=$((attempt + 1))
      if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         timeout 8s "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" Nametag >"${tmpdir}/verify-report.log" 2>&1 &&
         report_version_ready "${tmpdir}/verify-report.log" "$((version_id + 1))" 3
      then
         healthy=1
      fi
      printf 'attempt=%s elapsedSeconds=%s budgetSeconds=%s\n' \
         "${attempt}" "$((SECONDS - handoff_started))" "${handoff_wait_seconds}" >>"${tmpdir}/verify-report-samples.log"
      cat "${tmpdir}/verify-report.log" >>"${tmpdir}/verify-report-samples.log"
      [[ "${healthy}" != 1 ]] || break
      sleep 0.5
   done
   [[ "${healthy}" == 1 ]] || { echo "FAIL: successor did not become healthy within ${handoff_wait_seconds}s serial handoff budget" >&2; exit 1; }
   observe_handoff after
   }

   if [[ "${test_mode}" == initial-health-zero ]]
   then
      # nDeployed is a scheduler admission count. Reuse the exact owner observer
      # as the materialization barrier; it writes handoff-before.json only after
      # the three sealed processes and their seeded storage are verified.
      observe_deadline=$((SECONDS + 60))
      observe_attempt=0
      : > "${tmpdir}/initial-replica-observe-attempts.log"
      while (( SECONDS < observe_deadline ))
      do
         observe_attempt=$((observe_attempt + 1))
         if observe_handoff before >> "${tmpdir}/initial-replica-observe-attempts.log" 2>&1
         then
            break
         fi
         printf 'attempt=%s elapsedSeconds=%s\n' "${observe_attempt}" "$((SECONDS + 60 - observe_deadline))" \
            >> "${tmpdir}/initial-replica-observe-attempts.log"
         sleep 0.5
      done
      [[ -s "${tmpdir}/handoff-before.json" ]] || {
         echo "FAIL: initial-health-zero fixture replicas were not materialized within 60s" >&2
         tail -80 "${tmpdir}/initial-replica-observe-attempts.log" >&2 || true
         exit 1
      }
   else
      observe_handoff before
   fi
   if [[ "${test_mode}" == initial-health-zero ]]
   then
      run_successor_handoff deploying
      echo "PASS: direct-runtime initial 3/0 health recovery, durable idempotent operation and three-replica storage readback"
      exit 0
   fi
   if [[ "${test_mode}" == follower-retained ]]; then
      # This is a bounded mechanics/storage experiment with finite endpoint and
      # control-socket observations. It does not claim uninterrupted traffic or
      # a production follower-replacement protocol.
      env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         timeout 8s "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" >"${tmpdir}/follower-before-cluster.log" 2>&1
      follower_machine_index="$(python3 - "${tmpdir}/follower-before-cluster.log" "${tmpdir}/handoff-before.json" "${manifest_path}" <<'PY_FOLLOWER_SELECT'
import json, pathlib, re, sys
report, before = map(pathlib.Path, sys.argv[1:3])
nodes = json.loads(pathlib.Path(sys.argv[3]).read_text())['nodes']
by_address = {node['ipv4']: int(node['index']) for node in nodes}
assert len(by_address) == 3, 'fixture has duplicate machine addresses'
text = report.read_text()
blocks = re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)', text)
records = json.loads(before.read_text())
actual = {int(record['machineIndex']) for record in records}
assert len(blocks) == 3 and len(actual) == 3, 'fixture is not three machines with three live replicas'
candidates = []
seen = set()
masters = 0
for block in blocks:
    identity = re.search(r'(?m)^[ \t]*identity uuid=(0x[0-9a-f]+) .*sshAddress=(\S+)', block)
    assert identity and identity.group(2) in by_address, 'reported machine is outside fixture'
    index = by_address[identity.group(2)]
    assert index not in seen, 'report repeats a fixture machine'
    seen.add(index)
    lifecycle = re.search(r'(?m)^[ \t]*lifecycle .*currentMaster=(\d)\b', block)
    assert lifecycle and lifecycle.group(1) in ('0', '1'), 'missing master identity'
    masters += int(lifecycle.group(1))
    if lifecycle.group(1) == '0' and index in actual:
        candidates.append(index)
assert candidates and masters == 1, 'fixture needs one master and an observed nonmaster replica'
print(min(candidates))
PY_FOLLOWER_SELECT
      )"
      [[ "${follower_machine_index}" =~ ^[123]$ ]] || { echo "FAIL: could not select an observed nonmaster fixture replica" >&2; exit 1; }
      [[ "${follower_machine_index}" == "${follower_ingress_machine_index}" ]] || {
         archive_workspace=1
         echo "FAIL: retained follower ingress machine became master before replacement" >&2
         exit 1
      }
      follower_traffic_history="${tmpdir}/follower-traffic-history.jsonl"
      follower_recovery_windows="${tmpdir}/follower-recovery-windows.jsonl"
      follower_traffic_phase="${tmpdir}/follower-traffic-phase"
      follower_traffic_stop="${tmpdir}/follower-traffic-stop"
      follower_traffic_sampler_active="${tmpdir}/follower-traffic-sampler-active"
      : > "${follower_traffic_history}"
      : > "${follower_recovery_windows}"
      printf 'baseline\n' > "${follower_traffic_phase}"
      cat > "${tmpdir}/follower-wormhole-coverage.txt" <<EOF
The 198.18.0.1:19090 probe enters through the registered single-machine
Switchboard wormhole bound to retained follower ${follower_machine_index}. It
proves selected-follower ingress and a routed ping/pong request to the separate
stateless traffic deployment; that application's replica may be scheduled on a
different fixture machine.
EOF
      follower_monotonic_ns()
      {
         python3 -c 'import time; print(time.monotonic_ns())'
      }
      record_follower_recovery_window()
      {
         python3 - "${follower_recovery_windows}" "$1" "$2" "$3" "$4" <<'PY_FOLLOWER_RECOVERY_WINDOW'
import json, pathlib, sys
path, name, start, end, status = sys.argv[1:]
record = dict(name=name, startMonotonicNs=int(start), endMonotonicNs=int(end), exitStatus=int(status))
with pathlib.Path(path).open('a', encoding='utf-8') as stream:
    stream.write(json.dumps(record, sort_keys=True) + '\n')
PY_FOLLOWER_RECOVERY_WINDOW
      }
      probe_follower_traffic()
      {
         local phase="$1" output="${tmpdir}/follower-traffic-probe-${BASHPID}.log" status start_ns end_ns
         start_ns="$(follower_monotonic_ns)"
         [[ "${follower_traffic_sampler_running:-0}" != 1 ]] || : > "${follower_traffic_sampler_active}"
         set +e
         env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
            timeout 4s "${MOTHERSHIP_BIN}" probeTestCluster "${cluster_name}" \
            "${follower_wormhole_address}" 19090 ping pong 1500 0 >"${output}" 2>&1
         status=$?
         set -e
         end_ns="$(follower_monotonic_ns)"
         follower_traffic_last_ok="$(python3 - "${follower_traffic_history}" "${phase}" "${start_ns}" "${end_ns}" "${status}" "${output}" <<'PY_FOLLOWER_TRAFFIC_SAMPLE'
import json, pathlib, re, sys
history, phase, start, end, status, output = sys.argv[1:]
text = pathlib.Path(output).read_text(encoding='utf-8', errors='replace')
ok = int(status) == 0 and bool(re.search(r'^probeTestCluster success=1\b', text, re.M))
if ok:
    classification = 'success'
elif re.search(r'TidesDB|registry|database.*(?:lock|busy)|(?:lock|busy).*database', text, re.I):
    classification = 'control'
else:
    classification = 'probe'
record = dict(phase=phase, startMonotonicNs=int(start), endMonotonicNs=int(end),
              exitStatus=int(status), success=ok, classification=classification, response=text)
with open(history, 'a', encoding='utf-8') as stream:
    stream.write(json.dumps(record, sort_keys=True) + '\n')
print(1 if ok else 0)
PY_FOLLOWER_TRAFFIC_SAMPLE
)"
      }
      for baseline_probe in $(seq 1 5)
      do
         probe_follower_traffic baseline
         [[ "${follower_traffic_last_ok}" == 1 ]] || {
            archive_workspace=1
            echo "FAIL: retained follower baseline wormhole probe ${baseline_probe} failed" >&2
            cat "${follower_traffic_history}" >&2 || true
            exit 1
         }
      done
      follower_traffic_loop_pid=""
      start_follower_traffic_history()
      {
         rm -f "${follower_traffic_stop}" "${follower_traffic_sampler_active}"
         (
            follower_traffic_sampler_running=1
            while [[ ! -e "${follower_traffic_stop}" ]]
            do
               local_phase="$(cat "${follower_traffic_phase}" 2>/dev/null || printf unknown)"
               # The marker is written once the sampled interval has started;
               # overlap is still proven below from measured intervals.
               probe_follower_traffic "${local_phase}"
               sleep 0.25
            done
         ) &
         follower_traffic_loop_pid=$!
         owned_background_pids+=("${follower_traffic_loop_pid}")
      }
      stop_follower_traffic_history()
      {
         [[ -n "${follower_traffic_loop_pid}" ]] || return 0
         : > "${follower_traffic_stop}"
         wait "${follower_traffic_loop_pid}" || true
         filtered_background_pids=()
         for background_pid in "${owned_background_pids[@]}"
         do
            [[ "${background_pid}" == "${follower_traffic_loop_pid}" ]] || filtered_background_pids+=("${background_pid}")
         done
         owned_background_pids=("${filtered_background_pids[@]}")
         follower_traffic_loop_pid=""
      }
      follower_peer_observer_arguments=()
      if [[ -n "${PRODIGY_STORAGE_HANDOFF_PEER_MEMORY_LAYOUT:-}" ]]; then
         follower_peer_observer_arguments+=(--peer-memory-layout "${PRODIGY_STORAGE_HANDOFF_PEER_MEMORY_LAYOUT}")
      fi
      python3 -B "${SCRIPT_DIR}/prodigy_dev_retained_quorum_observer.py" "${follower_peer_observer_arguments[@]}" \
         --phase before --manifest "${manifest_path}" \
         --cluster-report "${tmpdir}/follower-before-cluster.log" \
         --selected-index "${follower_machine_index}" --evidence-root "${tmpdir}"
      start_follower_traffic_history
      for _ in $(seq 1 80)
      do
         [[ -e "${follower_traffic_sampler_active}" ]] && break
         sleep 0.05
      done
      [[ -e "${follower_traffic_sampler_active}" ]] || {
         archive_workspace=1
         echo "FAIL: retained follower traffic sampler did not begin a recovery probe" >&2
         exit 1
      }
      observe_follower_fault_pause()
      {
         python3 - "${manifest_path}" "${tmpdir}/handoff-before.json" "${handoff_id}" \
            "${follower_machine_index}" "${PINGPONG_BIN}" "${tmpdir}/follower-fault-pause-observation.json" <<'PY_FOLLOWER_FAULT_PAUSE'
import hashlib, json, pathlib, sys
manifest = pathlib.Path(sys.argv[1])
before_path = pathlib.Path(sys.argv[2])
identity = sys.argv[3]
selected = int(sys.argv[4])
executable = pathlib.Path(sys.argv[5])
output = pathlib.Path(sys.argv[6])
expected_binary = hashlib.sha256(executable.read_bytes()).hexdigest()
before = json.loads(before_path.read_text())
nodes = {int(node['index']): node for node in json.loads(manifest.read_text())['nodes']}
assert len(before) == 3 and len(nodes) == 3 and {int(record['machineIndex']) for record in before} == {1, 2, 3}, \
    'fault pause requires the original three-replica snapshot'
observed = []
for prior in before:
    child = pathlib.Path('/proc') / str(prior['pid'])
    assert child.exists(), 'original application process disappeared during coordinator fault pause'
    assert (child / 'exe').readlink().name == 'pingpong_container'
    assert hashlib.sha256((child / 'exe').read_bytes()).hexdigest() == expected_binary
    starttime = (child / 'stat').read_text().rsplit(') ', 1)[1].split()[19]
    assert starttime == prior['starttime'], 'application PID was recycled during coordinator fault pause'
    network_namespace = str((child / 'ns/net').readlink())
    cgroup = (child / 'cgroup').read_text()
    assert network_namespace == prior['networkNamespace'] and cgroup == prior['cgroup'], 'application namespace or cgroup changed during coordinator fault pause'
    storage = child / 'root/storage'
    metadata = storage.stat()
    assert (metadata.st_dev, metadata.st_ino) == (prior['device'], prior['inode']), 'application storage owner changed during coordinator fault pause'
    sparse = storage / 'kvdb/handoff-sparse'
    with sparse.open('rb') as stream:
        assert stream.read(32) == identity.encode(), 'application storage identity marker changed during coordinator fault pause'
        stream.seek(1 << 40); assert stream.read(1) == b'M', 'application storage middle marker changed during coordinator fault pause'
        stream.seek((1 << 41) - 1); assert stream.read(1) == b'Z', 'application storage tail marker changed during coordinator fault pause'
    assert sparse.stat().st_size == 1 << 41 and sparse.stat().st_blocks * 512 < 1024 * 1024, 'application sparse storage changed during coordinator fault pause'
    index = int(prior['machineIndex'])
    if index != selected:
        parent = pathlib.Path('/proc') / str(prior['parentPID'])
        assert parent.exists(), 'unselected Brain process disappeared during coordinator fault pause'
        parent_starttime = (parent / 'stat').read_text().rsplit(') ', 1)[1].split()[19]
        assert parent_starttime == prior['parentStarttime']
        assert hashlib.sha256((parent / 'exe').read_bytes()).hexdigest() == prior['runtimeSHA256']
        assert str((parent / 'ns/net').readlink()) == prior['parentNetworkNamespace']
        assert (parent / 'cgroup').read_text() == prior['parentCgroup']
    observed.append(dict(machineIndex=index, pid=prior['pid'], starttime=starttime,
                         device=metadata.st_dev, inode=metadata.st_ino,
                         networkNamespace=network_namespace, cgroup=cgroup))
output.write_text(json.dumps(observed, indent=2) + '\n')
print('FOLLOWER_FAULT_PAUSE_PASS replicas=3 selectedMachine=' + str(selected))
PY_FOLLOWER_FAULT_PAUSE
      }
      if [[ -n "${follower_fault_after_phase}" ]]
      then
         printf 'fault-command:%s\n' "${follower_fault_after_phase}" > "${follower_traffic_phase}"
         follower_fault_start_ns="$(follower_monotonic_ns)"
         set +e
         env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
            "${MOTHERSHIP_BIN}" recoverTestClusterFollowerBrain "${cluster_name}" "${upgrade_bundle}" \
            "${follower_machine_index}" "${old_bundle_sha}" "${follower_fault_after_phase}" \
            >"${tmpdir}/follower-fault.log" 2>&1
         follower_fault_status=$?
         set -e
         follower_fault_end_ns="$(follower_monotonic_ns)"
         record_follower_recovery_window "fault-command:${follower_fault_after_phase}" "${follower_fault_start_ns}" "${follower_fault_end_ns}" "${follower_fault_status}"
         [[ "${follower_fault_status}" == 86 ]] || {
            echo "FAIL: follower recovery fault command exited ${follower_fault_status}, expected 86" >&2
            sed -n '1,160p' "${tmpdir}/follower-fault.log" >&2 || true
            exit 1
         }
         python3 - "${tmpdir}/follower-fault.log" "${tmpdir}/follower-fault-receipt.json" \
            "${follower_machine_index}" "${follower_fault_after_phase}" <<'PY_FOLLOWER_FAULT_RECEIPT'
import json, pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
line = next((line for line in text.splitlines() if line.startswith('recoverTestClusterFollowerBrain testFault=')), '')
fields = dict(re.findall(r'(\w+)=([^\s]*)', line))
assert fields.get('testFault') == '1' and fields.get('phase') == sys.argv[4], line
assert fields.get('machineIndex') == sys.argv[3] and fields.get('before_exit') == '86', line
assert re.fullmatch(r'0x[0-9a-f]{1,32}', fields.get('operationID', '')) and int(fields['operationID'], 16) != 0, line
pathlib.Path(sys.argv[2]).write_text(json.dumps(dict(operationID=fields['operationID'], machineIndex=fields['machineIndex'], phase=fields['phase']), sort_keys=True) + '\n')
print('FOLLOWER_FAULT_RECEIPT_PASS', fields['operationID'])
PY_FOLLOWER_FAULT_RECEIPT
         printf 'fault-pause:%s\n' "${follower_fault_after_phase}" > "${follower_traffic_phase}"
         follower_pause_start_ns="$(follower_monotonic_ns)"
         follower_pause_deadline=$((SECONDS + 3))
         while (( SECONDS < follower_pause_deadline ))
         do
            # The existing sampler is the sole probe client; overlapping probe
            # CLIs contend for the registry file lock before they send traffic.
            sleep 0.05
         done
         follower_pause_end_ns="$(follower_monotonic_ns)"
         record_follower_recovery_window "fault-pause:${follower_fault_after_phase}" "${follower_pause_start_ns}" "${follower_pause_end_ns}" 0
         # Observe the still-running master before any replacement starts.
         # Retained PIDs alone cannot prove that it still owns their plans.
         follower_pause_control_socket="$(jq -er '.controlSocketPath | select(type == "string" and length > 0)' "${manifest_path}")"
         env PRODIGY_MOTHERSHIP_SOCKET="${follower_pause_control_socket}" \
            timeout 8s "${MOTHERSHIP_BIN}" clusterReport local >"${tmpdir}/follower-pause-cluster.log" 2>&1
         env PRODIGY_MOTHERSHIP_SOCKET="${follower_pause_control_socket}" \
            timeout 8s "${MOTHERSHIP_BIN}" applicationReport local Nametag >"${tmpdir}/follower-pause-application.log" 2>&1
         observe_follower_fault_pause >"${tmpdir}/follower-fault-pause.log" 2>&1 || {
            echo "FAIL: coordinator fault pause changed a retained application or unselected Brain owner" >&2
            cat "${tmpdir}/follower-fault-pause.log" >&2 || true
            exit 1
         }
      fi
      for retry in initial retry
      do
         printf 'resume-%s\n' "${retry}" > "${follower_traffic_phase}"
         follower_resume_start_ns="$(follower_monotonic_ns)"
         set +e
         env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
            "${MOTHERSHIP_BIN}" recoverTestClusterFollowerBrain "${cluster_name}" "${upgrade_bundle}" \
            "${follower_machine_index}" "${old_bundle_sha}" >"${tmpdir}/follower-${retry}.log" 2>&1
         follower_resume_status=$?
         set -e
         follower_resume_end_ns="$(follower_monotonic_ns)"
         record_follower_recovery_window "resume-${retry}" "${follower_resume_start_ns}" "${follower_resume_end_ns}" "${follower_resume_status}"
         [[ "${follower_resume_status}" == 0 ]] || exit "${follower_resume_status}"
         python3 - "${tmpdir}/follower-${retry}.log" "${tmpdir}/follower-initial-receipt.json" \
            "${follower_machine_index}" "${old_bundle_sha}" <<'PY_FOLLOWER_RECEIPT'
import json, pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
line = next((line for line in text.splitlines() if line.startswith('recoverTestClusterFollowerBrain accepted=')), '')
fields = dict(re.findall(r'(\w+)=([^\s]*)', line))
assert fields.get('accepted') == '1', line
assert fields.get('machineIndex') == sys.argv[3], line
assert fields.get('sourceSHA256') == sys.argv[4], line
assert re.fullmatch(r'[0-9a-f]{64}', fields.get('successorSHA256', '')), line
assert re.fullmatch(r'0x[0-9a-f]{1,32}', fields.get('operationID', '')) and int(fields['operationID'], 16) != 0, line
receipt = dict(operationID=fields['operationID'], machineIndex=fields['machineIndex'],
               sourceSHA256=fields['sourceSHA256'], successorSHA256=fields['successorSHA256'])
path = pathlib.Path(sys.argv[2])
fault_path = path.with_name('follower-fault-receipt.json')
if fault_path.exists():
    fault = json.loads(fault_path.read_text())
    assert receipt['operationID'] == fault['operationID'] and receipt['machineIndex'] == fault['machineIndex'], \
        'resume changed the durable faulted operation or selected member'
if path.exists():
    assert json.loads(path.read_text()) == receipt, 'retry changed follower operation/member/target receipt'
else:
    path.write_text(json.dumps(receipt, sort_keys=True) + '\n')
print('FOLLOWER_RECOVERY_RECEIPT_PASS', pathlib.Path(sys.argv[1]).name, receipt['operationID'])
PY_FOLLOWER_RECEIPT
      done
      follower_target_bundle_sha="$(python3 - "${tmpdir}/follower-initial-receipt.json" <<'PY_FOLLOWER_TARGET'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())['successorSHA256'])
PY_FOLLOWER_TARGET
)"
      observe_handoff follower-step >"${tmpdir}/follower-owner-observe.log" 2>&1 || {
         echo "FAIL: retained follower replacement changed a live application/storage owner" >&2; exit 1;
      }
      follower_final_cluster_ready()
      {
         python3 - "${tmpdir}/follower-after-cluster.log" "${tmpdir}/follower-before-cluster.log" <<'PY_FOLLOWER_FINAL'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
blocks = re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)', text)
assert len(blocks) == 3, 'final report does not contain all three machines'
def identities(report):
    return set(re.findall(r'(?m)^[ \t]*identity uuid=(0x[0-9a-f]+) ', report))
assert len(identities(text)) == 3 and identities(text) == identities(pathlib.Path(sys.argv[2]).read_text()), 'commissioned member identities changed'
masters = 0
for index, block in enumerate(blocks, 1):
    state = re.search(r'^[ \t]*Machine: state=(\S+) role=brain ', block, re.M)
    lifecycle = re.search(r'(?m)^[ \t]*lifecycle controlPlaneReachable=(\d) runtimeReady=(\d) currentMaster=(\d)', block)
    assert state and state.group(1) == 'healthy', 'follower fixture lost a healthy Brain'
    assert lifecycle and lifecycle.group(1, 2) == ('1', '1'), 'follower fixture is not control-plane/runtime ready'
    masters += int(lifecycle.group(3))
assert masters == 1, 'follower fixture does not report exactly one current master'
print('FOLLOWER_FINAL_REPORT_PASS masters=1')
PY_FOLLOWER_FINAL
      }
      # Named reports refresh the registry, which would race the continuous
      # provider probe's registry lookup. Observe through the exact socket
      # published by this fixture's Mothership provider instead.
      follower_control_socket="$(jq -er '.controlSocketPath | select(type == "string" and length > 0)' "${manifest_path}")"
      [[ -S "${follower_control_socket}" ]] || { echo "FAIL: follower control socket is unavailable" >&2; exit 1; }
      final_ready=0
      printf 'final-readiness\n' > "${follower_traffic_phase}"
      follower_final_readiness_start_ns="$(follower_monotonic_ns)"
      follower_ready_deadline=$((SECONDS + 90))
      while (( SECONDS < follower_ready_deadline ))
      do
         if env PRODIGY_MOTHERSHIP_SOCKET="${follower_control_socket}" \
               timeout 15s "${MOTHERSHIP_BIN}" clusterReport local >"${tmpdir}/follower-after-cluster.log" 2>&1 &&
            env PRODIGY_MOTHERSHIP_SOCKET="${follower_control_socket}" \
               timeout 8s "${MOTHERSHIP_BIN}" applicationReport local Nametag >"${tmpdir}/follower-after-application.log" 2>&1 &&
            env PRODIGY_MOTHERSHIP_SOCKET="${follower_control_socket}" \
               timeout 8s "${MOTHERSHIP_BIN}" applicationReport local "${follower_traffic_application_name}" >"${tmpdir}/follower-traffic-after-application.log" 2>&1 &&
            follower_final_cluster_ready &&
            report_version_ready "${tmpdir}/follower-after-application.log" "${version_id}" 3 3 running &&
            report_version_ready "${tmpdir}/follower-traffic-after-application.log" "${follower_traffic_version_id}" 1 1 running
         then
            final_ready=1
            break
         fi
         sleep 0.5
      done
      follower_final_readiness_end_ns="$(follower_monotonic_ns)"
      if [[ "${final_ready}" == 1 ]]; then follower_final_readiness_status=0; else follower_final_readiness_status=1; fi
      record_follower_recovery_window "final-readiness" "${follower_final_readiness_start_ns}" "${follower_final_readiness_end_ns}" "${follower_final_readiness_status}"
      if [[ "${final_ready}" != 1 ]]; then
         # Retain an independent control-pair observation even when the selected
         # runtime or app is unavailable. It cannot turn this failed run green.
         python3 -B "${SCRIPT_DIR}/prodigy_dev_retained_quorum_observer.py" "${follower_peer_observer_arguments[@]}" \
            --phase after --manifest "${manifest_path}" \
            --cluster-report "${tmpdir}/follower-after-cluster.log" \
            --selected-index "${follower_machine_index}" --evidence-root "${tmpdir}" || true
         echo "FAIL: follower fixture did not recover full three-Brain readiness with three non-crashing replicas" >&2
         exit 1
      fi
      # Drain the concurrent recovery sampler before the bounded serial dwell.
      stop_follower_traffic_history
      printf 'after-ready\n' > "${follower_traffic_phase}"
      for after_probe in $(seq 1 10)
      do
         probe_follower_traffic after-ready
         [[ "${follower_traffic_last_ok}" == 1 ]] || {
            archive_workspace=1
            stop_follower_traffic_history
            echo "FAIL: retained follower post-ready wormhole probe ${after_probe} failed" >&2
            cat "${follower_traffic_history}" >&2 || true
            exit 1
         }
         sleep 0.2
      done
      stop_follower_traffic_history
      # Preserve independent surviving-peer evidence even if sampled traffic failed.
      python3 -B "${SCRIPT_DIR}/prodigy_dev_retained_quorum_observer.py" "${follower_peer_observer_arguments[@]}" \
         --phase after --manifest "${manifest_path}" \
         --cluster-report "${tmpdir}/follower-after-cluster.log" \
         --selected-index "${follower_machine_index}" --evidence-root "${tmpdir}"
      python3 - "${follower_traffic_history}" "${follower_recovery_windows}" <<'PY_FOLLOWER_TRAFFIC_HISTORY'
import json, pathlib, sys
records = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line]
windows = [json.loads(line) for line in pathlib.Path(sys.argv[2]).read_text().splitlines() if line]
assert len(records) >= 15, 'traffic history omitted required baseline or post-ready samples'
assert sum(record['phase'] == 'baseline' and record['success'] for record in records) >= 5, 'traffic history lacks five successful baseline probes'
assert sum(record['phase'] == 'after-ready' and record['success'] for record in records) >= 10, 'traffic history lacks ten successful post-ready probes'
assert windows and all(window['endMonotonicNs'] >= window['startMonotonicNs'] for window in windows), 'recovery timing receipt is malformed'
for window in windows:
    window['overlappingProbes'] = sum(record['startMonotonicNs'] < window['endMonotonicNs'] and
                                    record['endMonotonicNs'] > window['startMonotonicNs'] for record in records)
    window['elapsedMs'] = (window['endMonotonicNs'] - window['startMonotonicNs']) / 1e6
# A short idempotent RPC can fit between samples. Preserve its measured coverage
# instead of claiming every command was observed by a concurrent request.
assert any(window['overlappingProbes'] for window in windows if window['name'] != 'final-readiness'), \
    'no measured traffic probe overlapped a recovery command'
pathlib.Path(sys.argv[2]).with_name('follower-recovery-timing.json').write_text(json.dumps(windows, indent=2) + '\n')
assert all(record['success'] for record in records), 'traffic history contains a failed control-plane or data-plane observation'
print('FOLLOWER_TRAFFIC_HISTORY_PASS samples=' + str(len(records)))
PY_FOLLOWER_TRAFFIC_HISTORY
      echo "PASS: retained follower mechanics/storage experiment with finite zero-failure wormhole traffic history selectedMachine=${follower_machine_index} replicas=3"
      exit 0
   elif [[ "${test_mode}" == provider-handoff ]]; then
      for machine_index in 2 3 4 1; do
         env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
            "${MOTHERSHIP_BIN}" recoverTestClusterBundle "${cluster_name}" "${upgrade_bundle}" "${machine_index}" "${old_bundle_sha}" >>"${tmpdir}/upgrade.log" 2>&1
         env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
            "${MOTHERSHIP_BIN}" recoverTestClusterBundle "${cluster_name}" "${upgrade_bundle}" "${machine_index}" "${old_bundle_sha}" >>"${tmpdir}/upgrade.log" 2>&1
         observe_handoff provider-step
         cp "${tmpdir}/handoff-provider-step.json" "${tmpdir}/handoff-provider-machine-${machine_index}.json"
      done
   elif [[ "${test_mode}" == bootstrap-supersession ]]; then
      # Keep one existing worker disconnected while the ordinary update owner
      # persists a real incomplete worker operation. Both actions remain
      # Mothership requests; this fixture owns only their bounded CLI children.
      env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" faultTestCluster "${cluster_name}" link 2 "${fault_duration_ms}" 0 0 0 >"${tmpdir}/bootstrap-fault.log" 2>&1 &
      fault_pid=$!
      owned_background_pids+=("${fault_pid}")
      # The provider owns the parent netns. Read its authoritative runtime
      # identity and verify vp2 is actually DOWN before starting the update.
      fault_down=0
      for attempt in $(seq 1 120)
      do
         provider_pid="$(cat "${workspace_root}/virtual-datacenter.pid" 2>/dev/null || true)"
         # The sealed predecessor predates the identity file; its resource
         # namespace is named by the original provider PID.
         runtime_identity="${provider_pid}"
         if [[ -e "${workspace_root}/virtual-datacenter.identity" ]]
         then
            runtime_identity="$(cat "${workspace_root}/virtual-datacenter.identity" 2>/dev/null || true)"
         fi
         if [[ "${provider_pid}" =~ ^[0-9]+$ && "${runtime_identity}" =~ ^[0-9]+$ ]] &&
            kill -0 "${fault_pid}" >/dev/null 2>&1 && kill -0 "${provider_pid}" >/dev/null 2>&1 &&
            nsenter -t "${provider_pid}" -m -- ip netns exec "pvd-p-${runtime_identity}" ip -o link show vp2 >"${tmpdir}/bootstrap-fault-link-${attempt}.log" 2>&1 &&
            rg -q 'state DOWN' "${tmpdir}/bootstrap-fault-link-${attempt}.log"
         then
            printf 'attempt=%s providerPid=%s runtimeIdentity=%s vp2=DOWN\n' "${attempt}" "${provider_pid}" "${runtime_identity}" >>"${tmpdir}/bootstrap-fault-observation.log"
            fault_down=1
            break
         fi
         sleep 0.5
      done
      [[ "${fault_down}" == 1 ]] || { echo "FAIL: Mothership link fault did not make provider parent-netns vp2 DOWN" >&2; exit 1; }
      timeout 120s env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" updateProdigy "${cluster_name}" "${interrupted_bundle}" >"${tmpdir}/bootstrap-interrupted-update.log" 2>&1 &
      interrupted_update_pid=$!
      owned_background_pids+=("${interrupted_update_pid}")
      pending=0
      for attempt in $(seq 1 120)
      do
         if kill -0 "${fault_pid}" >/dev/null 2>&1 &&
            kill -0 "${interrupted_update_pid}" >/dev/null 2>&1 &&
            env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
               timeout 8s "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" >"${tmpdir}/bootstrap-pending-cluster-${attempt}.log" 2>&1 &&
            rg -q "stagedBundleSHA256=${interrupted_bundle_sha}" "${tmpdir}/bootstrap-pending-cluster-${attempt}.log"
         then
            printf 'attempt=%s updatePid=%s state=deferred stagedBundleSHA256=%s\n' "${attempt}" "${interrupted_update_pid}" "${interrupted_bundle_sha}" >>"${tmpdir}/bootstrap-pending.log"
            pending=1
            break
         fi
         sleep 0.5
      done
      [[ "${pending}" == 1 ]] || { echo "FAIL: interrupted ordinary update was not observably deferred while link fault was active" >&2; exit 1; }
      env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" recoverTestClusterBundle "${cluster_name}" "${upgrade_bundle}" 1 "${old_bundle_sha}" "${interrupted_bundle_sha}" >>"${tmpdir}/bootstrap-recover.log" 2>&1
      # The replacement Brain owns completion of the original update request;
      # the CLI may exit on its old control stream, so preserve its receipt and
      # assert the actual post-recovery worker and storage observations below.
      wait "${fault_pid}" || true
      wait "${interrupted_update_pid}" || true
      owned_background_pids=()
   else
      env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" updateProdigy "${cluster_name}" "${upgrade_bundle}" >"${tmpdir}/upgrade.log" 2>&1
   fi
   # updateProdigy acknowledges staging before every worker has completed its
   # exec handoff. Wait for observed exact bytes, not a staged=1 response.
   upgraded=0
   for attempt in $(seq 1 240)
   do
      printf 'attempt=%s\n' "${attempt}" >> "${tmpdir}/upgrade-observer.log"
      if observe_handoff upgraded >> "${tmpdir}/upgrade-observer.log" 2>&1
      then
         upgraded=1
         break
      fi
      sleep 0.5
   done
   [[ "${upgraded}" == 1 ]] || { archive_workspace=1; echo "FAIL: exact worker-preserving bundle upgrade was not observed" >&2; exit 1; }
   recovered=0
   for attempt in $(seq 1 240)
   do
      if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         timeout 8s "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" Nametag >"${tmpdir}/upgrade-recovery-report.log" 2>&1
      then
         printf 'attempt=%s\n' "${attempt}" >> "${tmpdir}/upgrade-recovery-samples.log"
         cat "${tmpdir}/upgrade-recovery-report.log" >> "${tmpdir}/upgrade-recovery-samples.log"
         if report_version_ready "${tmpdir}/upgrade-recovery-report.log" "${version_id}" 3 "${initial_healthy}" "${recovered_state}"
         then
            recovered=1
            break
         fi
      fi
      sleep 0.5
   done
   [[ "${recovered}" == 1 ]] || { archive_workspace=1; echo "FAIL: original deployment control-plane recovery not observed; no successor submitted" >&2; exit 1; }
   # Readiness counters alone can conceal fresh replicas created after exec.
   # Re-observe the original owners after recovery settles, before any update.
   observe_handoff recovered || {
      archive_workspace=1
      echo "FAIL: controller recovery replaced original application/storage owners; no successor submitted" >&2
      exit 1
   }
   recovery_active_state=""
   if [[ "${test_mode}" == legacy-recovery || "${test_mode}" == legacy-recovery-zero ]]
   then
      recovery_active_state=none
   fi
   run_successor_handoff "${recovery_active_state}"
   if [[ "${test_mode}" == legacy-recovery || "${test_mode}" == legacy-recovery-zero ]]
   then
      echo "PASS: durably admitted retained 3/${initial_healthy} recovery, idempotent retry and three-replica storage readback"
   else
      echo "PASS: worker-preserving bundle upgrade and lifecycle-quiesced legacy storage handoff with logical readback"
   fi
   exit 0
fi

# A host-side storage filesystem alone does not prove the application mounted
# it. A failed bind used to leave a healthy process writing into its rootfs.
# Observe the exact Mothership-owned child and compare its live /storage inode
# with the declared payload, without entering or mutating the container.
if ! python3 - "${brain_pid}" "${PINGPONG_BIN}" "${storage_devices}" >"${tmpdir}/container-storage-mount.json" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

brain = pathlib.Path('/proc') / sys.argv[1]
children = (brain / 'task' / sys.argv[1] / 'children').read_text().split()
matches = []
for pid in children:
    process = pathlib.Path('/proc') / pid
    try:
        if (process / 'exe').readlink().name == 'pingpong_container':
            matches.append(process)
    except (FileNotFoundError, ProcessLookupError):
        pass
assert len(matches) == 1, f'expected one owned pingpong child, found {len(matches)}'
process = matches[0]
mountinfo = (process / 'mountinfo').read_text()
mounts = [line for line in mountinfo.splitlines() if line.split()[4] == '/storage']
assert len(mounts) == 1, 'application lacks its required /storage mount'
assert ' - btrfs ' in mounts[0], 'application storage is not the declared Btrfs payload'
uuid = re.search(r'/containers\.slice/([0-9]+)\.slice/leaf(?:\n|$)',
                 (process / 'cgroup').read_text())
assert uuid, 'owned container cgroup identity missing'
expected = brain / 'root/containers/storage' / uuid[1]
if int(sys.argv[3]) != 0:
    expected = expected / 'data'
observed = process / 'root/storage'
expected_stat, observed_stat = expected.stat(), observed.stat()
assert (expected_stat.st_dev, expected_stat.st_ino) == (observed_stat.st_dev, observed_stat.st_ino), \
       'application /storage does not match its owner payload'
def digest(path):
    with pathlib.Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
assert digest(process / 'exe') == digest(sys.argv[2]), 'unexpected running application bytes'
print(json.dumps({'passed': True, 'pid': int(process.name), 'containerUUID': uuid[1],
                  'storageDeviceCount': int(sys.argv[3]),
                  'device': observed_stat.st_dev, 'inode': observed_stat.st_ino,
                  'mountinfo': mounts[0], 'applicationSHA256': digest(sys.argv[2])}, indent=2))
PY
then
   archive_workspace=1
   echo "FAIL: application did not mount its declared persistent storage"
   exit 1
fi

if [[ "${test_mode}" == mount-only ]]
then
   archive_workspace=1
   echo "PASS: isolated application mounted exact persistent storage payload"
   exit 0
fi

traffic_payload="$(printf 'ping\n%.0s' {1..80})"
if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" probeTestCluster "${cluster_name}" 10.0.0.10 19090 "${traffic_payload}" pong 10000 0 \
   >"${traffic_log}" 2>&1
then
   archive_workspace=1
   echo "FAIL: Mothership test-provider traffic probe failed"
   sed -n '1,160p' "${traffic_log}" || true
   exit 1
fi

scaled=0
for _ in $(seq 1 180)
do
   if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" Nametag \
      >"${application_log}" 2>&1
   then
      max_storage="$(python3 - "${application_log}" <<'PY'
import re
import sys
text = open(sys.argv[1], "r", encoding="utf-8", errors="replace").read()
values = [int(v) for v in re.findall(r"containerRuntime: cores=\d+ memMB=\d+ storMB=(\d+)", text)]
print(max(values) if values else 0)
PY
)"
      if [[ "${max_storage}" -ge 512 ]]
      then
         scaled=1
         break
      fi
   fi

   sleep 0.5
done

if [[ "${scaled}" -ne 1 ]]
then
   archive_workspace=1
   echo "FAIL: runtime storage never scaled to 512MB"
   sed -n '1,240p' "${application_log}" || true
   sed -n '1,120p' "${traffic_log}" || true
   exit 1
fi

brain_mount_exec=(nsenter -t "${brain_pid}" -m --)
mapfile -t storage_a_files < <("${brain_mount_exec[@]}" find /mnt/prodigy-storage/1/.prodigy/container-storage -maxdepth 1 -type f -name '*.btrfs.loop' | sort)
mapfile -t storage_b_files < <("${brain_mount_exec[@]}" find /mnt/prodigy-storage/2/.prodigy/container-storage -maxdepth 1 -type f -name '*.btrfs.loop' | sort)

if [[ "${#storage_a_files[@]}" -ne 1 || "${#storage_b_files[@]}" -ne 1 ]]
then
   archive_workspace=1
   echo "FAIL: expected one loop backing file per mounted filesystem"
   "${brain_mount_exec[@]}" find /mnt/prodigy-storage -maxdepth 4 -printf '%p\n' | sort
   exit 1
fi

storage_a_size="$("${brain_mount_exec[@]}" stat -c '%s' "${storage_a_files[0]}")"
storage_b_size="$("${brain_mount_exec[@]}" stat -c '%s' "${storage_b_files[0]}")"
min_bytes=$((256 * 1024 * 1024))
if [[ "${storage_a_size}" -lt "${min_bytes}" || "${storage_b_size}" -lt "${min_bytes}" ]]
then
   archive_workspace=1
   echo "FAIL: backing files did not grow to the resized per-device target"
   printf 'storage_a=%s bytes=%s\n' "${storage_a_files[0]}" "${storage_a_size}"
   printf 'storage_b=%s bytes=%s\n' "${storage_b_files[0]}" "${storage_b_size}"
   exit 1
fi

storage_root="$("${brain_mount_exec[@]}" sh -lc 'find /containers/storage -mindepth 1 -maxdepth 1 -type d | head -n 1' 2>/dev/null || true)"
if [[ -z "${storage_root}" ]]
then
   archive_workspace=1
   echo "FAIL: unable to locate live container storage root"
   exit 1
fi

"${brain_mount_exec[@]}" btrfs filesystem show "${storage_root}" >"${btrfs_show_log}" 2>&1 || {
   archive_workspace=1
   echo "FAIL: btrfs filesystem show failed"
   sed -n '1,200p' "${btrfs_show_log}" || true
   exit 1
}

if [[ "$(rg -c 'devid' "${btrfs_show_log}")" -lt 2 ]]
then
   archive_workspace=1
   echo "FAIL: live btrfs filesystem did not expose multiple devices"
   sed -n '1,200p' "${btrfs_show_log}" || true
   exit 1
fi

echo "PASS: multi-drive loop-backed storage smoke storageA=${storage_a_files[0]} storageB=${storage_b_files[0]}"
