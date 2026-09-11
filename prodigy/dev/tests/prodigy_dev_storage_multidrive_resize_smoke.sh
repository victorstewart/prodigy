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
   legacy-handoff|legacy-recovery|provider-handoff|bootstrap-supersession) host_network=false ;;
   *) echo "error: expected resize, mount-only, legacy-handoff, legacy-recovery, provider-handoff or bootstrap-supersession mode" >&2; exit 2 ;;
esac
is_handoff=0
[[ "${test_mode}" != legacy-handoff && "${test_mode}" != legacy-recovery && "${test_mode}" != provider-handoff && "${test_mode}" != bootstrap-supersession ]] || is_handoff=1
[[ "${storage_devices}" == 0 || "${storage_devices}" == 2 ]] || { echo "error: expected zero or two storage devices" >&2; exit 2; }
[[ "${test_mode}" != resize || "${storage_devices}" == 2 ]] || { echo "error: resize requires two storage devices" >&2; exit 2; }
[[ "${is_handoff}" == 0 || ( "${storage_devices}" == 0 && -s "${upgrade_bundle}" ) ]] || { echo "error: legacy handoff requires zero devices and an exact upgrade bundle" >&2; exit 2; }
[[ "${is_handoff}" == 0 || "${PRODIGY_STORAGE_HANDOFF_EXPECTED_RUNTIME_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || { echo "error: legacy handoff requires the sealed successor runtime hash" >&2; exit 2; }
if [[ "${test_mode}" == provider-handoff || "${test_mode}" == bootstrap-supersession ]]; then
   old_bundle_sha="${PRODIGY_STORAGE_HANDOFF_EXPECTED_OLD_BUNDLE_SHA256:-}"
   [[ "${old_bundle_sha}" =~ ^[0-9a-f]{64}$ ]] || { echo "error: handoff mode requires sealed old bundle SHA" >&2; exit 2; }
   create_mothership_bin="${PRODIGY_STORAGE_HANDOFF_CREATE_MOTHERSHIP_BIN:-}"
   [[ -x "${create_mothership_bin}" ]] || { echo "error: handoff mode requires executable sealed predecessor Mothership" >&2; exit 2; }
fi
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
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_pingpong_container [resize|mount-only|legacy-handoff|legacy-recovery|provider-handoff] [0|2 storage devices] [upgrade bundle]"
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

tmpdir="$(mktemp -d)"
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
      find "${workspace_root}/virtual-datacenter.recovery" -maxdepth 2 -type f \( -name operation -o -name ready -o -name commit -o -name launch -o -name replaced -o -name complete -o -name failure -o -name provider.log -o -name selected-machine -o -name root-installed \) -size -8M \
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

   for background_pid in "${owned_background_pids[@]}"
   do
      kill "${background_pid}" >/dev/null 2>&1 || true
      wait "${background_pid}" >/dev/null 2>&1 || true
   done

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
application_type=stateless
is_stateful=false
expected_healthy=1
initial_healthy=1
initial_state=running
recovered_state=running
handoff_id=""
if [[ "${is_handoff}" == 1 ]]
then
   # Match the retained release topology: one controller and three workers.
   machine_count=4
   expected_healthy=3
   initial_healthy=3
   if [[ "${test_mode}" == legacy-recovery ]]
   then
      initial_healthy=1
      initial_state=deploying
      recovered_state=none
   fi
   application_type=stateful
   is_stateful=true
   handoff_id="$(tr -d '-' < /proc/sys/kernel/random/uuid)"
fi

read -r -d '' CREATE_REQUEST <<EOF || true
{
  "name": "${cluster_name}",
  "deploymentMode": "test",
  "autoscaleIntervalSeconds": 3,
  "nBrains": 1,
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
    "enableFakeIpv4Boundary": false
  }
}
EOF

create_mothership_bin="${create_mothership_bin:-${MOTHERSHIP_BIN}}"
if ! env \
   PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${create_mothership_bin}" createCluster "${CREATE_REQUEST}" \
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
   if [[ "${test_mode}" == legacy-recovery ]]
   then
      # A fixture readiness failure leaves two real data owners running unready.
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
  "useHostNetworkNamespace": ${host_network},
  "minimumSubscriberCapacity": 1024,
  "isStateful": ${is_stateful},
  "stateful": {
    "clientPrefix": 601, "siblingPrefix": 602, "cousinPrefix": 603,
    "seedingPrefix": 604, "shardingPrefix": 605,
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
python3 - "${plan_json}" "${test_mode}" <<'PY'
import json, sys
with open(sys.argv[1]) as stream:
    plan = json.load(stream)
if sys.argv[2] in ('legacy-handoff', 'legacy-recovery', 'provider-handoff', 'bootstrap-supersession'):
    plan.pop('stateless')
    plan['verticalScalers'] = []
else:
    plan.pop('stateful')
with open(sys.argv[1], 'w') as stream:
    json.dump(plan, stream)
PY

if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" deploy "${cluster_name}" "$(cat "${plan_json}")" "${container_blob}" \
   >"${deploy_log}" 2>&1
then
   archive_workspace=1
   echo "FAIL: storage deployment failed"
   sed -n '1,200p' "${deploy_log}" || true
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
        match = re.search(r'(?m)^\s*' + name + r':\s*(\S+)', block)
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

if [[ "${is_handoff}" == 1 ]]
then
   archive_workspace=1
   observe_handoff()
   {
      python3 - "${manifest_path}" "${PINGPONG_BIN}" "${handoff_id}" "$1" "${tmpdir}" "${PRODIGY_STORAGE_HANDOFF_EXPECTED_RUNTIME_SHA256}" "${test_mode}" <<'PY'
import hashlib, json, pathlib, re, sys
manifest, executable, identity, phase, output, runtime_hash, mode = sys.argv[1:]
root = pathlib.Path(output)
nodes = json.loads(pathlib.Path(manifest).read_text())['nodes']
expected_binary = hashlib.sha256(pathlib.Path(executable).read_bytes()).hexdigest()
before = json.loads((root / 'handoff-before.json').read_text()) if phase != 'before' else None
records = []
for node in nodes:
    parent = pathlib.Path('/proc') / str(node['pid'])
    if phase not in ('before', 'provider-step'):
        assert hashlib.sha256((parent / 'exe').read_bytes()).hexdigest() == runtime_hash, 'machine has wrong runtime bytes'
    children = []
    if mode in ('provider-handoff', 'bootstrap-supersession'):
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
        original = parent / 'root/containers' / uuid / 'rootfs/storage'
        if phase in ('before', 'upgraded', 'recovered', 'provider-step'):
            assert (original.stat().st_dev, original.stat().st_ino) == (metadata.st_dev, metadata.st_ino)
        else:
            target = parent / 'root/containers/storage' / uuid
            assert (target.stat().st_dev, target.stat().st_ino) == (metadata.st_dev, metadata.st_ino)
            assert file.stat().st_uid == metadata.st_uid
            assert any(line.split()[4] == '/storage' for line in (child / 'mountinfo').read_text().splitlines())
        starttime = (child / 'stat').read_text().rsplit(') ',1)[1].split()[19]
        records.append(dict(machineIndex=node['index'], parentPID=node['pid'], pid=int(pid), starttime=starttime, uuid=uuid,
                            device=metadata.st_dev, inode=metadata.st_ino, uid=metadata.st_uid,
                            networkNamespace=str((child / 'ns/net').readlink()),
                            cgroup=(child / 'cgroup').read_text(),
                            applicationSHA256=expected_binary))
assert len(records) == 3, f'expected three real fixture replicas, got {len(records)}'
if phase in ('upgraded', 'recovered', 'provider-step'):
    assert sorted((r['pid'], r['starttime'], r['uuid'], r['device'], r['inode'], r['networkNamespace'], r['cgroup']) for r in records) == \
           sorted((r['pid'], r['starttime'], r['uuid'], r['device'], r['inode'], r['networkNamespace'], r['cgroup']) for r in before), 'bundle upgrade changed live app/storage/network owners'
if phase == 'after':
    assert not ({r['pid'] for r in before} & {r['pid'] for r in records})
    for old in before:
        node = next(n for n in nodes if n['index'] == old['machineIndex'])
        owner = pathlib.Path('/proc') / str(node['pid']) / 'root/containers'
        source = owner / old['uuid'] / 'rootfs/storage'
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
   observe_handoff before
   if [[ "${test_mode}" == provider-handoff ]]; then
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
      # persists a real incomplete three-worker operation. Both actions remain
      # Mothership requests; this fixture owns only their bounded CLI children.
      env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" faultTestCluster "${cluster_name}" link 2 "${fault_duration_ms}" 0 0 0 >"${tmpdir}/bootstrap-fault.log" 2>&1 &
      fault_pid=$!
      owned_background_pids+=("${fault_pid}")
      env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" updateProdigy "${cluster_name}" "${interrupted_bundle}" >"${tmpdir}/bootstrap-interrupted-update.log" 2>&1 &
      interrupted_update_pid=$!
      owned_background_pids+=("${interrupted_update_pid}")
      pending=0
      for attempt in $(seq 1 120)
      do
         if kill -0 "${fault_pid}" >/dev/null 2>&1 &&
            kill -0 "${interrupted_update_pid}" >/dev/null 2>&1 &&
            env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
               timeout 8s "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" >"${tmpdir}/bootstrap-pending-cluster-${attempt}.log" 2>&1
         then
            printf 'attempt=%s updatePid=%s state=deferred clusterReport=observed\n' "${attempt}" "${interrupted_update_pid}" >>"${tmpdir}/bootstrap-pending.log"
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
   [[ "${upgraded}" == 1 ]] || { echo "FAIL: exact worker-preserving bundle upgrade was not observed" >&2; exit 1; }
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
   [[ "${recovered}" == 1 ]] || { echo "FAIL: original deployment control-plane recovery not observed; no successor submitted" >&2; exit 1; }
   # Readiness counters alone can conceal fresh replicas created after exec.
   # Re-observe the original owners after recovery settles, before any update.
   observe_handoff recovered || {
      echo "FAIL: controller recovery replaced original application/storage owners; no successor submitted" >&2
      exit 1
   }
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
   if [[ "${test_mode}" == legacy-recovery ]]
   then
      queued=0
      for _ in $(seq 1 120)
      do
         if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
            timeout 8s "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" Nametag >"${tmpdir}/recovery-admission-report.log" 2>&1 &&
            report_version_ready "${tmpdir}/recovery-admission-report.log" "${version_id}" 3 1 none &&
            report_version_ready "${tmpdir}/recovery-admission-report.log" "$((version_id + 1))" 0 0 waitingToDeploy
         then
            queued=1
            break
         fi
         sleep 0.5
      done
      [[ "${queued}" == 1 ]] || { echo "FAIL: exact retained 3/1 predecessor and empty waiting successor not observed" >&2; exit 1; }
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
   if [[ "${test_mode}" == legacy-recovery ]]
   then
      echo "PASS: durably admitted retained 3/1 recovery, idempotent retry and three-replica logical readback"
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
