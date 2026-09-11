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
   legacy-handoff) host_network=false ;;
   *) echo "error: expected resize, mount-only or legacy-handoff mode" >&2; exit 2 ;;
esac
[[ "${storage_devices}" == 0 || "${storage_devices}" == 2 ]] || { echo "error: expected zero or two storage devices" >&2; exit 2; }
[[ "${test_mode}" != resize || "${storage_devices}" == 2 ]] || { echo "error: resize requires two storage devices" >&2; exit 2; }
[[ "${test_mode}" != legacy-handoff || ( "${storage_devices}" == 0 && -s "${upgrade_bundle}" ) ]] || { echo "error: legacy handoff requires zero devices and an exact upgrade bundle" >&2; exit 2; }
[[ "${test_mode}" != legacy-handoff || "${PRODIGY_STORAGE_HANDOFF_EXPECTED_RUNTIME_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || { echo "error: legacy handoff requires the sealed successor runtime hash" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/prodigy_dev_discombobulator_artifact_helpers.sh"
SCRIPT_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_STORAGE_MULTIDRIVE_RESIZE_SMOKE_MOUNT_NS_READY bash "${SCRIPT_SELF}" "$@"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${PINGPONG_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_pingpong_container [resize|mount-only] [0|2 storage devices]"
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

cleanup()
{
   local status=$?
   trap - EXIT
   set +e

   if [[ "${archive_workspace}" -eq 1 && -d "${workspace_root}" ]]
   then
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
      rm -rf "${tmpdir}/workspace-archive" >/dev/null 2>&1 || true
      mkdir -p "${tmpdir}/workspace-archive"
      find "${workspace_root}" -maxdepth 1 -type f \( -name '*.log' -o -name '*.json' -o -name '*.ready' -o -name '*.failure' \) \
         -exec cp -a {} "${tmpdir}/workspace-archive/" \; >/dev/null 2>&1 || true
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
application_type=stateless
is_stateful=false
expected_healthy=1
handoff_id=""
if [[ "${test_mode}" == legacy-handoff ]]
then
   machine_count=3
   expected_healthy=3
   application_type=stateful
   is_stateful=true
   handoff_id="$(tr -d '-' < /proc/sys/kernel/random/uuid)"
fi

read -r -d '' CREATE_REQUEST <<EOF || true
{
  "name": "${cluster_name}",
  "deploymentMode": "test",
  "autoscaleIntervalSeconds": 3,
  "nBrains": ${machine_count},
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

if ! env \
   PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" createCluster "${CREATE_REQUEST}" \
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
if [[ "${test_mode}" == legacy-handoff ]]
then
   printf 'ENV PINGPONG_STORAGE_HANDOFF_MODE=seed\nENV PINGPONG_STORAGE_HANDOFF_ID=%s\n' "${handoff_id}" >> "${discombobulator_file}"
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
if sys.argv[2] == 'legacy-handoff':
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

healthy=0
report_version_ready()
{
   python3 - "$1" "$2" "$3" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
wanted, count = int(sys.argv[2]), int(sys.argv[3])
for block in re.split(r'(?m)^\s*versionID:\s*', text)[1:]:
    if int(block.splitlines()[0]) != wanted:
        continue
    def field(name):
        match = re.search(r'(?m)^\s*' + name + r':\s*(\S+)', block)
        return match[1] if match else None
    ready = field('state') == 'DeploymentState::running' and all(
        field(name) == str(count) for name in ('nTarget', 'nDeployed', 'nHealthy')) and field('nCrashes') == '0'
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
      if report_version_ready "${application_log}" "${version_id}" "${expected_healthy}"
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

if [[ "${test_mode}" == legacy-handoff ]]
then
   archive_workspace=1
   observe_handoff()
   {
      python3 - "${manifest_path}" "${PINGPONG_BIN}" "${handoff_id}" "$1" "${tmpdir}" "${PRODIGY_STORAGE_HANDOFF_EXPECTED_RUNTIME_SHA256}" <<'PY'
import hashlib, json, pathlib, re, sys
manifest, executable, identity, phase, output, runtime_hash = sys.argv[1:]
root = pathlib.Path(output)
nodes = json.loads(pathlib.Path(manifest).read_text())['nodes']
expected_binary = hashlib.sha256(pathlib.Path(executable).read_bytes()).hexdigest()
before = json.loads((root / 'handoff-before.json').read_text()) if phase != 'before' else None
records = []
for node in nodes:
    parent = pathlib.Path('/proc') / str(node['pid'])
    if phase != 'before':
        assert hashlib.sha256((parent / 'exe').read_bytes()).hexdigest() == runtime_hash, 'machine has wrong runtime bytes'
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
        if phase in ('before', 'upgraded'):
            assert (original.stat().st_dev, original.stat().st_ino) == (metadata.st_dev, metadata.st_ino)
        else:
            target = parent / 'root/containers/storage' / uuid
            assert (target.stat().st_dev, target.stat().st_ino) == (metadata.st_dev, metadata.st_ino)
            assert file.stat().st_uid == metadata.st_uid
            assert any(line.split()[4] == '/storage' for line in (child / 'mountinfo').read_text().splitlines())
        records.append(dict(machineIndex=node['index'], parentPID=node['pid'], pid=int(pid), uuid=uuid,
                            device=metadata.st_dev, inode=metadata.st_ino, uid=metadata.st_uid,
                            networkNamespace=str((child / 'ns/net').readlink()),
                            cgroup=(child / 'cgroup').read_text(),
                            applicationSHA256=expected_binary))
assert len(records) == 3, f'expected three real fixture replicas, got {len(records)}'
if phase == 'upgraded':
    assert sorted((r['pid'], r['uuid'], r['device'], r['inode'], r['networkNamespace'], r['cgroup']) for r in records) == \
           sorted((r['pid'], r['uuid'], r['device'], r['inode'], r['networkNamespace'], r['cgroup']) for r in before), 'bundle upgrade changed live app/storage/network owners'
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
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" updateProdigy "${cluster_name}" "${upgrade_bundle}" >"${tmpdir}/upgrade.log" 2>&1
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
         if report_version_ready "${tmpdir}/upgrade-recovery-report.log" "${version_id}" 3
         then
            recovered=1
            break
         fi
      fi
      sleep 0.5
   done
   [[ "${recovered}" == 1 ]] || { echo "FAIL: original deployment control-plane recovery not observed; no successor submitted" >&2; exit 1; }
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
   healthy=0
   for _ in $(seq 1 120)
   do
      if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" Nametag >"${tmpdir}/verify-report.log" 2>&1 &&
         report_version_ready "${tmpdir}/verify-report.log" "$((version_id + 1))" 3
      then
         healthy=1
         break
      fi
      sleep 0.5
   done
   [[ "${healthy}" == 1 ]] || { echo "FAIL: successor did not become healthy" >&2; exit 1; }
   observe_handoff after
   echo "PASS: worker-preserving bundle upgrade and lifecycle-quiesced legacy storage handoff with logical readback"
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
