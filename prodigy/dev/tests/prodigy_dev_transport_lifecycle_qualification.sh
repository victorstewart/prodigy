#!/usr/bin/env bash
# Ordinary Brain-owned credential lifecycle through the Mothership test provider.
set -Eeuo pipefail
if [[ ${1:-} == --validate-only && $# == 1 ]]; then bash -n "$0"; exit 0; fi
[[ $# == 2 && -x $1 && -x $2 && $EUID == 0 ]] || exit 2
PRODIGY_BIN=$(readlink -f "$1")
MOTHERSHIP_BIN=$(readlink -f "$2")
TEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd "$TEST_DIR/../../.." && pwd -P)
source "$TEST_DIR/prodigy_dev_discombobulator_artifact_helpers.sh"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_TRANSPORT_LIFECYCLE_MOUNT_NS_READY bash "$(readlink -f "$0")" "$@"
"$TEST_DIR/prodigy_dev_test_cluster.sh" --check-boundary
[[ $(dirname "$PRODIGY_BIN") == "$(dirname "$MOTHERSHIP_BIN")" ]] || exit 2
case $(uname -m) in aarch64|arm64) ARCH=aarch64;; x86_64) ARCH=x86_64;; riscv64) ARCH=riscv64;; *) exit 77;; esac
BUNDLE="$(dirname "$PRODIGY_BIN")/prodigy.$ARCH.bundle.tar.zst"
EXPECTED_BUNDLE_SHA256=$(sha256sum "$BUNDLE" | cut -d' ' -f1)
ROOT=$(mktemp -d "$REPO_ROOT/.run/prodigy-transport-lifecycle.XXXXXX")
WORKSPACE="$ROOT/workspace"
MANIFEST="$WORKSPACE/test-cluster-manifest.json"
DB="$ROOT/mothership.tidesdb"
CLUSTER="transport-lifecycle-$$-$RANDOM"
CREATED=0
FAULT_PID=0
mkdir -p "$ROOT/receipts"

m() {
  local label=$1 seconds=$2 started ended status
  shift 2
  started=$(date +%s%3N)
  if timeout "${seconds}s" env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$DB" "$MOTHERSHIP_BIN" "$@" >"$ROOT/$label.log" 2>&1; then status=0; else status=$?; fi
  ended=$(date +%s%3N)
  jq -nc --arg label "$label" --arg command "$1" --argjson status "$status" --argjson startedMs "$started" --argjson endedMs "$ended" \
    '{label:$label,command:$command,status:$status,startedMs:$startedMs,endedMs:$endedMs}' >"$ROOT/receipts/$label-$started.json"
  return "$status"
}
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if (( FAULT_PID )); then wait "$FAULT_PID" || status=1; fi
  mkdir -p "$ROOT/native"
  cp -p "$WORKSPACE"/machine*.log* "$WORKSPACE"/fault-events.log "$MANIFEST" "$ROOT/native/" 2>/dev/null
  if (( CREATED )); then
    m remove 180 removeCluster "$CLUSTER" || status=1
    rg -q 'removeCluster success=1' "$ROOT/remove.log" || status=1
  fi
  [[ ! -e $MANIFEST ]] || status=1
  jq -nc --argjson exitCode "$status" --arg cluster "$CLUSTER" '{exitCode:$exitCode,cluster:$cluster}' >"$ROOT/result.json"
  printf 'TRANSPORT_LIFECYCLE_EVIDENCE=%s\n' "$ROOT"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

new_operation() { python3 -c 'import secrets; v=secrets.randbits(128) or 1; print("0x"+v.to_bytes((v.bit_length()+7)//8,"big").hex())'; }
ready() {
  local expected=${2:-4}
  [[ $(rg -c '^[[:space:]]*Machine: state=healthy ' "$1" || true) == "$expected" &&
     $(rg -c '^[[:space:]]*lifecycle controlPlaneReachable=1 runtimeReady=1 ' "$1" || true) == "$expected" &&
     $(rg -c "approvedBundleSHA256=$EXPECTED_BUNDLE_SHA256 " "$1" || true) == "$expected" ]]
}
wait_ready() {
  local expected=${1:-4} deadline=$(( $(date +%s) + 120 ))
  while (( $(date +%s) < deadline )); do
    if m report 8 clusterReport "$CLUSTER" && ready "$ROOT/report.log" "$expected"; then return 0; fi
    sleep .5
  done
  return 1
}
identities() {
  python3 - "$ROOT/report.log" "$MANIFEST" <<'PY'
import json,pathlib,re,sys
nodes={n['ipv4']:n['index'] for n in json.loads(pathlib.Path(sys.argv[2]).read_text())['nodes']}
for block in re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)',pathlib.Path(sys.argv[1]).read_text()):
    match=re.search(r'(?m)^[ \t]*identity uuid=(\S+) .*sshAddress=(\S+)',block)
    if match and match[2] in nodes:
        uuid=int(match[1],16)
        canonical='0x'+uuid.to_bytes(max(1,(uuid.bit_length()+7)//8),'big').hex()
        print(nodes[match[2]],canonical,int(bool(re.search(r'\bcurrentMaster=1(?:\s|$)',block))),sep='\t')
PY
}
request_lifecycle() {
  local label=$1 operation=$2 role=$3 kind=$4 uuid=$5 deadline=$(( $(date +%s) + 20 ))
  while (( $(date +%s) < deadline )); do
    if m "$label-request" 10 transportCredentialLifecycle "$CLUSTER" "$operation" request "$role" "$kind" "$uuid" &&
       rg -q 'transportCredentialLifecycle success=1 .*found=1' "$ROOT/$label-request.log"; then
      printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$operation" "$role" "$kind" "$uuid" >>"$ROOT/operations.tsv"
      return 0
    fi
    sleep .25
  done
  return 1
}
wait_phase() {
  local label=$1 operation=$2 phase=$3 deadline=$(( $(date +%s) + 90 ))
  while (( $(date +%s) < deadline )); do
    if m "$label-query" 8 transportCredentialLifecycle "$CLUSTER" "$operation" query &&
       rg -q "success=1 .*found=1 durable=1 qualified=$([[ $phase == 4 ]] && echo 1 || echo 0) phase=$phase " "$ROOT/$label-query.log"; then return 0; fi
    sleep .25
  done
  return 1
}
restart_revoked_target() {
  local label=$1 operation=$2 role=$3 target=$4 index=$5 offset address deadline
  offset=$(wc -c <"$WORKSPACE/machine$index.log")
  m "$label-restart" 30 faultTestCluster "$CLUSTER" crash "$index" 8000 0 0 0
  rg -q 'faultTestCluster success=1' "$ROOT/$label-restart.log"
  address=$(jq -r --argjson index "$index" '.nodes[]|select(.index==$index)|.ipv4' "$MANIFEST")
  deadline=$(( $(date +%s) + 30 ))
  while (( $(date +%s) < deadline )); do
    if [[ $role == neuron ]]; then
      # Exercise the real listener through the provider-owned probe. A TCP
      # connection alone is not an authenticated control session; the native
      # refusal below must identify the persisted revoked credential.
      m "$label-probe" 5 probeTestCluster "$CLUSTER" "$address" 312 revoked-probe "" 2000 0 || true
    fi
    if python3 - "$WORKSPACE/machine$index.log" "$offset" "$role" "$target" "$operation" "$ROOT/$label-restart-observation.json" <<'PY'
import json,pathlib,re,sys
path,offset,role,target,operation,destination=sys.argv[1:]
text=pathlib.Path(path).read_bytes()[int(offset):].decode(errors='replace')
pattern=(r'transport lifecycle credential-refused role='+role+r' node='+f'{int(target,16):032x}'+
         r' operation='+f'{int(operation,16):032x}'+r' generation=(\d+) reason=revoked')
match=re.search(pattern,text)
if not match: raise SystemExit(1)
assert 'prodigy startup nodeRole=' in text,'refusal was not observed after process restart'
pathlib.Path(destination).write_text(json.dumps(dict(role=role,node=target,operation=operation,
    log=path,offset=int(offset),generation=int(match[1]),nativeRefusal=match[0]),indent=2)+'\n')
PY
    then return 0; fi
    sleep .25
  done
  return 1
}

sha256sum "$PRODIGY_BIN" "$MOTHERSHIP_BIN" "$BUNDLE" >"$ROOT/artifact-identities.sha256"
REQUEST=$(jq -nc --arg name "$CLUSTER" --arg workspace "$WORKSPACE" \
  '{name:$name,deploymentMode:"test",internalTransportProfile:"aegis-x25519-v1",nBrains:3,machineSchemas:[{schema:"transport-lifecycle",kind:"vm",vmImageURI:"test://virtual-datacenter"}],test:{workspaceRoot:$workspace,machineCount:4,machineLogicalCores:4,machineMemoryMB:8192,machineStorageMB:8192,brainBootstrapFamily:"ipv4",enableFakeIpv4Boundary:false,interContainerMTU:9000}}')
printf '%s\n' "$REQUEST" >"$ROOT/create-request.json"
CREATED=1
m create 180 createCluster "$REQUEST"
rg -q 'createCluster success=1' "$ROOT/create.log"
wait_ready
identities >"$ROOT/identities.tsv"
WORKER_UUID=$(awk '$1==4 {print $2}' "$ROOT/identities.tsv")
[[ -n $WORKER_UUID ]]
OP=$(new_operation)
request_lifecycle neuron-rotate "$OP" neuron rotate "$WORKER_UUID"
wait_phase neuron-rotate "$OP" 4
wait_ready
identities >"$ROOT/identities.tsv"
MASTER_UUID=$(awk '$3==1 {print $2}' "$ROOT/identities.tsv")
OP=$(new_operation)
request_lifecycle leader-rotate "$OP" brain rotate "$MASTER_UUID"
wait_phase leader-rotate "$OP" 4
wait_ready

# A missing worker cannot be dropped from a Brain roster cutover. The current
# leader dies while that fleet fence is outstanding; its successor resumes it.
identities >"$ROOT/identities.tsv"
MASTER_INDEX=$(awk '$3==1 {print $1}' "$ROOT/identities.tsv")
MASTER_UUID=$(awk '$3==1 {print $2}' "$ROOT/identities.tsv")
# Exercise freshness ahead of UUID priority: the required target receipt is
# held by the higher-UUID survivor, while the lower-UUID survivor may lag.
TARGET_UUID=$(python3 - "$ROOT/identities.tsv" <<'PY_TARGET'
import pathlib,sys
candidates=[row.split()[1] for row in pathlib.Path(sys.argv[1]).read_text().splitlines() if int(row.split()[0])<4 and row.split()[2]=='0']
print(max(candidates,key=lambda value:int(value,16)))
PY_TARGET
)
m partition-worker 75 faultTestCluster "$CLUSTER" link 4 60000 0 0 0 &
FAULT_PID=$!
python3 - "$WORKSPACE/fault-events.log" <<'PY'
import pathlib,re,sys,time
p=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+10
while not (p.exists() and re.search(r'fault-link runtime=\d+ link=vp4 state=down',p.read_text())):
    if time.monotonic()>deadline: raise SystemExit('worker partition not observed')
    time.sleep(.05)
PY
OP=$(new_operation)
request_lifecycle interrupted-brain-rotate "$OP" brain rotate "$TARGET_UUID"
wait_phase interrupted-brain-rotate "$OP" 1
cp "$ROOT/interrupted-brain-rotate-query.log" "$ROOT/pre-fault-prepared.log"
# A native prepared receipt is possible only after the exact operation reached
# its capable majority. A local durable query alone is insufficient here.
python3 - "$WORKSPACE" "$OP" <<'PY'
import pathlib,re,sys,time
workspace=pathlib.Path(sys.argv[1]); operation=f'{int(sys.argv[2],16):032x}'; deadline=time.monotonic()+10
while True:
    observed='\n'.join(p.read_text(errors='replace') for p in workspace.glob('machine*.log'))
    if re.search(r'transport lifecycle local-durable node=[0-9a-f]{32} operation='+operation+r' phase=1 ',observed): break
    if time.monotonic()>deadline: raise SystemExit('prepared operation has no majority-authorized native recipient')
    time.sleep(.05)
events=re.findall(r'fault-link runtime=\d+ link=vp4 state=(down|up)',(workspace/'fault-events.log').read_text())
assert events and events[-1]=='down','worker partition ended before the qualified leader fault'
PY
m leader-crash 30 faultTestCluster "$CLUSTER" crash "$MASTER_INDEX" 8000 0 0 0
rg -q 'faultTestCluster success=1' "$ROOT/leader-crash.log"
wait "$FAULT_PID"
FAULT_PID=0
wait_phase interrupted-brain-rotate "$OP" 4
wait_ready
identities >"$ROOT/identities-after-fault.tsv"
NEW_MASTER_UUID=$(awk '$3==1 {print $2}' "$ROOT/identities-after-fault.tsv")
[[ -n $NEW_MASTER_UUID && $NEW_MASTER_UUID != "$MASTER_UUID" ]]
m interrupted-retry 15 transportCredentialLifecycle "$CLUSTER" "$OP" request brain rotate "$TARGET_UUID"
rg -q 'success=1 .*durable=1 qualified=1 phase=4 ' "$ROOT/interrupted-retry.log"

OP=$(new_operation)
request_lifecycle neuron-revoke "$OP" neuron revoke "$WORKER_UUID"
wait_phase neuron-revoke "$OP" 4
restart_revoked_target neuron-revoke "$OP" neuron "$WORKER_UUID" 4
# Keep the earlier restarted leader in the final surviving majority. Selecting
# an arbitrary report row can revoke that survivor and miss its recovery path.
TARGET_UUID=$(awk -v original="$MASTER_UUID" '$1<4 && $3==0 && $2!=original {print $2;exit}' "$ROOT/identities-after-fault.tsv")
[[ -n $TARGET_UUID ]]
TARGET_INDEX=$(awk -v uuid="$TARGET_UUID" '$2==uuid {print $1}' "$ROOT/identities-after-fault.tsv")
OP=$(new_operation)
request_lifecycle brain-revoke "$OP" brain revoke "$TARGET_UUID"
wait_phase brain-revoke "$OP" 4
restart_revoked_target brain-revoke "$OP" brain "$TARGET_UUID" "$TARGET_INDEX"
# The revoked Brain's colocated Neuron retains its separate credential and
# must recover. The retired worker must not regain authenticated control.
wait_ready 3
cp "$ROOT/report.log" "$ROOT/post-revoke-report.log"
identities >"$ROOT/identities-after-revoke.tsv"
MASTER_INDEX=$(awk '$3==1 {print $1}' "$ROOT/identities-after-revoke.tsv")
[[ -n $MASTER_INDEX && $MASTER_INDEX != "$TARGET_INDEX" ]]
m terminal-leader-restart 30 faultTestCluster "$CLUSTER" crash "$MASTER_INDEX" 8000 0 0 0
wait_phase brain-revoke "$OP" 4
wait_ready 3
cp "$ROOT/report.log" "$ROOT/terminal-report.log"
python3 - "$ROOT/terminal-report.log" "$TARGET_UUID" "$WORKER_UUID" <<'PY'
import pathlib,re,sys
blocks=re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)',pathlib.Path(sys.argv[1]).read_text())
observed={}
for block in blocks:
    match=re.search(r'\bidentity uuid=(\S+)',block)
    if match: observed[int(match[1],16)]=block
target=observed[int(sys.argv[2],16)]
assert re.search(r'lifecycle controlPlaneReachable=1 runtimeReady=1 currentMaster=0\b',target),target
worker=observed.get(int(sys.argv[3],16),'')
assert not re.search(r'lifecycle controlPlaneReachable=1\b',worker),worker
assert sum(bool(re.search(r'\bcurrentMaster=1\b',block)) for block in blocks)==1
PY

python3 - "$ROOT" "$WORKSPACE" <<'PY'
import json,pathlib,re,sys
root,workspace=map(pathlib.Path,sys.argv[1:]); text='\n'.join(p.read_text(errors='replace') for p in workspace.glob('machine*.log*'))
rows=re.findall(r'transport lifecycle local-durable node=([0-9a-f]{32}) operation=([0-9a-f]{32}) phase=(\d+) generation=(\d+) revoked=(\d+)',text)
result=[]
for row in (root/'operations.tsv').read_text().splitlines():
    label,op,role,kind,target=row.split('\t'); observed=[r for r in rows if int(r[1],16)==int(op,16) and r[2]=='3']
    expected=1 if role=='neuron' else 3 if kind=='revoke' else 4
    assert len({r[0] for r in observed})==expected,(label,'missing durable native recipients',observed)
    if role=='neuron':
        assert all(int(r[0],16)==int(target,16) and r[4]==str(int(kind=='revoke')) for r in observed)
    result.append(dict(label=label,operation=op,recipientCount=expected,receipts=observed))
(root/'native-lifecycle-observations.json').write_text(json.dumps(result,indent=2)+'\n')
PY
printf 'PASS: real Brain/Neuron rotation, revocation and interrupted fleet recovery\n'
