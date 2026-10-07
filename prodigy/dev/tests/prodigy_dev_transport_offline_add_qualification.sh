#!/usr/bin/env bash
# Real offline Brain-owned enrollment with leader recovery through the Mothership test provider.
set -Eeuo pipefail
if [[ ${1:-} == --validate-only && $# == 1 ]]; then bash -n "$0"; exit 0; fi
[[ $# == 3 && -x $1 && -x $2 && -x $3 && $EUID == 0 ]] || exit 2
PRODIGY_BIN=$(readlink -f "$1")
MOTHERSHIP_BIN=$(readlink -f "$2")
PINGPONG_BIN=$(readlink -f "$3")
TEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd "$TEST_DIR/../../.." && pwd -P)
source "$TEST_DIR/prodigy_dev_discombobulator_artifact_helpers.sh"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_TRANSPORT_OFFLINE_ADD_MOUNT_NS_READY bash "$(readlink -f "$0")" "$@"
"$TEST_DIR/prodigy_dev_test_cluster.sh" --check-boundary
[[ $(dirname "$PRODIGY_BIN") == "$(dirname "$MOTHERSHIP_BIN")" ]] || exit 2
case $(uname -m) in aarch64|arm64) ARCH=aarch64;; x86_64) ARCH=x86_64;; riscv64) ARCH=riscv64;; *) exit 77;; esac
BUNDLE="$(dirname "$PRODIGY_BIN")/prodigy.$ARCH.bundle.tar.zst"
EXPECTED_BUNDLE_SHA256=$(sha256sum "$BUNDLE" | cut -d' ' -f1)
ROOT=$(mktemp -d "$REPO_ROOT/.run/prodigy-transport-offline-add.XXXXXX")
WORKSPACE="$ROOT/workspace"
MANIFEST="$WORKSPACE/test-cluster-manifest.json"
DB="$ROOT/mothership.tidesdb"
CLUSTER="transport-offline-add-$$-$RANDOM"
OFFLINE=0
CREATED=0
FAULT_PID=0
CAPTURE_PID=0
mkdir -p "$ROOT/receipts"

m() {
  local label=$1 seconds=$2 started ended status
  shift 2
  [[ $OFFLINE == 0 || $1 == faultTestCluster ]] || { echo "ordinary Mothership command during offline join" >&2; return 125; }
  started=$(date +%s%3N)
  if timeout "${seconds}s" env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$DB" "$MOTHERSHIP_BIN" "$@" >"$ROOT/$label.log" 2>&1; then status=0; else status=$?; fi
  ended=$(date +%s%3N)
  jq -nc --arg label "$label" --arg command "$1" --argjson status "$status" --argjson startedMs "$started" --argjson endedMs "$ended" \
    '{label:$label,command:$command,status:$status,startedMs:$startedMs,endedMs:$endedMs}' >"$ROOT/receipts/$label-$started.json"
  return "$status"
}
capture_native() {
  mkdir -p "$ROOT/native"
  local path
  for path in "$WORKSPACE"/machine*.log* "$WORKSPACE"/fault-events.log "$MANIFEST" \
      "$WORKSPACE"/virtual-datacenter.{log,failure} "$WORKSPACE"/machine-exits.log \
      "$WORKSPACE"/machines/4/var/log/prodigy/*; do
    [[ ! -f $path ]] || cp -p "$path" "$ROOT/native/" 2>/dev/null || true
  done
}
cleanup() {
  local status=$?
  OFFLINE=0
  trap - EXIT HUP INT TERM
  set +e
  if (( CAPTURE_PID )); then kill "$CAPTURE_PID"; wait "$CAPTURE_PID"; fi
  if (( FAULT_PID )); then wait "$FAULT_PID" || status=1; fi
  capture_native
  if (( CREATED )); then
    m remove 180 removeCluster "$CLUSTER" || status=1
    rg -q 'removeCluster success=1' "$ROOT/remove.log" || status=1
  fi
  [[ ! -e $MANIFEST ]] || status=1
  jq -nc --argjson exitCode "$status" --arg cluster "$CLUSTER" '{exitCode:$exitCode,cluster:$cluster}' >"$ROOT/result.json"
  printf 'TRANSPORT_OFFLINE_ADD_EVIDENCE=%s\n' "$ROOT"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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

sha256sum "$PRODIGY_BIN" "$MOTHERSHIP_BIN" "$PINGPONG_BIN" "$BUNDLE" >"$ROOT/artifact-identities.sha256"
REQUEST=$(jq -nc --arg name "$CLUSTER" --arg workspace "$WORKSPACE" \
  '{name:$name,deploymentMode:"test",internalTransportProfile:"aegis-x25519-v1",nBrains:3,machineSchemas:[{schema:"offline-add",kind:"vm",vmImageURI:"test://virtual-datacenter"}],test:{workspaceRoot:$workspace,machineCount:4,spareMachineCount:1,machineLogicalCores:4,machineMemoryMB:8192,machineStorageMB:8192,brainBootstrapFamily:"ipv4",enableFakeIpv4Boundary:false,interContainerMTU:9000}}')
printf '%s\n' "$REQUEST" >"$ROOT/create-request.json"
CREATED=1
# Failed creation may remove provider roots before returning. Preserve native
# diagnostics continuously through read-only observation of that owned workspace.
(trap - EXIT HUP INT TERM; while :; do capture_native; sleep .1; done) &
CAPTURE_PID=$!
m create 240 createCluster "$REQUEST"
kill "$CAPTURE_PID"
wait "$CAPTURE_PID" || true
CAPTURE_PID=0
rg -q 'createCluster success=1' "$ROOT/create.log"
wait_ready 3
# Native PID 1 reports any inherited non-stdio descriptors before closing them.
# The private OS must never receive provider image, lock, or control handles.
! rg -q 'Closing set fd ([3-9]|[1-9][0-9]+) ' "$WORKSPACE/machine4.log"
cp "$ROOT/report.log" "$ROOT/initial-report.log"
identities >"$ROOT/initial-identities.tsv"
MASTER_INDEX=$(awk '$3==1 {print $1}' "$ROOT/initial-identities.tsv")
MASTER_UUID=$(awk '$3==1 {print $2}' "$ROOT/initial-identities.tsv")
[[ -n $MASTER_INDEX && ! -e $WORKSPACE/boot/4.json && ! -e $WORKSPACE/transport-tls/4.json ]]
[[ ! -e $WORKSPACE/machines/4/var/log/prodigy/runtime.log ]]
m submit 15 adoptTestClusterSpare "$CLUSTER"
rg -q 'adoptTestClusterSpare submitted=1 ' "$ROOT/submit.log"
OFFLINE=1
python3 - "$ROOT" "$WORKSPACE" "$MASTER_UUID" <<'PY'
import json,pathlib,re,sys,time
root,workspace=map(pathlib.Path,sys.argv[1:3]); expected_master=int(sys.argv[3],16)
receipt=json.loads(next((root/'receipts').glob('submit-*.json')).read_text())
pattern=r'transport enrollment cohort-qualified node=([0-9a-f]{32}) addOperation=(\d+) generation=(\d+) master=([0-9a-f]{32}) masterEpoch=(\d+) atMs=(\d+)'
deadline=time.monotonic()+120
while True:
    matches=[m for p in workspace.glob('machine*.log') for m in re.finditer(pattern,p.read_text(errors='replace'))]
    if matches:
        first=min(matches,key=lambda m:int(m[6]))
        assert int(first[6])>receipt['endedMs'],'cohort qualified before submission client exited'
        assert int(first[4],16)==expected_master,'qualified enrollment owner changed before targeted fault'
        (root/'qualified-before-fault.json').write_text(json.dumps(dict(zip(('node','operation','generation','master','epoch','atMs'),first.groups())),indent=2)+'\n')
        break
    if time.monotonic()>deadline: raise SystemExit('no native qualified enrollment after Mothership exit')
    time.sleep(.025)
PY
# This Mothership request is explicit infrastructure fault injection only. No
# ordinary provisioning or runtime request occurs until native recovery.
m leader-crash 30 faultTestCluster "$CLUSTER" crash "$MASTER_INDEX" 8000 0 0 0
rg -q 'faultTestCluster success=1' "$ROOT/leader-crash.log"
python3 - "$ROOT" "$WORKSPACE" "$MASTER_UUID" <<'PY'
import json,pathlib,re,sys,time
root,workspace=map(pathlib.Path,sys.argv[1:3]); oldmaster=int(sys.argv[3],16)
first=json.loads((root/'qualified-before-fault.json').read_text())
pattern=r'transport enrollment cohort-qualified node=([0-9a-f]{32}) addOperation=(\d+) generation=(\d+) master=([0-9a-f]{32}) masterEpoch=(\d+) atMs=(\d+)'
deadline=time.monotonic()+180
while True:
    rows=[m.groups() for p in workspace.glob('machine*.log') for m in re.finditer(pattern,p.read_text(errors='replace'))]
    resumed=[r for r in rows if r[0]==first['node'] and r[1]==first['operation'] and int(r[3],16)!=oldmaster and int(r[5])>int(first['atMs'])]
    runtime=workspace/'machines/4/var/log/prodigy/runtime.log'
    started=runtime.exists() and 'prodigy startup nodeRole=neuron' in runtime.read_text(errors='replace')
    if resumed and started:
        (root/'offline-recovery.json').write_text(json.dumps(dict(first=first,successorReceipts=resumed,nativeRuntimeLog=str(runtime),observedMs=time.time_ns()//1000000),indent=2)+'\n')
        break
    if time.monotonic()>deadline: raise SystemExit('same enrollment did not resume through successor and native spare startup')
    time.sleep(.1)
PY
OFFLINE=0
wait_ready 4
cp "$ROOT/report.log" "$ROOT/joined-report.log"
identities >"$ROOT/joined-identities.tsv"
SPARE_UUID=$(awk '$1==4 {print $2}' "$ROOT/joined-identities.tsv")
python3 - "$SPARE_UUID" "$ROOT/qualified-before-fault.json" <<'PY_IDENTITY'
import json,pathlib,sys
assert int(sys.argv[1],16)==int(json.loads(pathlib.Path(sys.argv[2]).read_text())['node'],16)
PY_IDENTITY

# Build the existing probe with an explicit IPv6 listener for this endpoint.
# An endpointless initial version establishes the ordinary constructive
# successor path, whose existing placement policy admits only the new spare.
BLOB="$ROOT/pingpong-ipv6.container.zst"
ARTIFACT_PROJECT="$ROOT/pingpong-ipv6"
mkdir -p "$ARTIFACT_PROJECT"
cat >"$ARTIFACT_PROJECT/PingPong.DiscombobuFile" <<EOF
FROM scratch for $ARCH
COPY {bin} ./$(basename "$PINGPONG_BIN") /app/pingpong
SURVIVE /app/pingpong
ENV PINGPONG_IPV6_LISTENER=1
EOF
prodigy_dev_write_common_prodigy_assets "$ARTIFACT_PROJECT/PingPong.DiscombobuFile"
printf 'EXECUTE ["/app/pingpong"]\n' >>"$ARTIFACT_PROJECT/PingPong.DiscombobuFile"
prodigy_dev_run_discombobulator_build "$ARTIFACT_PROJECT" "$ARTIFACT_PROJECT/PingPong.DiscombobuFile" \
  "$BLOB" "bin=$(dirname "$PINGPONG_BIN")" "ebpf=$(dirname "$PRODIGY_BIN")"
sha256sum "$BLOB" >>"$ROOT/artifact-identities.sha256"
APP="OfflineJoinPing-$RANDOM"
m reserve 30 reserveApplicationID "$CLUSTER" "$(jq -nc --arg applicationName "$APP" '{applicationName:$applicationName,createIfMissing:true}')"
APPID=$(rg -m1 -o 'appID=[1-9][0-9]*' "$ROOT/reserve.log" | cut -d= -f2)
[[ $APPID =~ ^[1-9][0-9]*$ ]]
jq -nc --argjson app "$APPID" --arg arch "$ARCH" \
  '{config:{type:"ApplicationType::stateless",applicationID:$app,versionID:1,architecture:$arch,filesystemMB:64,storageMB:64,memoryMB:256,nLogicalCores:1,msTilHealthy:2000,sTilHealthcheck:3,sTilKillable:30},apiCredentials:{applicationID:$app,requiredCredentialNames:[]},useHostNetworkNamespace:false,minimumSubscriberCapacity:1024,isStateful:false,stateless:{nBase:1,maxPerRackRatio:1.0,maxPerMachineRatio:1.0,moveableDuringCompaction:true},moveConstructively:true,requiresDatacenterUniqueTag:false}' >"$ROOT/v1-plan.json"
wait_app() {
  local version=$1 deadline=$(( $(date +%s) + 120 ))
  while (( $(date +%s) < deadline )); do
    if m app-report 8 applicationReport "$CLUSTER" "$APP" && python3 - "$ROOT/app-report.log" "$version" <<'PY'
import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text()
blocks=re.split(r'(?m)^\s*versionID:\s*',text)[1:]
blocks=[b for b in blocks if re.match(sys.argv[2]+r'\s',b)]
if len(blocks)!=1: raise SystemExit(1)
b=blocks[0]
if not re.search(r'(?m)^\s*state:\s*DeploymentState::running\s*$',b): raise SystemExit(1)
for key in ('nTarget','nDeployed','nHealthy'):
    if re.findall(r'(?m)(?:^|[ \t])'+key+r':[ \t]*(\d+)(?=\s|$)',b)!=['1']: raise SystemExit(1)
PY
    then cp "$ROOT/app-report.log" "$ROOT/v$version-app-report.log"; return 0; fi
    sleep .25
  done
  m "v$version-timeout-cluster-report" 10 clusterReport "$CLUSTER" || true
  capture_native
  return 1
}
m deploy-v1 180 deploy "$CLUSTER" "$(<"$ROOT/v1-plan.json")" "$BLOB"
rg -q 'SpinApplicationResponseCode::okay' "$ROOT/deploy-v1.log"
wait_app 1
SPARE_ADDRESS=$(jq -r '.nodes[]|select(.index==4)|.public6' "$MANIFEST")
# Use the provider's existing public IPv6 endpoint. Registering the private
# management address as hosted ingress would also encapsulate Brain control
# traffic to that address through the application overlay.
m prefix 30 registerRoutableSubnet "$CLUSTER" "$(jq -nc --arg n "$APP-v2" --arg u "$SPARE_UUID" --arg p "$SPARE_ADDRESS/128" '{name:$n,kind:"BGP",prefix:$p,usage:"wormholes",ingressScope:"singleMachine",machineUUID:$u}')"
rg -q 'registerRoutableSubnet success=1 .*ingressScope=singleMachine ' "$ROOT/prefix.log"
PREFIX_UUID=$(rg -m1 -o 'uuid=(0x)?[0-9a-fA-F]+' "$ROOT/prefix.log" | cut -d= -f2)
[[ $PREFIX_UUID =~ ^(0x)?[0-9a-fA-F]{1,32}$ ]]
OPERATION=$(python3 -c 'import uuid; print(uuid.uuid4())')
POLICY=$(jq -nc --arg operation "$OPERATION" --arg spare "$SPARE_UUID" --argjson app "$APPID" '{applicationID:$app,versionID:2,operationID:$operation,eligibleMachineUUIDs:[$spare]}')
printf '%s\n' "$POLICY" >"$ROOT/placement-policy.json"
m policy 30 placementPolicy "$CLUSTER" "$POLICY"
rg -q 'placementPolicy success=1 ' "$ROOT/policy.log"
jq --arg prefix "$PREFIX_UUID" '.config.versionID=2|.wormholes=[{name:"spare-ping",source:"registeredRoutablePrefix",routablePrefixUUID:$prefix,externalPort:19090,containerPort:19090,layer4:"TCP",isQuic:false}]' "$ROOT/v1-plan.json" >"$ROOT/v2-plan.json"
m deploy-v2 180 deploy "$CLUSTER" "$(<"$ROOT/v2-plan.json")" "$BLOB"
rg -q 'SpinApplicationResponseCode::okay' "$ROOT/deploy-v2.log"
wait_app 2
m endpoint-leases 10 pullRoutableResourceLeases "$CLUSTER"
m payload-placement 10 clusterReport "$CLUSTER"
python3 - "$ROOT/payload-placement.log" "$SPARE_UUID" "$APPID" "$ROOT/payload-placement.json" <<'PY'
import json,pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text(); target=int(sys.argv[2],16); deployment=str((int(sys.argv[3])<<48)|2)
found=[]
for b in re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)',text):
    identity=re.search(r'\bidentity uuid=(\S+)',b); placement=re.search(r'\bdeploymentIDs=([^\s]*)',b)
    if identity and placement and deployment in placement[1].split(','): found.append(int(identity[1],16))
assert found==[target],('payload not placed only on joined spare',found,target)
pathlib.Path(sys.argv[4]).write_text(json.dumps(dict(deploymentID=deployment,machineUUID=f'0x{target:032x}'),indent=2)+'\n')
PY
deadline=$(( $(date +%s) + 30 ))
while ! m payload-ready 8 probeTestCluster "$CLUSTER" "$SPARE_ADDRESS" 19090 ping pong 3000 0; do
  if (( $(date +%s) >= deadline )); then
    m payload-container-logs 10 containerLogs "$CLUSTER" "$APP" 65536 || true
    capture_native
    exit 1
  fi
  sleep .25
done
for n in 1 2 3; do
  m "payload-$n" 8 probeTestCluster "$CLUSTER" "$SPARE_ADDRESS" 19090 ping pong 3000 0
  rg -q 'probeTestCluster success=1 ' "$ROOT/payload-$n.log"
done
printf 'PASS: real offline Brain-owned spare enrollment, same-operation leader recovery and isolated application payload\n'
