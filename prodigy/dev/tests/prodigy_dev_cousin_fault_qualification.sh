#!/usr/bin/env bash
# Finite G3B graph faults. All lifecycle and network actions are Mothership requests.
set -Eeuo pipefail
if [[ ${1:-} == --validate-only && $# == 1 ]]; then bash -n "$0"; exit 0; fi
TEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$TEST_DIR/prodigy_dev_discombobulator_artifact_helpers.sh"
prodigy_dev_reexec_in_private_mount_namespace_once \
  PRODIGY_DEV_PAIR_ENROLLMENT_MOUNT_NS_READY bash "${BASH_SOURCE[0]}" "$@"
PRODIGY_DEV_COUSIN_GRAPH_LIBRARY=1 source "$TEST_DIR/prodigy_dev_cousin_multicluster_qualification.sh" "$@"
case ${PRODIGY_DEV_COUSIN_FAULT_REGION_ONLY:-0} in
  0|1) ;;
  *) echo 'FAIL: PRODIGY_DEV_COUSIN_FAULT_REGION_ONLY must be 0 or 1' >&2; exit 2 ;;
esac

independent_quorums() {
  local phase=$1 label
  for label in "$@"; do
    [[ $label == "$phase" ]] && continue
    wait_ready "${CLUSTERS[$label]}" "$phase-$label"
  done
  python3 - "$ROOT" "$@" <<'PY_QUORUM'
import pathlib,re,sys,json
root=pathlib.Path(sys.argv[1]); phase=sys.argv[2]; groups={}
for label in sys.argv[3:]:
    data=(root/f'{phase}-{label}-cluster-report.log').read_text()
    ids={int(x,16) for x in re.findall(r'(?m)^\s*identity uuid=(0x[0-9a-f]+) ',data)}
    assert len(ids)==3 and all(not ids.intersection(group) for group in groups.values())
    groups[label]=ids
baseline_path=root/'initial-quorums.json'
if phase == 'initial':
    assert set(groups)=={'a','b','c'} and not baseline_path.exists(), 'initial quorum ledger already exists'
    baseline={label:sorted(map(str,ids)) for label,ids in groups.items()}
else:
    assert baseline_path.exists(), 'missing immutable initial quorum ledger'
    baseline=json.loads(baseline_path.read_text())
    assert set(baseline)=={'a','b','c'}
    for label,ids in groups.items():
        assert sorted(map(str,ids))==baseline[label], f'{label} membership changed from its initial quorum'
(root/(phase+'-quorums.json')).write_text(json.dumps({label:sorted(map(str,ids)) for label,ids in groups.items()},indent=2)+'\n')
PY_QUORUM
}

pair_fault() {
  local direction=$1 phase="pair-$1"
  cp "$ROOT/graph-current-spec.json" "$ROOT/$phase-before-spec.json"
  prodigy_dev_cousin_mark_time "$ROOT/$phase-sealed"
  m "$phase" 70 "$ROOT/$phase.log" testClusterPairControl "${OPERATIONS[ab]}" fault 0 45000 "$direction" &
  PAIR_PARTITION_PID=$!
  COUSIN_OFFLINE=1
  wait "$PAIR_PARTITION_PID"
  PAIR_PARTITION_PID=0
  prodigy_dev_cousin_mark_time "$ROOT/$phase-completed"
  ok "$ROOT/$phase.log" testClusterPairControl
  python3 "$TEST_DIR/prodigy_dev_cousin_fault_observe.py" "$ROOT" "$phase" pair "${OPERATIONS[ab]}" "$direction"
  COUSIN_OFFLINE=0
  query_pair ab
  independent_quorums "$phase-healed" a b c
  observe_graph "$phase-healed" ab ba ac ca bc cb
  cp "$ROOT/graph-$phase-healed-spec.json" "$ROOT/graph-current-spec.json"
}

reject_fault_requests() {
  local scenario operation=${OPERATIONS[ab]}
  for scenario in direction missing extra delay duration unknown; do
    case $scenario in
      direction) set -- "$operation" fault 0 1 invalid ;;
      missing) set -- "$operation" fault 0 ;;
      extra) set -- "$operation" fault 0 1 both extra ;;
      delay) set -- "$operation" fault 30001 1 ;;
      duration) set -- "$operation" fault 0 60001 ;;
      unknown) set -- "$(new_operation)" fault 0 1 ;;
    esac
    if m "reject-fault-$scenario" 15 "$ROOT/reject-fault-$scenario.log" testClusterPairControl "$@"; then
      echo "FAIL: invalid pair fault $scenario accepted" >&2; return 1
    fi
    rg -q 'testClusterPairControl success=0' "$ROOT/reject-fault-$scenario.log"
  done
  query_pair ab
}

region_fault() {
  local phase=region-c
  cp "$ROOT/graph-current-spec.json" "$ROOT/$phase-before-spec.json"
  m "$phase" 70 "$ROOT/$phase.log" faultTestCluster "${CLUSTERS[c]}" link 1,2,3 45000 0 0 0 &
  PAIR_PARTITION_PID=$!
  python3 - "${WORKSPACES[c]}/fault-events.log" <<'PY_DOWN'
import pathlib,re,sys,time
path=pathlib.Path(sys.argv[1])
# The sealed provider changes three links sequentially; allow their bounded
# setup latency while still requiring the witness before the 45s outage ends.
deadline=time.monotonic()+30
while True:
    data=path.read_text() if path.exists() else ''
    down=re.findall(r'fault-link runtime=\d+ link=(vp[123]) state=down atMs=\d+ monotonicMs=\d+',data)
    assert len(down)<=3, 'unexpected prior regional fault records'
    if set(down)=={'vp1','vp2','vp3'}: break
    if time.monotonic()>=deadline: raise SystemExit('region outage has no exact provider active witness')
    time.sleep(.1)
PY_DOWN
  # These read-only reports precede the sealed payload window inside the outage.
  independent_quorums "$phase-active" a b
  prodigy_dev_cousin_mark_time "$ROOT/$phase-sealed"
  COUSIN_OFFLINE=1
  wait "$PAIR_PARTITION_PID"
  PAIR_PARTITION_PID=0
  prodigy_dev_cousin_mark_time "$ROOT/$phase-completed"
  ok "$ROOT/$phase.log" faultTestCluster
  cp "${WORKSPACES[c]}/fault-events.log" "$ROOT/$phase-events.log"
  python3 "$TEST_DIR/prodigy_dev_cousin_fault_observe.py" "$ROOT" "$phase" region
  COUSIN_OFFLINE=0
  independent_quorums "$phase-healed" a b c
  observe_graph "$phase-healed" ab ba ac ca bc cb
  cp "$ROOT/graph-$phase-healed-spec.json" "$ROOT/graph-current-spec.json"
}

master_fault() {
  local phase=$1; shift
  local label index uuid boot pid outage_proof_status=0 fault_status=0
  local fault_duration_ms=12000 proof_margin_ms=500
  local -a outage_proof_pids=()
  for label in "$@"; do
    wait_ready "${CLUSTERS[$label]}" "$phase-$label-before"
    IFS=$'\t' read -r index uuid boot < <(master_identity "$ROOT/$phase-$label-before-cluster-report.log" "${MANIFESTS[$label]}")
    [[ $index =~ ^[1-3]$ && -n $uuid && -n $boot ]]
    pid=$(jq -r --argjson index "$index" '.nodes[]|select(.index==$index)|.pid' "${MANIFESTS[$label]}")
    jq -nc --argjson index "$index" --arg uuid "$uuid" --arg boot "$boot" --argjson pid "$pid" \
      '{index:$index,uuid:$uuid,boot:$boot,pid:$pid}' >"$ROOT/$phase-$label-selected.json"
  done
  prodigy_dev_cousin_mark_time "$ROOT/$phase-started"
  if [[ $# == 2 ]]; then
    local first_label=$1 second_label=$2 first_index second_index
    first_index=$(jq -r .index "$ROOT/$phase-$first_label-selected.json")
    second_index=$(jq -r .index "$ROOT/$phase-$second_label-selected.json")
    # One typed Mothership request owns both provider faults. The harness never
    # races two CLI/TidesDB clients to obtain overlapping outages.
    m "$phase-faults" 55 "$ROOT/$phase-faults.log" faultTestClusters \
      "${CLUSTERS[$first_label]}" "$first_index" \
      "${CLUSTERS[$second_label]}" "$second_index" "$fault_duration_ms" &
    GRAPH_FAULT_PIDS+=("$!")
  else
    for label in "$@"; do
      index=$(jq -r .index "$ROOT/$phase-$label-selected.json")
      m "$phase-$label-fault" 55 "$ROOT/$phase-$label-fault.log" faultTestCluster "${CLUSTERS[$label]}" crash "$index" "$fault_duration_ms" 0 0 0 &
      GRAPH_FAULT_PIDS+=("$!")
    done
  fi
  for label in "$@"; do
    (
    index=$(jq -r .index "$ROOT/$phase-$label-selected.json")
    python3 - "${WORKSPACES[$label]}/fault-events.log" "$index" "$(cat "$ROOT/$phase-started-monotonic-ms")" \
      "$ROOT/$phase-$label-crash.json" <<'PY_ACTIVE'
import json,pathlib,re,sys,time
path=pathlib.Path(sys.argv[1]); index=int(sys.argv[2]); started=int(sys.argv[3]); output=pathlib.Path(sys.argv[4]); deadline=time.monotonic()+4
while True:
    data=path.read_text() if path.exists() else ''
    events=[{'runtime':int(runtime),'machine':int(machine),'atMs':int(at),'monotonicMs':int(mono)}
            for runtime,machine,at,mono in re.findall(r'fault-crash runtime=(\d+) machine=(\d+) atMs=(\d+) monotonicMs=(\d+)',data)
            if int(machine)==index and int(mono)>=started]
    if len(events)==1:
        output.write_text(json.dumps(events[0],indent=2)+'\n')
        break
    if len(events)>1: raise SystemExit('controller fault emitted duplicate active events')
    if time.monotonic()>=deadline: raise SystemExit('controller fault has no active provider witness')
    time.sleep(.1)
PY_ACTIVE
    crash_at_ms=$(jq -r .atMs "$ROOT/$phase-$label-crash.json")
    proof_deadline_ms=$(( crash_at_ms + fault_duration_ms - proof_margin_ms ))
    while true; do
      (( $(date +%s%3N) < proof_deadline_ms )) || {
        echo "FAIL: no exact in-outage controller failover proof for $phase-$label" >&2
        exit 1
      }
      if m "report-$phase-$label-during" 3 "$ROOT/$phase-$label-during-cluster-report.log" clusterReport "${CLUSTERS[$label]}" &&
         receipt=$(find "$ROOT/receipts" -maxdepth 1 -type f -name "report-$phase-$label-during-*.json" -print | sort | tail -n 1) &&
         [[ -n $receipt ]] &&
         python3 - "$ROOT/$phase-$label-before-cluster-report.log" \
           "$ROOT/$phase-$label-during-cluster-report.log" \
           "$ROOT/$phase-$label-selected.json" \
           "$ROOT/$phase-$label-during-qualified.json" \
           "$receipt" "$crash_at_ms" "$proof_deadline_ms" <<'PY_DURING'
import json,pathlib,re,sys
before,during,selected_path,output,receipt_path=map(pathlib.Path,sys.argv[1:6])
crash_at_ms=int(sys.argv[6]); proof_deadline_ms=int(sys.argv[7])
selected=json.loads(selected_path.read_text())
receipt=json.loads(receipt_path.read_text())
assert receipt['status']==0 and receipt['operation']=='clusterReport'
assert crash_at_ms <= receipt['startedMs'] <= receipt['endedMs'] < proof_deadline_ms, \
       'controller report was not completed inside the provider-witnessed outage'
def entries(path):
    blocks=re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)',path.read_text())
    assert len(blocks)==3, f'{path.name} must contain exactly three machine blocks'
    result={}
    for block in blocks:
        identity=re.search(r'(?m)^\s*identity uuid=(\S+)',block)
        state=re.search(r'(?m)^\s*Machine: state=(\S+) role=brain\b',block)
        lifecycle=re.search(r'\bcontrolPlaneReachable=(\d+) runtimeReady=(\d+) currentMaster=(\d+)(?:\s|$)',block)
        assert identity and state and lifecycle, f'{path.name} has a malformed machine block'
        assert identity[1] not in result, f'{path.name} has duplicate machine uuid {identity[1]}'
        result[identity[1]]={'state':state[1],'reachable':int(lifecycle[1]),
                             'runtimeReady':int(lifecycle[2]),'currentMaster':int(lifecycle[3])}
    return result
expected=entries(before); active=entries(during)
assert set(active)==set(expected), 'controller outage changed membership'
assert selected['uuid'] in active
faulted=active[selected['uuid']]
assert faulted['currentMaster']==0 and (faulted['state']!='healthy' or not faulted['reachable']), \
       'selected controller still appears available during provider outage'
survivors={uuid:value for uuid,value in active.items() if uuid!=selected['uuid']}
assert len(survivors)==2 and all(value['state']=='healthy' and value['reachable'] for value in survivors.values()), \
       'controller survivors were not both healthy and reachable during outage'
masters=[uuid for uuid,value in survivors.items() if value['currentMaster']]
assert len(masters)==1, 'controller outage did not elect exactly one surviving master'
output.write_text(json.dumps({'selected':selected,'survivingMaster':masters[0],'survivors':survivors,
                              'reportReceipt':receipt,'crashAtMs':crash_at_ms,
                              'proofDeadlineMs':proof_deadline_ms},indent=2)+'\n')
PY_DURING
      then
        break
      fi
      sleep .1
    done
    ) &
    outage_proof_pids+=("$!")
  done
  for pid in "${outage_proof_pids[@]}"; do
    if ! wait "$pid"; then outage_proof_status=1; fi
  done
  for pid in "${GRAPH_FAULT_PIDS[@]}"; do
    if ! wait "$pid"; then fault_status=1; fi
  done
  GRAPH_FAULT_PIDS=()
  (( outage_proof_status == 0 && fault_status == 0 )) || return 1
  if [[ $# == 2 ]]; then
    ok "$ROOT/$phase-faults.log" faultTestClusters
  fi
  for label in "$@"; do
    if [[ $# != 2 ]]; then ok "$ROOT/$phase-$label-fault.log" faultTestCluster; fi
    wait_ready "${CLUSTERS[$label]}" "$phase-$label-after"
  done
  python3 - "$ROOT" "$phase" "$@" <<'PY_MASTER'
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]);phase=sys.argv[2];proof=[];times=[]
workspaces={'a':'first-workspace','b':'second-workspace'}
labels=sys.argv[3:]
if len(labels)==2:
    faults=[json.loads(path.read_text()) for path in (root/'receipts').glob(phase+'-*fault*.json')]
    assert len(faults)==1 and faults[0]['label']==phase+'-faults' and faults[0]['operation']=='faultTestClusters' and faults[0]['status']==0, \
        'concurrent controller phase must have one successful batch fault receipt'
    assert not [receipt for receipt in faults if receipt['operation']=='faultTestCluster'], \
        'concurrent controller phase must not issue standalone fault requests'
start=int((root/(phase+'-started-monotonic-ms')).read_text())
for label in labels:
    selected=json.loads((root/f'{phase}-{label}-selected.json').read_text())
    before=(root/f'{phase}-{label}-before-cluster-report.log').read_text()
    before_blocks=re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)',before)
    assert len(before_blocks)==3, 'pre-fault report must contain exactly three machine blocks'
    before_uuids=[]
    for block in before_blocks:
        identity=re.search(r'(?m)^\s*identity uuid=(\S+)',block)
        assert identity, 'pre-fault report has a malformed machine block'
        before_uuids.append(identity[1])
    assert len(set(before_uuids))==3, 'pre-fault report has duplicate machine UUIDs'
    report=(root/f'{phase}-{label}-after-cluster-report.log').read_text()
    blocks=re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)',report)
    assert len(blocks)==3, 'post-fault report must contain exactly three machine blocks'
    entries=[]
    for block in blocks:
        identity=re.search(r'(?m)^\s*identity uuid=(\S+)',block)
        boot=re.search(r'\bbootTimeMs=(\d+)',block)
        lifecycle=re.search(r'\bcontrolPlaneReachable=(\d+) runtimeReady=(\d+) currentMaster=(\d+)(?:\s|$)',block)
        assert identity and boot and lifecycle, 'post-fault report has a malformed machine block'
        entries.append((identity[1],boot[1],int(lifecycle[3])==1))
    assert len({x[0] for x in entries})==3, 'post-fault report has duplicate machine UUIDs'
    assert {x[0] for x in entries}==set(before_uuids), 'controller recovery changed membership'
    masters=[x[0] for x in entries if x[2]]
    assert len(masters)==1, 'recovered controller quorum has no unique master'
    assert len([x for x in entries if x[0]==selected['uuid'] and x[1]!=selected['boot']])==1
    workspace=root/workspaces[label]
    manifest=json.loads((workspace/'test-cluster-manifest.json').read_text())
    nodes=[n for n in manifest['nodes'] if n['index']==selected['index']]
    assert len(nodes)==1 and nodes[0]['pid']!=selected['pid']
    events=re.findall(r'fault-crash runtime=(\d+) machine=(\d+) atMs=(\d+) monotonicMs=(\d+)',(workspace/'fault-events.log').read_text())
    matching=[int(mono) for _,index,_,mono in events if int(index)==selected['index'] and int(mono)>=start]
    assert len(matching)==1
    times.extend(matching)
    during=json.loads((root/f'{phase}-{label}-during-qualified.json').read_text())
    assert during['selected']==selected and during['survivingMaster']!=selected['uuid']
    proof.append({'cluster':label,'selected':selected,'duringMaster':during['survivingMaster'],
                  'recoveredMaster':masters[0],'newPID':nodes[0]['pid'],'crashMonotonicMs':matching[0]})
if len(times)==2: assert max(times)-min(times)<12000, 'concurrent controller outages did not overlap'
(root/(phase+'-qualified.json')).write_text(json.dumps(proof,indent=2)+'\n')
PY_MASTER
  independent_quorums "$phase-recovered" a b c
  observe_graph "$phase-recovered" ab ba ac ca bc cb
  cp "$ROOT/graph-$phase-recovered-spec.json" "$ROOT/graph-current-spec.json"
}

sha256sum "$PRODIGY_BIN" "$MOTHERSHIP_BIN" "$BUNDLE" "$PRODIGY_DEV_COUSIN_PROBE_BIN" >"$ROOT/artifact-identities.sha256"
for label in a b c; do create_graph_cluster "$label"; done
for pair in ab ac bc; do prepare_pair "$pair"; done
for route in ab ba ac ca bc cb; do
  pair=$route
  [[ $route != ba ]] || pair=ab
  [[ $route != ca ]] || pair=ac
  [[ $route != cb ]] || pair=bc
  prepare_route "$route" "$pair"
done
for pair in ab ac bc; do query_pair "$pair"; done
reject_fault_requests
independent_quorums initial a b c
observe_graph initial ab ba ac ca bc cb
cp "$ROOT/graph-initial-spec.json" "$ROOT/graph-current-spec.json"
if [[ ${PRODIGY_DEV_COUSIN_FAULT_CONTROLLER_ONLY:-0} == 1 ]]; then
  master_fault master-a a
  echo 'PASS: bounded independent controller fault with native current graph recovery'
  exit 0
fi
if [[ ${PRODIGY_DEV_COUSIN_FAULT_REGION_ONLY:-0} == 1 ]]; then
  region_fault
  echo 'PASS: bounded Region C fault with native current graph recovery'
  exit 0
fi
for direction in both first-to-second second-to-first; do pair_fault "$direction"; done
region_fault
master_fault master-a a
master_fault master-b b
master_fault masters-concurrent a b
m close-ab 45 "$ROOT/close-ab.log" testClusterPairControl "${OPERATIONS[ab]}" remove
ok "$ROOT/close-ab.log" testClusterPairControl
PAIR_REMOVED[ab]=1
OPERATION=${OPERATIONS[ab]} assert_pair_control_removed
if m reject-closed-fault 15 "$ROOT/reject-closed-fault.log" testClusterPairControl "${OPERATIONS[ab]}" fault 0 1; then
  echo 'FAIL: removed pair accepted a fault' >&2; exit 1
fi
rg -q 'testClusterPairControl success=0' "$ROOT/reject-closed-fault.log"
echo 'PASS: bounded directed pair, region and independent controller faults with native current graph recovery'
