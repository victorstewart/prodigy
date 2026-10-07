#!/usr/bin/env bash
# Mothership-client qualification of reciprocal and triangular COUSIN routes.
set -Eeuo pipefail
if [[ ${1:-} == --validate-only && $# == 1 ]]; then bash -n "$0"; exit 0; fi
TEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$TEST_DIR/prodigy_dev_discombobulator_artifact_helpers.sh"
prodigy_dev_reexec_in_private_mount_namespace_once \
  PRODIGY_DEV_PAIR_ENROLLMENT_MOUNT_NS_READY bash "${BASH_SOURCE[0]}" "$@"
PRODIGY_DEV_PAIR_ENROLLMENT_LIBRARY=1 source "$TEST_DIR/prodigy_dev_pair_enrollment_qualification.sh" "$@"
source "$TEST_DIR/prodigy_dev_cousin_session_qualification.sh"
GRAPH_ROOT=$ROOT
PRODIGY_DEV_COUSIN_GRAPH=1
[[ -x ${PRODIGY_DEV_COUSIN_PROBE_BIN:-} ]] || { echo 'FAIL: graph requires native probe' >&2; exit 1; }
declare -A CLUSTERS WORKSPACES MANIFESTS CREATED OPERATIONS PAIR_ATTEMPTED PAIR_REMOVED ROUTE_IDS PREFIX_KEYS
CLUSTERS[a]=$FIRST; CLUSTERS[b]=$SECOND; CLUSTERS[c]="pair-enroll-third-$$-$RANDOM"
WORKSPACES[a]=$FIRST_WORKSPACE; WORKSPACES[b]=$SECOND_WORKSPACE; WORKSPACES[c]="$ROOT/third-workspace"
for label in a b c; do MANIFESTS[$label]="${WORKSPACES[$label]}/test-cluster-manifest.json"; CREATED[$label]=0; done
for pair in ab ac bc; do OPERATIONS[$pair]=$(new_operation); PAIR_ATTEMPTED[$pair]=0; PAIR_REMOVED[$pair]=0; done
for route in ab ba ac ca bc cb; do
  for attempt in {1..16}; do
    route_id=$(new_operation)
    prefix_key=$(python3 -c 'import sys; print((int(sys.argv[1],16)>>32)&0xffffffff)' "$route_id")
    if [[ -z ${PREFIX_KEYS[$prefix_key]:-} ]]; then
      PREFIX_KEYS[$prefix_key]=$route; ROUTE_IDS[$route]=$route_id; break
    fi
  done
  [[ -n ${ROUTE_IDS[$route]:-} ]] || { echo 'FAIL: cannot allocate distinct route prefixes' >&2; exit 1; }
done

# All resource lifecycle remains with Mothership, including failure cleanup.
graph_cleanup() {
  local status=$? label pair file
  COUSIN_OFFLINE=0
  trap - EXIT HUP INT TERM
  set +e
  for label in a b c; do copy_cluster_logs "$label" "${MANIFESTS[$label]}" || status=1; done
  for pair in ab ac bc; do
    if (( PAIR_ATTEMPTED[$pair] )); then
      mkdir -p "$ROOT/pairs/$pair/provider"
      for file in /mnt/prodigy-vdc-pair-control/"${OPERATIONS[$pair]}"/*; do
        [[ -f $file && ! -L $file ]] || continue
        cp -p "$file" "$ROOT/pairs/$pair/provider/" || status=1
      done
      if (( !PAIR_REMOVED[$pair] )); then
        m "remove-pair-$pair" 45 "$ROOT/remove-pair-$pair.log" testClusterPairControl "${OPERATIONS[$pair]}" remove || status=1
      fi
      local OPERATION=${OPERATIONS[$pair]}
      assert_pair_control_removed || status=1
    fi
  done
  for label in a b c; do
    if (( CREATED[$label] )); then remove_cluster "${CLUSTERS[$label]}" "$ROOT/remove-$label.log" || status=1; fi
    [[ ! -e ${MANIFESTS[$label]} ]] || status=1
  done
  jq -nc --argjson exitCode "$status" '{exitCode:$exitCode,clusters:3,directedRoutes:6}' >"$ROOT/result.json"
  printf 'COUSIN_MULTICLUSTER_EVIDENCE=%s\n' "$ROOT"
  exit "$status"
}
trap graph_cleanup EXIT

create_graph_cluster() {
  local label=$1
  CREATED[$label]=1
  create_cluster "${CLUSTERS[$label]}" "${WORKSPACES[$label]}" "$ROOT/create-$label.log"
  wait_ready "${CLUSTERS[$label]}" "$label"
}

prepare_pair() {
  local pair=$1 src=${1:0:1} dst=${1:1:1}
  local ROOT="$GRAPH_ROOT/pairs/$pair" FIRST=${CLUSTERS[$src]} SECOND=${CLUSTERS[$dst]}
  local FIRST_MANIFEST=${MANIFESTS[$src]} SECOND_MANIFEST=${MANIFESTS[$dst]} OPERATION=${OPERATIONS[$pair]}
  mkdir -p "$ROOT/receipts"
  cp "$GRAPH_ROOT/$src-cluster-report.log" "$ROOT/first-cluster-report.log"
  cp "$GRAPH_ROOT/$dst-cluster-report.log" "$ROOT/second-cluster-report.log"
  m enroll 45 "$ROOT/enroll.log" enrollClusterPair "$FIRST" "$SECOND" "$OPERATION"
  enrollment_complete "$ROOT/enroll.log"
  PAIR_ATTEMPTED[$pair]=1
  m prepare 45 "$ROOT/prepare.log" testClusterPairControl "$OPERATION" prepare
  ok "$ROOT/prepare.log" testClusterPairControl
  wait_pair_control initial
}

prepare_route() {
  local name=$1 pair=$2 src=${1:0:1} dst=${1:1:1}
  local ROOT="$GRAPH_ROOT/routes/$name" FIRST=${CLUSTERS[$src]} SECOND=${CLUSTERS[$dst]}
  local OPERATION=${OPERATIONS[$pair]} PRODIGY_DEV_COUSIN_ROUTE_ID
  local PRODIGY_DEV_COUSIN_PREPARE_ONLY=1 PRODIGY_DEV_COUSIN_GRAPH=1
  local PRODIGY_DEV_COUSIN_EXISTING_ROUTES="$GRAPH_ROOT/routes"
  PRODIGY_DEV_COUSIN_ROUTE_ID=${ROUTE_IDS[$name]}
  mkdir -p "$ROOT/receipts"
  cp "$GRAPH_ROOT/create-$src.log" "$ROOT/create-first.log"
  cp "$GRAPH_ROOT/create-$dst.log" "$ROOT/create-second.log"
  cp "$GRAPH_ROOT/$src-cluster-report.log" "$ROOT/first-cluster-report.log"
  cp "$GRAPH_ROOT/pairs/$pair/pair-control-initial.json" "$ROOT/pair-control-initial.json"
  prodigy_dev_qualify_cousin_session
  # An exact retry must leave both immutable direction tuples intact.
  m transit-retry 45 "$ROOT/transit-retry.log" testClusterPairControl "$OPERATION" service "$(cat "$ROOT/cousin-service-transit.json")"
  ok "$ROOT/transit-retry.log" testClusterPairControl
}

query_pair() {
  local pair=$1 reverse="${1:1:1}${1:0:1}"
  m "query-$pair" 45 "$ROOT/query-$pair.log" testClusterPairControl "${OPERATIONS[$pair]}" query
  ok "$ROOT/query-$pair.log" testClusterPairControl
  python3 - "$ROOT/query-$pair.log" "$ROOT/routes/$pair/cousin-service-transit.json" "$ROOT/routes/$reverse/cousin-service-transit.json" <<'PY_QUERY'
import json,pathlib,re,sys
transits=sorted((json.loads(pathlib.Path(p).read_text()) for p in sys.argv[2:]),key=lambda x:int(x['sourceClusterUUID'],16))
expected=[(x['sourceWhiteholeIPv6']+':'+str(x['sourceTCPPort']),x['destinationWormholeIPv6']+':'+str(x['destinationTCPPort'])) for x in transits]
seen=re.findall(r'\bservice=1\s+source=(\S+)\s+destination=(\S+)',pathlib.Path(sys.argv[1]).read_text())
assert seen==expected, (seen,expected)
PY_QUERY
}

observe_graph() {
  local phase=$1; shift
  prodigy_dev_cousin_mark_time "$ROOT/graph-$phase"
  COUSIN_OFFLINE=1
  python3 - "$ROOT" "$phase" "$@" <<'PY_SPEC'
import json,pathlib,re,sys,time
root=pathlib.Path(sys.argv[1]); phase=sys.argv[2]; names=sys.argv[3:]
marker=int((root/('graph-'+phase+'-monotonic-ms')).read_text())
workspaces={'a':'first-workspace','b':'second-workspace','c':'third-workspace'}
def records(data,kind):
    return [dict(re.findall(r'(\w+)=([^\s]+)',s)) for s in data.splitlines() if s.startswith('cousin_session_probe.'+kind+' ')]
def candidates(label,deployment,role):
    found=[]
    manifest=json.loads((root/workspaces[label]/'test-cluster-manifest.json').read_text())
    for node in manifest['nodes']:
        for path in pathlib.Path(f"/proc/{node['pid']}/root/containers").glob('*/rootfs/logs/stdout.log'):
            try: data=path.read_text(errors='replace')
            except (FileNotFoundError,PermissionError): continue
            for ready in records(data,'ready'):
                if ready.get('deployment')==str(deployment) and ready.get('source')==role:
                    found.append((path,ready,data))
    return found
routes=[]
for name in names:
    transit=json.loads((root/'routes'/name/'cousin-service-transit.json').read_text())
    deadline=time.monotonic()+15
    while True:
        sources=[x for x in candidates(name[0],transit['sourceDeploymentID'],'1') if any(
            r.get('source')==transit['sourceWhiteholeIPv6'] and r.get('sourcePort')==str(transit['sourceTCPPort']) for r in records(x[2],'request'))]
        destinations=candidates(name[1],transit['destinationDeploymentID'],'0')
        if len(sources)==1 and len(destinations)==3: break
        if time.monotonic()>=deadline: raise SystemExit(f'no exact native identities for {name}: source={len(sources)} destination={len(destinations)}')
        time.sleep(.2)
    path,ready,_=sources[0]
    routes.append({'name':name,'sourceLog':str(path),'sourceUUID':ready['uuid'],
       'sourceDeploymentID':transit['sourceDeploymentID'],'sourceTuple':[transit['sourceWhiteholeIPv6'],transit['sourceTCPPort']],
       'destinationUUIDs':[x[1]['uuid'] for x in destinations],
       'destinationLogs':[{'path':str(p),'uuid':r['uuid'],'deploymentID':transit['destinationDeploymentID']} for p,r,_ in destinations],
       'afterMonotonicMs':marker,'transit':transit})
spec={'routes':routes,'minimumWindowMs':12000,'timeoutSeconds':240,'outputName':'graph-'+phase+'-qualified.json'}
(root/('graph-'+phase+'-spec.json')).write_text(json.dumps(spec,indent=2)+'\n')
PY_SPEC
  python3 "$TEST_DIR/prodigy_dev_cousin_multicluster_observe.py" "$ROOT" "$ROOT/graph-$phase-spec.json"
  COUSIN_OFFLINE=0
}

sha256sum "$PRODIGY_BIN" "$MOTHERSHIP_BIN" "$BUNDLE" "$PRODIGY_DEV_COUSIN_PROBE_BIN" >"$ROOT/artifact-identities.sha256"
create_graph_cluster a
create_graph_cluster b
prepare_pair ab
prepare_route ab ab
prepare_route ba ab
query_pair ab
observe_graph reciprocal ab ba
create_graph_cluster c
prepare_pair ac
prepare_pair bc
prepare_route ac ac
prepare_route ca ac
prepare_route bc bc
prepare_route cb bc
for pair in ab ac bc; do query_pair "$pair"; done
for label in a b c; do wait_ready "${CLUSTERS[$label]}" "$label-before-graph"; done
python3 - "$ROOT" <<'PY_QUORUM'
import pathlib,re,sys,json
root=pathlib.Path(sys.argv[1]); groups=[]
for label in 'abc':
    data=(root/(label+'-before-graph-cluster-report.log')).read_text()
    ids={int(x,16) for x in re.findall(r'(?m)^\s*identity uuid=(0x[0-9a-f]+) ',data)}
    assert len(ids)==3 and all(not ids.intersection(g) for g in groups)
    groups.append(ids)
(root/'independent-quorums.json').write_text(json.dumps([sorted(map(str,g)) for g in groups])+'\n')
PY_QUORUM
observe_graph triangle ab ba ac ca bc cb
prodigy_dev_cousin_mark_time "$ROOT/ab-remove-request"
m remove-ab 45 "$ROOT/remove-ab.log" testClusterPairControl "${OPERATIONS[ab]}" remove
ok "$ROOT/remove-ab.log" testClusterPairControl
PAIR_REMOVED[ab]=1
OPERATION=${OPERATIONS[ab]} assert_pair_control_removed
prodigy_dev_cousin_mark_time "$ROOT/ab-removed"
observe_graph surviving ac ca bc cb
# The surviving proof supplies a bounded observation interval after removal.
# AB must have stopped exact echoes, and its application must keep retrying.
python3 - "$ROOT" <<'PY_REMOVAL'
import json,pathlib,re,sys,time
root=pathlib.Path(sys.argv[1]); marker=int((root/'ab-removed-monotonic-ms').read_text())
spec=json.loads((root/'graph-triangle-spec.json').read_text()); proof=[]
requested=int((root/'ab-remove-request-monotonic-ms').read_text())
deadline=time.monotonic()+130
for route in spec['routes'][:2]:
    while True:
        data=pathlib.Path(route['sourceLog']).read_text()
        (root/'cousin-native-logs'/(route['name']+'-source.log')).write_text(data)
        rows=[(s.split()[0],dict(re.findall(r'(\w+)=([^\s]+)',s))) for s in data.splitlines() if s.strip()]
        assert not [r for k,r in rows if k=='cousin_session_probe.round' and int(r.get('monotonicMs','0'))>marker+1000], 'removed AB boundary still carries payload'
        closed=[r for k,r in rows if k=='cousin_session_probe.closed' and int(r.get('monotonicMs','0'))>=requested]
        retries=[r for k,r in rows if k=='cousin_session_probe.request' and int(r.get('monotonicMs','0'))>=marker]
        if closed and retries: break
        if time.monotonic()>=deadline: raise SystemExit('removed route lacks bounded close and fresh retry')
        time.sleep(.2)
    proof.append({'name':route['name'],'closed':closed,'retries':retries,'latePayloads':0})
(root/'ab-removal-qualified.json').write_text(json.dumps({'removedMonotonicMs':marker,'observedUntilMonotonicMs':time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000,'routes':proof},indent=2)+'\n')
PY_REMOVAL
for label in a b c; do wait_ready "${CLUSTERS[$label]}" "$label-after-removal"; done
for pair in ac bc; do query_pair "$pair"; done
echo 'PASS: reciprocal and six-direction native COUSIN graph, independent pair removal'
