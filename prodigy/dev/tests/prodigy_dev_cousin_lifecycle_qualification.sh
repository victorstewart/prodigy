#!/usr/bin/env bash
# Sourced inside the existing Mothership-client qualification. Probe logs and
# fault receipts are observations; only Mothership may change the test cluster.
prodigy_dev_qualify_cousin_lifecycle() {
  local profile=$1 source_name=${2:-} destination_name=${3:-$2} expected_groups=1 expected_containers=3
  [[ "$profile" != horizontal ]] || { expected_groups=2; expected_containers=6; }
  local source_groups=1 source_containers=3 source_memory=256 destination_groups=$expected_groups destination_containers=$expected_containers destination_memory=256
  [[ $profile != vertical ]] || destination_memory=384
  if [[ $profile == source-horizontal-destination-vertical ]]; then source_groups=2; source_containers=6; destination_memory=384; fi
  if [[ $profile == source-vertical-destination-horizontal ]]; then source_memory=384; destination_groups=2; destination_containers=6; fi
  expected_groups=$destination_groups; expected_containers=$destination_containers
  cp "$ROOT/cousin-native-session-qualified.json" "$ROOT/cousin-native-session-before-lifecycle.json" || return
  wait "$PAIR_PARTITION_PID" || return
  PAIR_PARTITION_PID=0
  ok "$ROOT/cousin-lifecycle-partition.log" testClusterPairControl || return 1
  python3 "$TEST_DIR/prodigy_dev_cousin_session_observe.py" "$ROOT" snapshot || return
  python3 - "$ROOT" "$profile" <<'PY_LIFECYCLE' || return
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]); profile=sys.argv[2]
endpoints=json.loads((root/'cousin-endpoints.json').read_text())
expected={'source':str((int(endpoints['sourceApplicationID'])<<48)|1), 'destination':str((int(endpoints['destinationApplicationID'])<<48)|1)}
fault=re.search(r'PAIR_CONTROL_FAULT operationID=\w+ clock=CLOCK_BOOTTIME delayMs=(\d+) durationMs=(\d+) beginNs=(\d+) endNs=(\d+)',
                (root/'cousin-lifecycle-partition.log').read_text())
assert fault, 'missing provider-owned pair partition interval'
delay,duration,begin,end=map(int,fault.groups())
assert delay==15000 and duration==60000 and end-begin>=duration*1_000_000
events=[]; samples={'source':[], 'destination':[]}; metric_times=[]
for path in (root/'cousin-native-logs').glob('*-*.log'):
    side='source' if path.name.startswith('first-') else 'destination' if path.name.startswith('second-') else None
    if side is None: continue
    lines=path.read_text().splitlines()
    ready=[dict(re.findall(r'(\w+)=([^\s]+)',line)) for line in lines if line.startswith('cousin_session_probe.ready ')]
    assert len(ready)==1, 'each native log needs one current endpoint identity'
    identity=ready[0]
    assert identity.get('source') == ('1' if side=='source' else '0') and identity.get('deployment') == expected[side]
    assert re.fullmatch(r'[0-9a-f]{32}', identity.get('uuid',''))
    for line in lines:
        if not line.startswith('cousin_session_probe.'): continue
        row=dict(re.findall(r'(\w+)=([^\s]+)',line))
        if line.startswith('cousin_session_probe.scaleMetric ') and 'monotonicMs' in row:
            metric_times.append(int(row['monotonicMs'])*1_000_000)
        if 'monotonicMs' not in row or not begin<=int(row['monotonicMs'])*1_000_000<=end: continue
        if line.startswith('cousin_session_probe.scaleMetric '): samples[side].append(row)
        horizontal=(profile=='horizontal' and side=='destination') or (profile=='source-horizontal-destination-vertical' and side=='source') or (profile=='source-vertical-destination-horizontal' and side=='destination')
        vertical=(profile=='vertical' and side=='destination') or (profile=='source-horizontal-destination-vertical' and side=='destination') or (profile=='source-vertical-destination-horizontal' and side=='source')
        if horizontal and line.startswith('cousin_session_probe.ready ') and row.get('uuid')==identity['uuid'] and row.get('group')=='1':
            events.append(dict(row,log=path.name,side=side))
        if vertical and line.startswith('cousin_session_probe.resources ') and row.get('uuid')==identity['uuid'] and row.get('memoryMB')=='384':
            assert row.get('cores')=='1' and row.get('storageMB')=='64' and row.get('downscale')=='0' and row.get('accepted')=='1'
            events.append(dict(row,log=path.name,side=side))
assert any(samples.values()), 'no ordinary application scale metrics during pair partition'
assert begin<=min(metric_times)<=end, 'scale metric started before pair partition'
changed={'source','destination'} if profile.startswith('source-') else {'destination'}
assert all(samples[side] for side in changed), 'each changed side needs an ordinary metric during pair partition'
if profile.startswith('source-'):
    assert {x['uuid'] for x in events if x['side']=='source'} and {x['uuid'] for x in events if x['side']=='destination'}
    assert len({x['uuid'] for x in events if x['side']=='source'})==3 and len({x['uuid'] for x in events if x['side']=='destination'})==3, 'each changed side needs three exact local instances'
else: assert len({row['uuid'] for row in events})==3, 'all three destination replicas must progress during pair partition'
receipt={'profile':profile,'clock':'CLOCK_BOOTTIME','faultBeginNs':begin,'faultEndNs':end,
         'scaleEvents':events,'metricSamples':sum(map(len,samples.values())),'localScaleProgressDuringPeerPartition':True}
(root/'cousin-lifecycle-scaled.json').write_text(json.dumps(receipt,indent=2)+'\n')
PY_LIFECYCLE
  # Resume only read-only Mothership reporting after the offline interval to
  # verify that the ordinary scaler reached its complete local healthy target.
  COUSIN_OFFLINE=0
  if [[ $profile == source-* ]]; then
    m cousin-lifecycle-source-app 15 "$ROOT/cousin-lifecycle-source-app.log" applicationReport "$FIRST" "$source_name" || return
    python3 - "$ROOT/cousin-lifecycle-source-app.log" "$source_groups" "$source_containers" "$source_memory" <<'PY_SOURCE_HEALTH' || return
import pathlib,re,sys
data=pathlib.Path(sys.argv[1]).read_text()
for key,value in [('nShardGroups',sys.argv[2]),('nHealthy',sys.argv[3]),('nDeployed',sys.argv[3])]: assert re.findall(r'\b'+key+r':\s*(\d+)\b',data)==[value]
assert re.findall(r'containerRuntime: cores=(\d+) memMB=(\d+) storMB=(\d+)',data)==[('1',sys.argv[4],'128')]*int(sys.argv[3])
PY_SOURCE_HEALTH
  fi
  m cousin-lifecycle-app 15 "$ROOT/cousin-lifecycle-app.log" applicationReport "$SECOND" "$destination_name" || return
  python3 - "$ROOT/cousin-lifecycle-app.log" "$destination_groups" "$destination_containers" "$destination_memory" <<'PY_HEALTH' || return
import pathlib,re,sys
data=pathlib.Path(sys.argv[1]).read_text()
for field,expected in [('nShardGroups',sys.argv[2]),('nHealthy',sys.argv[3]),('nDeployed',sys.argv[3]),('nCrashes','0')]:
    assert re.findall(r'\b'+field+r':\s*(\d+)\b',data)==[expected], field
resources=re.findall(r'containerRuntime: cores=(\d+) memMB=(\d+) storMB=(\d+)',data)
assert resources==[('1',sys.argv[4],'128')]*int(sys.argv[3])
PY_HEALTH
  prodigy_dev_cousin_mark_time "$ROOT/cousin-lifecycle-recovered" || return
  COUSIN_OFFLINE=1
  python3 "$TEST_DIR/prodigy_dev_cousin_session_observe.py" "$ROOT" qualify cousin-lifecycle-recovered "$destination_groups" "$source_groups" || return
  cp "$ROOT/cousin-native-session-qualified.json" "$ROOT/cousin-native-session-after-scale.json" || return
  if [[ ${PRODIGY_DEV_COUSIN_FAULT_SOURCE:-0} == 1 ]]; then
    local source_index
    source_index=$(python3 - "$ROOT" <<'PY_SOURCE_SELECT'
import json,pathlib,re,sys
r=pathlib.Path(sys.argv[1]);q=json.loads((r/'cousin-native-session-after-scale.json').read_text());p=r/'cousin-native-logs'/(q['sourceLog']+'.log'); endpoints=json.loads((r/'cousin-endpoints.json').read_text())
m=re.fullmatch(r'first-(\d+)-\d+\.log',p.name);assert m
ready=[dict(re.findall(r'(\w+)=([^\s]+)',x)) for x in p.read_text().splitlines() if x.startswith('cousin_session_probe.ready ')]
assert len(ready)==1 and ready[0].get('source')=='1' and ready[0].get('deployment')==str((int(endpoints['sourceApplicationID'])<<48)|1)
activated=[dict(re.findall(r'(\w+)=([^\s]+)',x)) for x in p.read_text().splitlines() if x.startswith('cousin_session_probe.activate ')]
activated=[int(row['monotonicMs']) for row in activated if row.get('session')==q['sessionUUID']]; assert len(activated)==1
peers={row['peer'] for row in q['rounds']}; assert len(peers)==1
nodes=json.loads((r/'first-workspace/test-cluster-manifest.json').read_text())['nodes']; n=[x for x in nodes if x['index']==int(m[1])];assert len(n)==1
(r/'cousin-lifecycle-source-selected.json').write_text(json.dumps({'machineIndex':int(m[1]),'machinePID':n[0]['pid'],'containerUUID':ready[0]['uuid'],'sessionUUID':q['sessionUUID'],'sessionActivatedMonotonicMs':activated[0],'peerContainerUUID':peers.pop()},indent=2)+'\n')
print(m[1])
PY_SOURCE_SELECT
    ) || return
    COUSIN_OFFLINE=0; prodigy_dev_cousin_mark_time "$ROOT/cousin-lifecycle-source-restart" || return
    m cousin-lifecycle-source-restart 45 "$ROOT/cousin-lifecycle-source-restart.log" faultTestCluster "$FIRST" crash "$source_index" 12000 0 0 0 || return
    ok "$ROOT/cousin-lifecycle-source-restart.log" faultTestCluster || return 1; wait_ready "$FIRST" cousin-lifecycle-source-after-restart || return
    local source_report_deadline=$(( SECONDS + 45 )) source_restarted=0
    while (( SECONDS < source_report_deadline )); do
      m cousin-lifecycle-source-restarted-app 15 "$ROOT/cousin-lifecycle-source-restarted-app.log" applicationReport "$FIRST" "$source_name" || return
      if python3 - "$ROOT" "$ROOT/cousin-lifecycle-source-restarted-app.log" "$source_containers" "$source_memory" <<'PY_SOURCE_REPORT'
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]); data=pathlib.Path(sys.argv[2]).read_text()
for field in ('nHealthy','nDeployed'):
 assert re.findall(r'\b'+field+r':\s*(\d+)\b',data)==[sys.argv[3]]
ids=re.findall(r'containerRuntime: cores=1 memMB='+re.escape(sys.argv[4])+r' storMB=128 uuid=(\d+)',data)
assert len(ids)==int(sys.argv[3]) and len(set(ids))==len(ids)
(root/'cousin-lifecycle-source-report.json').write_text(json.dumps({'runtimeContainerUUIDs':ids}))
PY_SOURCE_REPORT
      then source_restarted=1; break; fi
      sleep .25
    done
    [[ $source_restarted == 1 ]] || return 1
    prodigy_dev_cousin_mark_time "$ROOT/cousin-lifecycle-source-restarted" || return; COUSIN_OFFLINE=1
    python3 "$TEST_DIR/prodigy_dev_cousin_session_observe.py" "$ROOT" qualify cousin-lifecycle-source-restarted "$destination_groups" "$source_groups" || return
    python3 - "$ROOT" <<'PY_SOURCE_RECOVER' || return
import json,pathlib,re,sys
r=pathlib.Path(sys.argv[1]); old=json.loads((r/'cousin-lifecycle-source-selected.json').read_text());q=json.loads((r/'cousin-native-session-qualified.json').read_text()); endpoints=json.loads((r/'cousin-endpoints.json').read_text())
assert q['sessionUUID']!=old['sessionUUID'] and int(q['request']['monotonicMs'])>int((r/'cousin-lifecycle-source-restarted-monotonic-ms').read_text())
m=re.fullmatch(r'first-(\d+)-(\d+)',q['sourceLog']); assert m and int(m[1])==old['machineIndex'], 'fresh source moved away from selected recovery machine'
reported={int(x) for x in json.loads((r/'cousin-lifecycle-source-report.json').read_text())['runtimeContainerUUIDs']}; assert int(m[2]) in reported
expectedUUID=f'{int(m[2]):032x}'
nodes=json.loads((r/'first-workspace/test-cluster-manifest.json').read_text())['nodes']; n=[x for x in nodes if x['index']==old['machineIndex']];assert len(n)==1 and n[0]['pid']!=old['machinePID']
request_marker=int((r/'cousin-lifecycle-source-restart-monotonic-ms').read_text()); recovered_marker=int((r/'cousin-lifecycle-source-restarted-monotonic-ms').read_text()); logs=list((r/'cousin-native-logs').glob(f"first-{old['machineIndex']}-*.log"))
faults=[]
for line in (r/'first-workspace/fault-events.log').read_text().splitlines():
 row=dict(re.findall(r'(\w+)=([^\s]+)',line)) if line.startswith('fault-crash ') else {}
 if int(row.get('machine','-1'))==old['machineIndex'] and int(row.get('monotonicMs','0'))>=request_marker: faults.append(row)
assert len(faults)==1, 'missing exact provider-owned source crash timestamp'
fault_marker=int(faults[0]['monotonicMs'])
closed=[]
for path in (r/'cousin-native-logs').glob('second-*.log'):
 lines=path.read_text().splitlines()
 identities=[dict(re.findall(r'(\w+)=([^\s]+)',line)) for line in lines if line.startswith('cousin_session_probe.ready ')]
 if len(identities)!=1 or identities[0].get('uuid')!=old['peerContainerUUID']: continue
 for line in lines:
  if line.startswith('cousin_session_probe.closed '):
   row=dict(re.findall(r'(\w+)=([^\s]+)',line))
   if row.get('session')==old['sessionUUID'] and request_marker<=int(row['monotonicMs'])<old['sessionActivatedMonotonicMs']+30000: closed.append(row)
assert closed, 'selected destination did not close the crashed source session before normal turnover'
ready=[]; ready_uuids=set(); active=set(); resource_ok=set(); expected_deployment=str((int(endpoints['sourceApplicationID'])<<48)|1); expected_memories=set()
report_path=r/'cousin-lifecycle-source-restarted-app.log'
if not report_path.exists(): report_path=r/'source-application.log'
for line in report_path.read_text().splitlines():
 m=re.search(r'containerRuntime: cores=1 memMB=(\d+) storMB=128 uuid=(\d+)',line)
 if m: expected_memories.add(m[1])
assert len(expected_memories)==1, 'current source report has inconsistent runtime resources'
expected_memory=expected_memories.pop()
for x in logs:
 lines=x.read_text().splitlines(); file_uuid=x.stem.split('-')[-1]
 for line in lines:
  if line.startswith('cousin_session_probe.round '):
   row=dict(re.findall(r'(\w+)=([^\s]+)',line))
   if int(row.get('monotonicMs','0'))>recovered_marker: active.add(f'{int(file_uuid):032x}')
  if line.startswith('cousin_session_probe.ready '):
   row=dict(re.findall(r'(\w+)=([^\s]+)',line))
   if int(row.get('monotonicMs','0'))>fault_marker: ready_uuids.add(f'{int(file_uuid):032x}')
   if row.get('uuid')==expectedUUID and row.get('source')=='1' and row.get('deployment')==expected_deployment and int(row.get('monotonicMs','0'))>fault_marker: ready.append(row)
  if line.startswith('cousin_session_probe.resources '):
   row=dict(re.findall(r'(\w+)=([^\s]+)',line))
   if row.get('uuid')==expectedUUID and row.get('accepted')=='1' and row.get('cores')=='1' and row.get('storageMB')=='64' and row.get('memoryMB')==expected_memory and int(row.get('monotonicMs','0'))>fault_marker: resource_ok.add(expectedUUID)
reported_hex={f'{x:032x}' for x in reported}
assert ready_uuids <= reported_hex, 'post-crash source ready identity missing from current report'
assert active <= reported_hex, 'active source session owner missing from current report'
assert expectedUUID in active and ready, 'qualified source lacks current post-crash native identity'
assert ready[-1].get('memoryMB')==expected_memory or expectedUUID in resource_ok, 'current source native resource does not match report'
(r/'cousin-lifecycle-source-restarted.json').write_text(json.dumps({'old':old,'oldSessionClosed':closed,
 'providerFaultMonotonicMs':fault_marker,'newSessionUUID':q['sessionUUID'],'replacementPID':n[0]['pid']},indent=2)+'\n')
PY_SOURCE_RECOVER
    COUSIN_OFFLINE=0
    cp "$ROOT/cousin-native-session-qualified.json" "$ROOT/cousin-native-session-after-scale.json" || return
  fi
  local destination_index
  destination_index=$(python3 - "$ROOT" <<'PY_PEER'
import json,pathlib,re,sys,time
root=pathlib.Path(sys.argv[1]); q=json.loads((root/'cousin-native-session-qualified.json').read_text())
peers={int(row['peer'],16) for row in q['rounds']}; assert len(peers)==1
peer=peers.pop()
matches=[p.name.split('-')[1] for p in (root/'cousin-native-logs').glob(f'second-*-{peer}.log')]
assert len(matches)==1
index=int(matches[0]); now=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000
source=(root/'cousin-native-logs'/(q['sourceLog']+'.log')).read_text()
records=lambda kind: [dict(re.findall(r'(\w+)=([^\s]+)',line)) for line in source.splitlines()
                      if line.startswith('cousin_session_probe.'+kind+' ')]
activation=[row for row in records('activate') if row['session']==q['sessionUUID']]
assert len(activation)==1
activated=int(activation[0]['monotonicMs'])
assert now-int(q['rounds'][-1]['monotonicMs'])<3000, 'selected session is no longer observably live'
assert now-activated<25000, 'selected session is too near its normal 30s turnover'
assert not any(row['session']==q['sessionUUID'] for row in records('closed'))
manifest=json.loads((root/'second-workspace/test-cluster-manifest.json').read_text())
nodes=[node for node in manifest['nodes'] if node['index']==index]; assert len(nodes)==1
(root/'cousin-lifecycle-restart-selected.json').write_text(json.dumps({'machineIndex':index,
    'machinePID':nodes[0]['pid'],'peerContainerUUID':str(peer),'sessionUUID':q['sessionUUID'],
    'sessionActivatedMonotonicMs':activated,'selectedMonotonicMs':now},indent=2)+'\n')
print(index)
PY_PEER
  ) || return
  # This is an explicit destructive fault request to the disposable provider,
  # never a direct machine action or a repair by the harness.
  COUSIN_OFFLINE=0
  prodigy_dev_cousin_mark_time "$ROOT/cousin-lifecycle-restart" || return
  m cousin-lifecycle-restart 45 "$ROOT/cousin-lifecycle-restart.log" faultTestCluster "$SECOND" crash "$destination_index" 12000 0 0 0 || return
  ok "$ROOT/cousin-lifecycle-restart.log" faultTestCluster || return 1
  wait_ready "$SECOND" cousin-lifecycle-after-restart || return
  # Poll the ordinary Mothership report until the destination fleet is healthy
  # and complete. A stateful plan UUID may either be retained by Neuron's cold
  # restart or replaced by Brain reconciliation; the native proof below binds
  # every retained selected UUID to a fresh post-crash ready event.
  local restart_report_deadline=$(( SECONDS + 45 )) restarted_app=0
  while (( SECONDS < restart_report_deadline )); do
    m cousin-lifecycle-restarted-app 15 "$ROOT/cousin-lifecycle-restarted-app.log" applicationReport "$SECOND" "$destination_name" || return
    if python3 - "$ROOT" "$ROOT/cousin-lifecycle-restarted-app.log" "$destination_groups" "$destination_containers" "$destination_memory" <<'PY_RESTART_REPORT'
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]); data=pathlib.Path(sys.argv[2]).read_text()
for field,expected in [('nShardGroups',sys.argv[3]),('nHealthy',sys.argv[4]),('nDeployed',sys.argv[4])]:
    assert re.findall(r'\b'+field+r':\s*(\d+)\b',data)==[expected], field
resources=re.findall(r'containerRuntime: cores=(\d+) memMB=(\d+) storMB=(\d+) uuid=(\d+)',data)
assert len(resources)==int(sys.argv[4]) and all(row[:3]==('1',sys.argv[5],'128') for row in resources), 'destination runtime target changed after restart'
runtime=[int(row[3]) for row in resources]
assert len(runtime)==int(sys.argv[4]) and len(set(runtime))==len(runtime), 'current runtime UUID count'
(root/'cousin-lifecycle-restarted-report.json').write_text(json.dumps({'runtimeContainerUUIDs':[str(uuid) for uuid in runtime], 'memoryMB':sys.argv[5]},indent=2)+'\n')
PY_RESTART_REPORT
    then restarted_app=1; break; fi
    sleep .25
  done
  [[ $restarted_app == 1 ]] || return 1
  prodigy_dev_cousin_mark_time "$ROOT/cousin-lifecycle-restarted" || return
  COUSIN_OFFLINE=1
  python3 "$TEST_DIR/prodigy_dev_cousin_session_observe.py" "$ROOT" qualify cousin-lifecycle-restarted "$destination_groups" "$source_groups" || return
  python3 - "$ROOT" <<'PY_RESTART' || return
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]); before=json.loads((root/'cousin-native-session-after-scale.json').read_text())
after=json.loads((root/'cousin-native-session-qualified.json').read_text())
selected=json.loads((root/'cousin-lifecycle-restart-selected.json').read_text())
manifest=json.loads((root/'second-workspace/test-cluster-manifest.json').read_text())
nodes=[node for node in manifest['nodes'] if node['index']==selected['machineIndex']]; assert len(nodes)==1
assert nodes[0]['pid']!=selected['machinePID'], 'selected machine process was not replaced'
data=(root/'cousin-native-logs'/(before['sourceLog']+'.log')).read_text()
closed=[dict(re.findall(r'(\w+)=([^\s]+)',line)) for line in data.splitlines()
        if line.startswith('cousin_session_probe.closed ')]
restart_marker=int((root/'cousin-lifecycle-restart-monotonic-ms').read_text())
faults=[]
for line in (root/'second-workspace/fault-events.log').read_text().splitlines():
    if not line.startswith('fault-crash '): continue
    row=dict(re.findall(r'(\w+)=([^\s]+)',line))
    if int(row.get('machine','-1'))==selected['machineIndex'] and int(row.get('monotonicMs','0'))>=restart_marker:
        faults.append(row)
assert len(faults)==1, 'missing exact provider-owned destination crash timestamp'
fault_marker=int(faults[0]['monotonicMs'])
assert any(row['session']==before['sessionUUID'] and restart_marker<=int(row['monotonicMs'])<
           selected['sessionActivatedMonotonicMs']+30000 for row in closed), 'selected session did not close before normal turnover'
assert before['sessionUUID']!=after['sessionUUID'], 'restart must establish a fresh authenticated session'
assert int(after['request']['monotonicMs'])>int((root/'cousin-lifecycle-restarted-monotonic-ms').read_text())
report=json.loads((root/'cousin-lifecycle-restarted-report.json').read_text())
reported={int(uuid) for uuid in report['runtimeContainerUUIDs']}
assert after['rounds'] and {int(row['peer'],16) for row in after['rounds']} <= reported, 'recovered payload peer is absent from the current report'
ready=[]
endpoints=json.loads((root/'cousin-endpoints.json').read_text())
expected_deployment=str((int(endpoints['destinationApplicationID'])<<48)|1)
for path in (root/'cousin-native-logs').glob(f"second-{selected['machineIndex']}-*.log"):
    for line in path.read_text().splitlines():
        if not line.startswith('cousin_session_probe.ready '): continue
        row=dict(re.findall(r'(\w+)=([^\s]+)',line))
        if int(row['monotonicMs']) > fault_marker and int(row['uuid'],16) in reported:
            assert row.get('source')=='0' and row.get('deployment')==expected_deployment, 'replacement destination identity mismatch'
            assert row.get('cores')=='1' and row.get('memoryMB')==report['memoryMB'] and row.get('storageMB')=='64', 'replacement destination native resource mismatch'
            ready.append(dict(row,log=path.name))
assert ready, 'selected machine has no new ready reported container after restart'
selected_uuid=int(selected['peerContainerUUID'])
selected_retained=selected_uuid in reported
if selected_retained:
    assert any(int(row['uuid'],16)==selected_uuid for row in ready), 'retained selected UUID lacks fresh post-crash readiness'
(root/'cousin-lifecycle-restarted.json').write_text(json.dumps({'selectedMachine':selected,
    'replacementMachinePID':nodes[0]['pid'],'providerFaultMonotonicMs':fault_marker,
    'currentPeerContainerUUID':after['rounds'][0]['peer'],
    'selectedIdentityRetained':selected_retained,'postRestartReadyContainers':ready,'oldSessionUUID':before['sessionUUID'],
    'newSessionUUID':after['sessionUUID'],'postRecoveryPayloadSpanMs':after['renewalObservedMs'],
    'renewalGenerations':after['renewalGenerations']},indent=2)+'\n')
PY_RESTART
  echo 'PASS: ordinary local COUSIN scaling during pair partition and fresh payload after restart'
}
