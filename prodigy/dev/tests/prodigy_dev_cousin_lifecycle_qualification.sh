#!/usr/bin/env bash
# Sourced inside the existing Mothership-client qualification. Probe logs and
# fault receipts are observations; only Mothership may change the test cluster.
prodigy_dev_qualify_cousin_lifecycle() {
  local profile=$1 destination_name=$2 expected_groups=1 expected_containers=3
  [[ "$profile" != horizontal ]] || { expected_groups=2; expected_containers=6; }
  cp "$ROOT/cousin-native-session-qualified.json" "$ROOT/cousin-native-session-before-lifecycle.json" || return
  wait "$PAIR_PARTITION_PID" || return
  PAIR_PARTITION_PID=0
  ok "$ROOT/cousin-lifecycle-partition.log" testClusterPairControl || return 1
  python3 "$TEST_DIR/prodigy_dev_cousin_session_observe.py" "$ROOT" snapshot || return
  python3 - "$ROOT" "$profile" <<'PY_LIFECYCLE' || return
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]); profile=sys.argv[2]
fault=re.search(r'PAIR_CONTROL_FAULT operationID=\w+ clock=CLOCK_BOOTTIME delayMs=(\d+) durationMs=(\d+) beginNs=(\d+) endNs=(\d+)',
                (root/'cousin-lifecycle-partition.log').read_text())
assert fault, 'missing provider-owned pair partition interval'
delay,duration,begin,end=map(int,fault.groups())
assert delay==15000 and duration==60000 and end-begin>=duration*1_000_000
events=[]; samples=[]; metric_times=[]
for path in (root/'cousin-native-logs').glob('second-*.log'):
    for line in path.read_text().splitlines():
        if not line.startswith('cousin_session_probe.'): continue
        row=dict(re.findall(r'(\w+)=([^\s]+)',line))
        if line.startswith('cousin_session_probe.scaleMetric ') and 'monotonicMs' in row:
            metric_times.append(int(row['monotonicMs'])*1_000_000)
        if 'monotonicMs' not in row or not begin<=int(row['monotonicMs'])*1_000_000<=end: continue
        if line.startswith('cousin_session_probe.scaleMetric '): samples.append(row)
        if profile=='horizontal' and line.startswith('cousin_session_probe.ready ') and row.get('group')=='1':
            events.append(dict(row,log=path.name))
        if profile=='vertical' and line.startswith('cousin_session_probe.resources ') and row.get('memoryMB')=='384':
            assert row.get('cores')=='1' and row.get('storageMB')=='64' and row.get('downscale')=='0' and row.get('accepted')=='1'
            events.append(dict(row,log=path.name))
assert samples, 'no ordinary application scale metrics during pair partition'
assert begin<=min(metric_times)<=end, 'scale metric started before pair partition'
assert len({row['uuid'] for row in events})==3, 'all three destination replicas must progress during pair partition'
receipt={'profile':profile,'clock':'CLOCK_BOOTTIME','faultBeginNs':begin,'faultEndNs':end,
         'scaleEvents':events,'metricSamples':len(samples),'localScaleProgressDuringPeerPartition':True}
(root/'cousin-lifecycle-scaled.json').write_text(json.dumps(receipt,indent=2)+'\n')
PY_LIFECYCLE
  # Resume only read-only Mothership reporting after the offline interval to
  # verify that the ordinary scaler reached its complete local healthy target.
  COUSIN_OFFLINE=0
  m cousin-lifecycle-app 15 "$ROOT/cousin-lifecycle-app.log" applicationReport "$SECOND" "$destination_name" || return
  python3 - "$ROOT/cousin-lifecycle-app.log" "$expected_groups" "$expected_containers" "$profile" <<'PY_HEALTH' || return
import pathlib,re,sys
data=pathlib.Path(sys.argv[1]).read_text()
for field,expected in [('nShardGroups',sys.argv[2]),('nHealthy',sys.argv[3]),('nDeployed',sys.argv[3]),('nCrashes','0')]:
    assert re.findall(r'\b'+field+r':\s*(\d+)\b',data)==[expected], field
resources=re.findall(r'containerRuntime: cores=(\d+) memMB=(\d+) storMB=(\d+)',data)
assert resources==[('1','384' if sys.argv[4]=='vertical' else '256','128')]*int(sys.argv[3])
PY_HEALTH
  prodigy_dev_cousin_mark_time "$ROOT/cousin-lifecycle-recovered" || return
  COUSIN_OFFLINE=1
  python3 "$TEST_DIR/prodigy_dev_cousin_session_observe.py" "$ROOT" qualify cousin-lifecycle-recovered "$expected_groups" || return
  cp "$ROOT/cousin-native-session-qualified.json" "$ROOT/cousin-native-session-after-scale.json" || return
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
  # A post-restart report is not evidence while it can still name the killed
  # destination container. Poll the ordinary Mothership report until the
  # selected UUID is gone and its replacement fleet is complete.
  local restart_report_deadline=$(( SECONDS + 45 )) restarted_app=0
  while (( SECONDS < restart_report_deadline )); do
    m cousin-lifecycle-restarted-app 15 "$ROOT/cousin-lifecycle-restarted-app.log" applicationReport "$SECOND" "$destination_name" || return
    if python3 - "$ROOT" "$ROOT/cousin-lifecycle-restarted-app.log" "$expected_groups" "$expected_containers" <<'PY_RESTART_REPORT'
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]); data=pathlib.Path(sys.argv[2]).read_text()
selected=json.loads((root/'cousin-lifecycle-restart-selected.json').read_text())
for field,expected in [('nShardGroups',sys.argv[3]),('nHealthy',sys.argv[4]),('nDeployed',sys.argv[4])]:
    assert re.findall(r'\b'+field+r':\s*(\d+)\b',data)==[expected], field
runtime=[int(uuid) for uuid in re.findall(r'containerRuntime: cores=\d+ memMB=\d+ storMB=\d+ uuid=(\d+)',data)]
assert len(runtime)==int(sys.argv[4]) and len(set(runtime))==len(runtime), 'current runtime UUID count'
assert int(selected['peerContainerUUID']) not in runtime, 'stale selected container remains in application report'
(root/'cousin-lifecycle-restarted-report.json').write_text(json.dumps({'runtimeContainerUUIDs':[str(uuid) for uuid in runtime]},indent=2)+'\n')
PY_RESTART_REPORT
    then restarted_app=1; break; fi
    sleep .25
  done
  [[ $restarted_app == 1 ]] || return 1
  prodigy_dev_cousin_mark_time "$ROOT/cousin-lifecycle-restarted" || return
  COUSIN_OFFLINE=1
  python3 "$TEST_DIR/prodigy_dev_cousin_session_observe.py" "$ROOT" qualify cousin-lifecycle-restarted "$expected_groups" || return
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
assert any(row['session']==before['sessionUUID'] and restart_marker<=int(row['monotonicMs'])<
           selected['sessionActivatedMonotonicMs']+30000 for row in closed), 'selected session did not close before normal turnover'
assert before['sessionUUID']!=after['sessionUUID'], 'restart must establish a fresh authenticated session'
assert int(after['request']['monotonicMs'])>int((root/'cousin-lifecycle-restarted-monotonic-ms').read_text())
report=json.loads((root/'cousin-lifecycle-restarted-report.json').read_text())
reported={int(uuid) for uuid in report['runtimeContainerUUIDs']}
assert int(selected['peerContainerUUID']) not in reported, 'stale selected UUID was accepted after restart'
ready=[]
for path in (root/'cousin-native-logs').glob(f"second-{selected['machineIndex']}-*.log"):
    for line in path.read_text().splitlines():
        if not line.startswith('cousin_session_probe.ready '): continue
        row=dict(re.findall(r'(\w+)=([^\s]+)',line))
        if int(row['monotonicMs']) > restart_marker and int(row['uuid'],16) in reported:
            ready.append(dict(row,log=path.name))
assert ready, 'selected machine has no new ready reported container after restart'
(root/'cousin-lifecycle-restarted.json').write_text(json.dumps({'selectedMachine':selected,
    'replacementMachinePID':nodes[0]['pid'],'currentPeerContainerUUID':after['rounds'][0]['peer'],
    'postRestartReadyContainers':ready,'oldSessionUUID':before['sessionUUID'],
    'newSessionUUID':after['sessionUUID'],'postRecoveryPayloadSpanMs':after['renewalObservedMs'],
    'renewalGenerations':after['renewalGenerations']},indent=2)+'\n')
PY_RESTART
  echo 'PASS: ordinary local COUSIN scaling during pair partition and fresh payload after restart'
}
