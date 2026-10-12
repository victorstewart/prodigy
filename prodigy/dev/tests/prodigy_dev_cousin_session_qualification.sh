#!/usr/bin/env bash
# Sourced by the two-cluster enrollment harness after authenticated pair setup.
# All cluster/runtime mutations remain ordinary Mothership operations.
prodigy_dev_cousin_mark_time() {
  python3 - "$1" <<'PY_CLOCK'
import pathlib,sys,time
prefix=sys.argv[1]
pathlib.Path(prefix+'-ms').write_text(str(time.time_ns()//1_000_000)+'\n')
pathlib.Path(prefix+'-monotonic-ms').write_text(str(time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1_000_000)+'\n')
PY_CLOCK
}

prodigy_dev_qualify_cousin_session() {
  local probe=${PRODIGY_DEV_COUSIN_PROBE_BIN:?} side cluster app name
  local route_id=${PRODIGY_DEV_COUSIN_ROUTE_ID:-$OPERATION}
  local lifecycle=${PRODIGY_DEV_COUSIN_LIFECYCLE:-}
  case "$lifecycle" in ''|horizontal|vertical|source-horizontal-destination-vertical|source-vertical-destination-horizontal) ;; *) echo 'FAIL: unsupported COUSIN lifecycle profile' >&2; return 1 ;; esac
  [[ -x "$probe" ]] || return 1
  local source_name="CousinSource-${route_id#0x}" destination_name="CousinDestination-${route_id#0x}"
  # Reuse the session preparation from another Mothership-client scenario
  # without coupling it to the enrollment harness' evidence file names.
  local first_create_log=${PRODIGY_DEV_COUSIN_FIRST_CREATE_LOG:-$ROOT/create-first.log}
  local second_create_log=${PRODIGY_DEV_COUSIN_SECOND_CREATE_LOG:-$ROOT/create-second.log}
  local first_report_log=${PRODIGY_DEV_COUSIN_FIRST_REPORT_LOG:-$ROOT/first-cluster-report.log}
  local source_permission destination_permission source_cluster destination_cluster source_prefix destination_prefix
  read -r source_permission destination_permission source_prefix destination_prefix < <(python3 - "$route_id" <<'PY'
import sys
v=int(sys.argv[1],16); part=(v>>32)&0xffffffff
def canonical(n): return n.to_bytes(max(1,(n.bit_length()+7)//8),'big').hex()
print(canonical(v^0x501),canonical(v^0x502),f'fdc5:{part>>16:x}:{part&65535:x}:1::/120',f'fdc5:{part>>16:x}:{part&65535:x}:2::/120')
PY
)
  source_cluster=$(rg -m1 -o 'clusterUUID=0x[0-9a-f]+' "$first_create_log" | cut -d= -f2)
  destination_cluster=$(rg -m1 -o 'clusterUUID=0x[0-9a-f]+' "$second_create_log" | cut -d= -f2)
  [[ -n "$source_cluster" && -n "$destination_cluster" && "$source_cluster" != "$destination_cluster" ]] || return 1
  local source_app destination_app destination_prefix_uuid
  # Reserve a destination-only dummy so asymmetric application IDs are exercised.
  m cousin-reserve-dummy 30 "$ROOT/cousin-reserve-dummy.log" reserveApplicationID "$SECOND" \
    "$(jq -nc --arg name "CousinDummy-${route_id#0x}" '{applicationName:$name,createIfMissing:true}')" || return
  for side in source destination; do
    if [[ $side == source ]]; then cluster=$FIRST; name=$source_name; else cluster=$SECOND; name=$destination_name; fi
    m "cousin-reserve-$side" 30 "$ROOT/cousin-reserve-$side.log" reserveApplicationID "$cluster" \
      "$(jq -nc --arg name "$name" '{applicationName:$name,createIfMissing:true}')" || return
    app=$(rg -m1 -o 'appID=[1-9][0-9]*' "$ROOT/cousin-reserve-$side.log" | cut -d= -f2)
    [[ $app =~ ^[1-9][0-9]*$ ]] || return 1
    if [[ $side == destination && $app == "$source_app" ]]; then
      destination_name+="-distinct"; name=$destination_name
      m cousin-reserve-destination-distinct 30 "$ROOT/cousin-reserve-destination.log" reserveApplicationID "$cluster" \
        "$(jq -nc --arg name "$name" '{applicationName:$name,createIfMissing:true}')" || return
      app=$(rg -m1 -o 'appID=[1-9][0-9]*' "$ROOT/cousin-reserve-destination.log" | cut -d= -f2)
      [[ $app =~ ^[1-9][0-9]*$ && $app != "$source_app" ]] || return 1
    fi
    m "cousin-service-$side" 30 "$ROOT/cousin-service-$side.log" reserveServiceID "$cluster" \
      "$(jq -nc --argjson app "$app" '{applicationID:$app,serviceName:"cousin",requestedServiceSlot:3,kind:"stateful",createIfMissing:true}')" || return
    local prefix
    if [[ $side == source ]]; then prefix=$source_prefix; source_app=$app
    else prefix=$destination_prefix; destination_app=$app; fi
    if [[ $side == source ]]; then
      python3 - "$first_report_log" "$source_prefix" >"$ROOT/cousin-source-prefixes.tsv" <<'PY_PREFIX'
import ipaddress,pathlib,re,sys
machines=re.findall(r'(?m)^\s*identity uuid=(0x[0-9a-f]+) ',pathlib.Path(sys.argv[1]).read_text())
assert len(machines)==3 and len(set(machines))==3
base=int(ipaddress.IPv6Network(sys.argv[2]).network_address)
for index,machine in enumerate(machines):
    print(index+1,machine,str(ipaddress.IPv6Network((base+index*256,120))),sep='\t')
PY_PREFIX
      local prefix_index machine_uuid
      while IFS=$'\t' read -r prefix_index machine_uuid prefix; do
        m "cousin-prefix-source-$prefix_index" 30 "$ROOT/cousin-prefix-source-$prefix_index.log" registerRoutableSubnet "$cluster" \
          "$(jq -nc --arg name "cousin-source-$prefix_index-${route_id#0x}" --arg prefix "$prefix" --arg machine "$machine_uuid" \
          '{name:$name,kind:"BGP",prefix:$prefix,usage:"whiteholes",ingressScope:"singleMachine",machineUUID:$machine}')" || return
      done <"$ROOT/cousin-source-prefixes.tsv"
    else
      m cousin-prefix-destination 30 "$ROOT/cousin-prefix-destination.log" registerRoutableSubnet "$cluster" \
        "$(jq -nc --arg name "cousin-destination-${route_id#0x}" --arg prefix "$prefix" \
        '{name:$name,kind:"BGP",prefix:$prefix,usage:"wormholes",ingressScope:"switchboardFleet"}')" || return
      destination_prefix_uuid=$(rg -m1 -o 'uuid=(0x)?[0-9a-fA-F]+' "$ROOT/cousin-prefix-destination.log" | cut -d= -f2)
      [[ $destination_prefix_uuid =~ ^(0x)?[0-9a-fA-F]{1,32}$ ]] || return 1
    fi
  done
  [[ $source_app != "$destination_app" ]] || return 1
  local artifact="$ROOT/cousin-artifact" blob="$ROOT/cousin.container.zst"
  mkdir -p "$artifact"
  printf '%s\n' "$source_permission" >"$artifact/cousin-probe-config"
  cat >"$artifact/Cousin.DiscombobuFile" <<PLAN
FROM scratch for $ARCH
COPY {bin} ./$(basename "$probe") /root/cousin_session_probe
COPY {config} ./cousin-probe-config /cousin-probe-config
SURVIVE /root/cousin_session_probe
SURVIVE /cousin-probe-config
PLAN
  prodigy_dev_write_common_prodigy_assets "$artifact/Cousin.DiscombobuFile"
  if [[ -n "$lifecycle" ]]; then echo "ENV COUSIN_PROBE_LIFECYCLE=$([[ $lifecycle == source-* ]] && echo both || echo 1)" >>"$artifact/Cousin.DiscombobuFile"; fi
  if [[ ${PRODIGY_DEV_COUSIN_GRAPH:-0} == 1 ]]; then echo 'ENV COUSIN_PROBE_GRAPH=1' >>"$artifact/Cousin.DiscombobuFile"; fi
  echo 'EXECUTE ["/root/cousin_session_probe"]' >>"$artifact/Cousin.DiscombobuFile"
  prodigy_dev_run_discombobulator_build "$artifact" "$artifact/Cousin.DiscombobuFile" "$blob" \
    "bin=$(dirname "$probe")" "config=$artifact" "ebpf=$(dirname "$PRODIGY_BIN")" || return
  python3 - "$ROOT" "$ARCH" "$source_app" "$destination_app" "$source_name" "$destination_name" "$destination_prefix_uuid" "$lifecycle" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); arch=sys.argv[2]
for side,app,name in [('source',int(sys.argv[3]),sys.argv[5]),('destination',int(sys.argv[4]),sys.argv[6])]:
    roles={name:(app<<48)|(slot<<40)|1023 for slot,name in enumerate(['clientPrefix','siblingPrefix','cousinPrefix','seedingPrefix','shardingPrefix'],1)}
    roles.update(allowUpdateInPlace=True,seedingAlways=False,neverShard=False,allMasters=True)
    plan={'config':{'type':'ApplicationType::stateful','applicationID':app,'versionID':1,'architecture':arch,
        'filesystemMB':64,'storageMB':64,'memoryMB':256,'isolateCPUs':False,'nLogicalCores':1,'msTilHealthy':2000,'sTilHealthcheck':3,'sTilKillable':30},
        'apiCredentials':{'applicationID':app,'requiredCredentialNames':[]},'useHostNetworkNamespace':False,
        'minimumSubscriberCapacity':1024,'isStateful':True,'stateful':roles,'moveConstructively':False,'requiresDatacenterUniqueTag':False}
    profile=sys.argv[8]
    horizontal=(side=='destination' and profile=='horizontal') or (side=='source' and profile=='source-horizontal-destination-vertical') or (side=='destination' and profile=='source-vertical-destination-horizontal')
    vertical=(side=='destination' and profile=='vertical') or (side=='destination' and profile=='source-horizontal-destination-vertical') or (side=='source' and profile=='source-vertical-destination-horizontal')
    scaler={'name':'cousin.probe.scale','percentile':90,'lookbackSeconds':3,'threshold':0.000001,'direction':'upscale'}
    if horizontal: plan['horizontalScalers']=[dict(scaler,lifetime='ApplicationLifetime::base',minValue=3,maxValue=6)]
    elif vertical: plan['verticalScalers']=[dict(scaler,resource='ScalingDimension::memory',increment=128,minValue=256,maxValue=384)]
    if side=='source': plan['whiteholes']=[{'transport':'tcp','family':'ipv6','source':'registeredRoutablePrefix'}]
    else:
        plan['advertisements']=[{'service':'${service:'+name+'/cousin.group0}','startAt':'ContainerState::scheduled','stopAt':'ContainerState::destroying','port':9443}]
        plan['wormholes']=[{'name':'cousin','source':'registeredRoutablePrefix','routablePrefixUUID':sys.argv[7],
                           'externalPort':9443,'containerPort':9443,'layer4':'TCP','isQuic':False}]
    (root/f'cousin-{side}-plan.json').write_text(json.dumps(plan))
PY
  jq -nc --arg sourceName "$source_name" --arg destinationName "$destination_name" --argjson sourceApplicationID "$source_app" --argjson destinationApplicationID "$destination_app" \
    '{sourceName:$sourceName,destinationName:$destinationName,sourceApplicationID:$sourceApplicationID,destinationApplicationID:$destinationApplicationID}' >"$ROOT/cousin-endpoints.json"
  if [[ $lifecycle == source-* ]]; then
    for side in horizontal vertical; do
      local rejected_plan
      rejected_plan=$(python3 - "$ROOT/cousin-source-plan.json" "$side" <<'PY_DOWNSCALE'
import json,pathlib,sys
p=json.loads(pathlib.Path(sys.argv[1]).read_text());p.pop('horizontalScalers',None);p.pop('verticalScalers',None)
metric={'name':'cousin.probe.scale','percentile':90,'lookbackSeconds':3,'threshold':0.000001,'direction':'downscale'}
if sys.argv[2]=='horizontal': p['horizontalScalers']=[dict(metric,lifetime='ApplicationLifetime::base',minValue=3,maxValue=6)]
else: p['verticalScalers']=[dict(metric,resource='ScalingDimension::memory',increment=128,minValue=256,maxValue=384)]
print(json.dumps(p))
PY_DOWNSCALE
      ) || return
      if m "cousin-reject-$side-downscale" 15 "$ROOT/cousin-reject-$side-downscale.log" deploy "$FIRST" "$rejected_plan" "$blob"; then
        echo "FAIL: unsupported stateful $side downscale was accepted" >&2; return 1
      fi
      rg -q "stateful deployments cannot set ${side}Scalers.direction=downscale" "$ROOT/cousin-reject-$side-downscale.log" || return 1
    done
  fi
  if m cousin-reject-unprotected-stateful 15 "$ROOT/cousin-reject-unprotected-stateful.log" deploy "$SECOND" \
      "$(jq '.advertisements=[]' "$ROOT/cousin-destination-plan.json")" "$blob"; then
    echo 'FAIL: unprotected stateful Wormhole was accepted' >&2; return 1
  fi
  rg -q 'stateful wormholes require an explicit protected COUSIN TCP advertisement' \
    "$ROOT/cousin-reject-unprotected-stateful.log" || return 1
  for side in destination source; do
    if [[ $side == source ]]; then cluster=$FIRST; name=$source_name; app=$source_app
    else cluster=$SECOND; name=$destination_name; app=$destination_app; fi
    m "cousin-deploy-$side" 90 "$ROOT/cousin-deploy-$side.log" deploy "$cluster" "$(cat "$ROOT/cousin-$side-plan.json")" "$blob" || return
    local deadline=$(( $(date +%s%3N) + 90000 )) ready_app=0
    while (( $(date +%s%3N) < deadline )); do
      if m "cousin-app-$side" 8 "$ROOT/cousin-$side-app.log" applicationReport "$cluster" "$name" &&
          python3 - "$ROOT/cousin-$side-app.log" <<'PY'
import pathlib,re,sys
s=pathlib.Path(sys.argv[1]).read_text()
assert re.findall(r'(?m)^\s*nHealthy:\s*(\d+)\s*$',s)==['3']
assert re.findall(r'(?m)^\s*nDeployed:\s*(\d+)\s*$',s)==['3']
assert re.findall(r'(?m)^\s*nCrashes:\s*(\d+)\s*$',s)==['0']
PY
      then ready_app=1; break; fi
      sleep .25
    done
    [[ $ready_app == 1 ]] || return 1
    m "cousin-identity-$side" 15 "$ROOT/cousin-$side-identity.log" deploymentIdentity "$cluster" "$(( (app << 48) | 1 ))" || return
    m "cousin-leases-$side" 15 "$ROOT/cousin-$side-leases.log" pullRoutableResourceLeases "$cluster" || return
  done
  python3 - "$ROOT" "$source_permission" "$destination_permission" "$source_cluster" "$destination_cluster" "$source_app" "$destination_app" <<'PY'
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]); pair=json.loads((root/'pair-control-initial.json').read_text())['pairUUIDs'][0]
for side,index,peer in [('source',0,1),('destination',1,0)]:
    ids=list(map(int,sys.argv[6:8])); app=ids[index]
    identity=dict(re.findall(r'(\w+)=([^\s]+)',(root/f'cousin-{side}-identity.log').read_text().split('deploymentIdentity success=1')[-1]))
    permission={'permissionUUID':'0x'+sys.argv[2+index],'pairUUID':'0x'+pair,
      'logicalWorkloadUUID':'0x'+sys.argv[2],'logicalServiceUUID':'0x'+sys.argv[3],
      'localClusterUUID':sys.argv[4+index],'peerClusterUUID':sys.argv[4+peer],'localHalf':side,
      'localApplicationID':app,'peerApplicationID':ids[peer],
      'localCousinServicePrefix':(app<<48)|(3<<40)|1023,'peerCousinServicePrefix':(ids[peer]<<48)|(3<<40)|1023,
      'slots':[0],'localDeploymentID':(app<<48)|1,'canonicalPlanSHA256':identity['planSHA256'],
      'artifactSHA256':identity['artifactSHA256'],'artifactBytes':int(identity['artifactBytes'])}
    (root/f'cousin-{side}-permission.json').write_text(json.dumps(permission))
PY
  for side in destination source; do
    if [[ $side == source ]]; then cluster=$FIRST; else cluster=$SECOND; fi
    m "cousin-permission-$side" 45 "$ROOT/cousin-$side-permission.log" cousinPermission "$cluster" install \
      "$(cat "$ROOT/cousin-$side-permission.json")" || return
    rg -q 'cousinPermission success=1 .*qualified=1' "$ROOT/cousin-$side-permission.log" || return 1
  done
  local deadline=$(( $(date +%s%3N) + 15000 )) discovered=0
  while (( $(date +%s%3N) < deadline )); do
    if m cousin-discover 8 "$ROOT/cousin-discovery.log" cousinPermission "$FIRST" discover "0x$source_permission" 0 &&
      rg -q 'cousinCounterpart ' "$ROOT/cousin-discovery.log"; then discovered=1; break; fi
    sleep .25
  done
  [[ $discovered == 1 ]] || return 1
  python3 - "$ROOT" "$source_cluster" "$destination_cluster" "$source_app" "$destination_app" "$source_permission" "$destination_permission" "${PRODIGY_DEV_COUSIN_EXISTING_ROUTES:-}" "$lifecycle" <<'PY_TRANSIT'
import ipaddress,json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]); src=int(sys.argv[4]); dst=int(sys.argv[5])
leases=[]
for line in (root/'cousin-source-leases.log').read_text().splitlines():
    d=dict(re.findall(r'(\w+)=([^\s]+)',line))
    if d.get('kind')=='whiteholeAddressPort' and int(d.get('app','0'))==src: leases.append(d)
assert leases, 'source Whitehole lease missing'
# Port allocation may reuse an existing Whitehole IP. Each graph pair owns its
# own external /128 route, so select distinct existing addresses across pairs;
# this is a choice among Brain-issued leases, never a runtime allocation.
used=set()
if sys.argv[8]:
    for path in pathlib.Path(sys.argv[8]).glob('*/cousin-service-transit.json'):
        prior=json.loads(path.read_text())
        if int(prior['sourceClusterUUID'],16)==int(sys.argv[2],16): used.add(prior['sourceWhiteholeIPv6'])
role=None
if sys.argv[9].startswith('source-'):
 report=pathlib.Path(__import__('os').environ.get('PRODIGY_DEV_COUSIN_FIRST_REPORT_LOG',root/'first-cluster-report.log')).read_text(); masters=[]; machines=[]
 for block in re.findall(r'(?ms)^\s*Machine:.*?(?=^\s*Machine:|\Z)',report):
  ident=re.search(r'identity uuid=(0x[0-9a-f]+)',block)
  assert ident, 'source machine identity is missing'
  machine=int(ident.group(1),16); machines.append(machine)
  if re.search(r'\bcurrentMaster=1(?:\s|$)',block): masters.append(machine)
 assert len(machines)==3 and len(set(machines))==3 and len(masters)==1, 'source master identity is unproven'
 prefixes=[]
 for line in (root/'cousin-source-prefixes.tsv').read_text().splitlines():
  i,u,p=line.split('\t'); prefixes.append((int(u,16),ipaddress.IPv6Network(p)))
 assert len(prefixes)==3 and {u for u,p in prefixes}==set(machines), 'source prefix owner mapping is ambiguous'
 assert all(not p.overlaps(q) for index,(_,p) in enumerate(prefixes) for _,q in prefixes[index+1:]), 'source prefixes overlap'
 target_master=sys.argv[9]=='source-vertical-destination-horizontal'
 choices=[(u,p) for u,p in prefixes if (u==masters[0])==target_master]
 assert len(choices)==(1 if target_master else 2), 'source role prefix mapping is ambiguous'
 if not target_master: choices=choices[:1]
 target_uuid,target_prefix=choices[0]; role='master' if target_master else 'follower'
 source=next((x for x in leases if ipaddress.IPv6Address(x['address']) in target_prefix and x['address'] not in used),None)
else: source=next((lease for lease in leases if lease['address'] not in used),None)
assert source is not None, 'no distinct allocated source address for independent pair route'
line=next(x for x in (root/'cousin-discovery.log').read_text().splitlines() if x.startswith('cousinCounterpart '))
dest=dict(re.findall(r'(\w+)=([^\s]+)',line))
record={'sourceClusterUUID':sys.argv[2],'destinationClusterUUID':sys.argv[3],
    'sourceDeploymentID':(src<<48)|1,'destinationDeploymentID':(dst<<48)|1,
    'sourcePermissionUUID':'0x'+sys.argv[6],'destinationPermissionUUID':'0x'+sys.argv[7],'sourceSlot':0,
    'sourceWhiteholeIPv6':source['address'],'sourceTCPPort':int(source['sourcePort']),
    'destinationWormholeIPv6':dest['publicAddress'],'destinationTCPPort':int(dest['publicTCPPort'])}
(root/'cousin-service-transit.json').write_text(json.dumps(record))
if role:
 (root/'cousin-source-role-selection.json').write_text(json.dumps({'sourceRole':role,'sourceMachineUUID':hex(target_uuid),'sourceWhiteholeIPv6':source['address'],'sourceTCPPort':int(source['sourcePort'])})+'\n')
PY_TRANSIT
  m cousin-transit 45 "$ROOT/cousin-transit.log" testClusterPairControl "$OPERATION" service "$(cat "$ROOT/cousin-service-transit.json")" || return
  ok "$ROOT/cousin-transit.log" testClusterPairControl || return 1
  local route_uuid
  route_uuid=$(prodigy_dev_cousin_route_uuid "$route_id") || return
  prodigy_dev_write_cousin_route_intent "$ROOT/cousin-route-active.json" "$route_id" "$source_permission" "$destination_permission" "$destination_prefix_uuid" active 1 || return
  # Network profile failures are Mothership parsing/admission failures, never
  # direct map/runtime changes. Each must leave the first valid generation
  # unrecorded so the coordinator-interrupt recovery below owns it.
  for case_name in unsupported-protocol invalid-cidr invalid-mtu; do
    local rejected_intent
    rejected_intent=$(jq --arg case "$case_name" '
      if $case == "unsupported-protocol" then .transportProtocol="UDP"
      elif $case == "invalid-cidr" then .destinationCIDR=129
      else .pathMTU=1279 end' "$ROOT/cousin-route-active.json") || return
    if m "cousin-route-$case_name" 45 "$ROOT/cousin-route-$case_name.log" cousinRoute put "$OPERATION" "$rejected_intent"; then
      echo "FAIL: cousin route $case_name was accepted" >&2; return 1
    fi
    rg -q 'cousinRoute success=0' "$ROOT/cousin-route-$case_name.log" || return 1
  done
  # Test-only interruption occurs after the source durable receipt. Recovery
  # must finish the exact saved operation through the normal Mothership owner.
  if PRODIGY_MOTHERSHIP_TEST_COUSIN_ROUTE_INTERRUPT_AFTER_SOURCE=1 \
      m cousin-route-interrupt-after-source 60 "$ROOT/cousin-route-interrupt-after-source.log" \
        cousinRoute put "$OPERATION" "$(cat "$ROOT/cousin-route-active.json")"; then
    echo 'FAIL: test-only route coordinator interruption unexpectedly succeeded' >&2; return 1
  fi
  rg -q 'test-only cousin route coordinator interruption after source receipt' \
    "$ROOT/cousin-route-interrupt-after-source.log" || return 1
  m cousin-route-recover 90 "$ROOT/cousin-route-recover.log" cousinRoute recover "$route_uuid" || return
  ok "$ROOT/cousin-route-recover.log" cousinRoute || return 1
  m cousin-route-query-active 45 "$ROOT/cousin-route-query-active.log" cousinRoute query "$route_uuid" || return
  ok "$ROOT/cousin-route-query-active.log" cousinRoute || return 1
  # Exact same-generation retry is the only accepted retry form.
  m cousin-route-exact-retry 60 "$ROOT/cousin-route-exact-retry.log" cousinRoute put "$OPERATION" \
    "$(cat "$ROOT/cousin-route-active.json")" || return
  rg -q 'cousinRoute success=1 .*resumed=1' "$ROOT/cousin-route-exact-retry.log" || return 1
  [[ ${PRODIGY_DEV_COUSIN_PREPARE_ONLY:-0} == 1 ]] && return 0
  # Mothership has no persistent daemon in this harness. Seal the command owner
  # during observation, and require the successful request to start after this.
  prodigy_dev_cousin_mark_time "$ROOT/cousin-offline-start"
  COUSIN_OFFLINE=1
  python3 "$TEST_DIR/prodigy_dev_cousin_session_observe.py" "$ROOT" qualify cousin-offline-start 1 || return
  if [[ -n "$lifecycle" ]]; then
    # The initial one-group payload proof precedes this explicit fault request.
    # Local application metrics and the existing Brain scaler own the scale.
    COUSIN_OFFLINE=0
    m cousin-lifecycle-partition 100 "$ROOT/cousin-lifecycle-partition.log" \
      testClusterPairControl "$OPERATION" fault 15000 60000 &
    PAIR_PARTITION_PID=$!
    COUSIN_OFFLINE=1
    source "$TEST_DIR/prodigy_dev_cousin_lifecycle_qualification.sh"
    prodigy_dev_qualify_cousin_lifecycle "$lifecycle" "$source_name" "$destination_name" || return
  fi
  COUSIN_OFFLINE=0
  # Route operation ordering is observed before permission revocation. A
  # recovered drain cannot admit new sessions, withdrawal is terminal, and a
  # delayed stale generation remains rejected after coordinator recovery.
  prodigy_dev_write_cousin_route_intent "$ROOT/cousin-route-draining.json" "$route_id" "$source_permission" "$destination_permission" "$destination_prefix_uuid" draining 2 || return
  m cousin-route-draining 60 "$ROOT/cousin-route-draining.log" cousinRoute put "$OPERATION" \
    "$(cat "$ROOT/cousin-route-draining.json")" || return
  ok "$ROOT/cousin-route-draining.log" cousinRoute || return 1
  m cousin-route-recover-draining 90 "$ROOT/cousin-route-recover-draining.log" cousinRoute recover "$route_uuid" || return
  ok "$ROOT/cousin-route-recover-draining.log" cousinRoute || return 1
  if m cousin-route-stale-after-recover 45 "$ROOT/cousin-route-stale-after-recover.log" cousinRoute put "$OPERATION" \
      "$(cat "$ROOT/cousin-route-active.json")"; then
    echo 'FAIL: delayed stale route generation was accepted after recovery' >&2; return 1
  fi
  rg -q 'cousinRoute success=0' "$ROOT/cousin-route-stale-after-recover.log" || return 1
  prodigy_dev_write_cousin_route_intent "$ROOT/cousin-route-withdrawn.json" "$route_id" "$source_permission" "$destination_permission" "$destination_prefix_uuid" withdrawn 3 || return
  prodigy_dev_cousin_mark_time "$ROOT/cousin-withdrawal-request"
  m cousin-route-withdrawn 60 "$ROOT/cousin-route-withdrawn.log" cousinRoute put "$OPERATION" \
    "$(cat "$ROOT/cousin-route-withdrawn.json")" || return
  ok "$ROOT/cousin-route-withdrawn.log" cousinRoute || return 1
  m cousin-route-query-withdrawn 45 "$ROOT/cousin-route-query-withdrawn.log" cousinRoute query "$route_uuid" || return
  ok "$ROOT/cousin-route-query-withdrawn.log" cousinRoute || return 1
  prodigy_dev_cousin_mark_time "$ROOT/cousin-withdrawn"
  COUSIN_OFFLINE=0
  # This marker bounds delivery of the synchronous Mothership revoke command;
  # its local revoke/close may happen before the completion marker below.
  prodigy_dev_cousin_mark_time "$ROOT/cousin-revocation-request"
  m cousin-permission-revoke 45 "$ROOT/cousin-permission-revoke.log" cousinPermission "$FIRST" revoke "0x$source_permission" || return
  prodigy_dev_cousin_mark_time "$ROOT/cousin-revoked"
  COUSIN_OFFLINE=1
  python3 "$TEST_DIR/prodigy_dev_cousin_session_observe.py" "$ROOT" revoked || return
  COUSIN_OFFLINE=0
}

# Build the only route-intent shape this harness uses. The Mothership command
# derives cluster, application and service identities from the active pair and
# the two installed permissions; this fixture supplies just the retry-stable
# caller-owned fields. It never writes route state outside Mothership.
prodigy_dev_write_cousin_route_intent() {
  local output=$1 route_id=$2 source_permission=$3 destination_permission=$4 destination_prefix_uuid=$5 state=$6 generation=$7
  python3 - "$output" "$route_id" "$source_permission" "$destination_permission" "$destination_prefix_uuid" "$state" "$generation" \
    "$ROOT/cousin-service-transit.json" "$ROOT/cousin-source-permission.json" "$ROOT/cousin-destination-permission.json" <<'PY_ROUTE'
import json,pathlib,sys,time
output,route_id,source_permission,destination_permission,destination_prefix_uuid,state,generation,transit_path,source_policy_path,destination_policy_path=sys.argv[1:]
route_seed=int(route_id,16)
transit=json.loads(pathlib.Path(transit_path).read_text())
source_policy=json.loads(pathlib.Path(source_policy_path).read_text())
destination_policy=json.loads(pathlib.Path(destination_policy_path).read_text())
assert source_policy['logicalWorkloadUUID']==destination_policy['logicalWorkloadUUID']
assert source_policy['logicalServiceUUID']==destination_policy['logicalServiceUUID']
now=time.time_ns()//1_000_000
def canonical(value):
    return '0x'+value.to_bytes(16,'big').hex()
# The per-directed-route seed is already collision-avoiding in the graph
# harness. Distinct operation UUIDs encode ordered durable generations.
intent={
  'routeUUID':canonical(route_seed ^ 0x5100),
  'operationUUID':canonical(route_seed ^ (0x5200 + int(generation))),
  'logicalWorkloadUUID':source_policy['logicalWorkloadUUID'],
  'logicalServiceUUID':source_policy['logicalServiceUUID'],
  'sourcePermissionUUID':'0x'+source_permission.removeprefix('0x'),
  'destinationPermissionUUID':'0x'+destination_permission.removeprefix('0x'),
  'slots':[0],
  'destinationRoutablePrefixUUID':destination_prefix_uuid,
  'destinationPublicAddress':transit['destinationWormholeIPv6'],
  'transportProtocol':'TCP',
  'destinationCIDR':120,
  'destinationTCPPort':int(transit['destinationTCPPort']),
  'pathMTU':9000,
  'generation':int(generation),
  'issuedAtMs':now,
  'expiresAtMs':now+60*60*1000,
  'state':state,
}
pathlib.Path(output).write_text(json.dumps(intent,sort_keys=True)+'\n')
PY_ROUTE
}

prodigy_dev_cousin_route_uuid() {
  python3 - "$1" <<'PY_ROUTE_UUID'
import sys
print('0x'+((int(sys.argv[1],16)^0x5100).to_bytes(16,'big').hex()))
PY_ROUTE_UUID
}
