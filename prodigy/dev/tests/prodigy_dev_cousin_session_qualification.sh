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
  local lifecycle=${PRODIGY_DEV_COUSIN_LIFECYCLE:-}
  case "$lifecycle" in ''|horizontal|vertical) ;; *) echo 'FAIL: unsupported COUSIN lifecycle profile' >&2; return 1 ;; esac
  [[ -x "$probe" ]] || return 1
  local source_name="CousinSource-${OPERATION#0x}" destination_name="CousinDestination-${OPERATION#0x}"
  local source_permission destination_permission source_cluster destination_cluster source_prefix destination_prefix
  read -r source_permission destination_permission source_prefix destination_prefix < <(python3 - "$OPERATION" <<'PY'
import sys
v=int(sys.argv[1],16); part=(v>>32)&0xffffffff
print(f'{v^0x501:032x}',f'{v^0x502:032x}',f'fdc5:{part>>16:x}:{part&65535:x}:1::/120',f'fdc5:{part>>16:x}:{part&65535:x}:2::/120')
PY
)
  source_cluster=$(rg -m1 -o 'clusterUUID=0x[0-9a-f]+' "$ROOT/create-first.log" | cut -d= -f2)
  destination_cluster=$(rg -m1 -o 'clusterUUID=0x[0-9a-f]+' "$ROOT/create-second.log" | cut -d= -f2)
  [[ -n "$source_cluster" && -n "$destination_cluster" && "$source_cluster" != "$destination_cluster" ]] || return 1
  local source_app destination_app destination_prefix_uuid
  # Reserve a destination-only dummy so asymmetric application IDs are exercised.
  m cousin-reserve-dummy 30 "$ROOT/cousin-reserve-dummy.log" reserveApplicationID "$SECOND" \
    "$(jq -nc --arg name "CousinDummy-${OPERATION#0x}" '{applicationName:$name,createIfMissing:true}')" || return
  for side in source destination; do
    if [[ $side == source ]]; then cluster=$FIRST; name=$source_name; else cluster=$SECOND; name=$destination_name; fi
    m "cousin-reserve-$side" 30 "$ROOT/cousin-reserve-$side.log" reserveApplicationID "$cluster" \
      "$(jq -nc --arg name "$name" '{applicationName:$name,createIfMissing:true}')" || return
    app=$(rg -m1 -o 'appID=[1-9][0-9]*' "$ROOT/cousin-reserve-$side.log" | cut -d= -f2)
    [[ $app =~ ^[1-9][0-9]*$ ]] || return 1
    m "cousin-service-$side" 30 "$ROOT/cousin-service-$side.log" reserveServiceID "$cluster" \
      "$(jq -nc --argjson app "$app" '{applicationID:$app,serviceName:"cousin",requestedServiceSlot:3,kind:"stateful",createIfMissing:true}')" || return
    local prefix
    if [[ $side == source ]]; then prefix=$source_prefix; source_app=$app
    else prefix=$destination_prefix; destination_app=$app; fi
    if [[ $side == source ]]; then
      python3 - "$ROOT/first-cluster-report.log" "$source_prefix" >"$ROOT/cousin-source-prefixes.tsv" <<'PY_PREFIX'
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
          "$(jq -nc --arg name "cousin-source-$prefix_index-${OPERATION#0x}" --arg prefix "$prefix" --arg machine "$machine_uuid" \
          '{name:$name,kind:"BGP",prefix:$prefix,usage:"whiteholes",ingressScope:"singleMachine",machineUUID:$machine}')" || return
      done <"$ROOT/cousin-source-prefixes.tsv"
    else
      m cousin-prefix-destination 30 "$ROOT/cousin-prefix-destination.log" registerRoutableSubnet "$cluster" \
        "$(jq -nc --arg name "cousin-destination-${OPERATION#0x}" --arg prefix "$prefix" \
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
  if [[ -n "$lifecycle" ]]; then echo 'ENV COUSIN_PROBE_LIFECYCLE=1' >>"$artifact/Cousin.DiscombobuFile"; fi
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
    if side=='source': plan['whiteholes']=[{'transport':'tcp','family':'ipv6','source':'registeredRoutablePrefix'}]
    else:
        plan['advertisements']=[{'service':'${service:'+name+'/cousin.group0}','startAt':'ContainerState::scheduled','stopAt':'ContainerState::destroying','port':9443}]
        plan['wormholes']=[{'name':'cousin','source':'registeredRoutablePrefix','routablePrefixUUID':sys.argv[7],
                           'externalPort':9443,'containerPort':9443,'layer4':'TCP','isQuic':False}]
        scaler={'name':'cousin.probe.scale','percentile':90,'lookbackSeconds':3,'threshold':0.000001,'direction':'upscale'}
        if sys.argv[8]=='horizontal':
            plan['horizontalScalers']=[dict(scaler,lifetime='ApplicationLifetime::base',minValue=3,maxValue=6)]
        elif sys.argv[8]=='vertical':
            plan['verticalScalers']=[dict(scaler,resource='ScalingDimension::memory',increment=128,minValue=256,maxValue=384)]
    (root/f'cousin-{side}-plan.json').write_text(json.dumps(plan))
PY
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
  python3 - "$ROOT" "$source_cluster" "$destination_cluster" "$source_app" "$destination_app" "$source_permission" "$destination_permission" <<'PY'
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]); src=int(sys.argv[4]); dst=int(sys.argv[5])
leases=[]
for line in (root/'cousin-source-leases.log').read_text().splitlines():
    d=dict(re.findall(r'(\w+)=([^\s]+)',line))
    if d.get('kind')=='whiteholeAddressPort' and int(d.get('app','0'))==src: leases.append(d)
assert leases, 'source Whitehole lease missing'
source=leases[0]
line=next(x for x in (root/'cousin-discovery.log').read_text().splitlines() if x.startswith('cousinCounterpart '))
dest=dict(re.findall(r'(\w+)=([^\s]+)',line))
record={'sourceClusterUUID':sys.argv[2],'destinationClusterUUID':sys.argv[3],
    'sourceDeploymentID':(src<<48)|1,'destinationDeploymentID':(dst<<48)|1,
    'sourcePermissionUUID':'0x'+sys.argv[6],'destinationPermissionUUID':'0x'+sys.argv[7],'sourceSlot':0,
    'sourceWhiteholeIPv6':source['address'],'sourceTCPPort':int(source['sourcePort']),
    'destinationWormholeIPv6':dest['publicAddress'],'destinationTCPPort':int(dest['publicTCPPort'])}
(root/'cousin-service-transit.json').write_text(json.dumps(record))
PY
  m cousin-transit 45 "$ROOT/cousin-transit.log" testClusterPairControl "$OPERATION" service "$(cat "$ROOT/cousin-service-transit.json")" || return
  ok "$ROOT/cousin-transit.log" testClusterPairControl || return 1
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
    prodigy_dev_qualify_cousin_lifecycle "$lifecycle" "$destination_name" || return
  fi
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
