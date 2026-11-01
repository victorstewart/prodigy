#!/usr/bin/env bash
# Manifest-driven production client. Mothership is the only lifecycle owner.
set -Eeuo pipefail
[[ ${1:-} != --validate-only ]] || { [[ $# == 1 ]] && bash -n "$0"; exit $?; }
usage(){ echo "usage: $0 --mothership BIN --manifest FILE --run-dir ABS --live [--dry-run|--cleanup|--qualify-existing]" >&2; }
M= MANIFEST= ROOT= CAMPAIGN_RUN_UUID= LIVE=0 DRY=0 CLEAN=0 EXISTING=0
while (($#)); do case $1 in --mothership) M=${2:-};shift 2;;--manifest) MANIFEST=${2:-};shift 2;;--run-dir) ROOT=${2:-};shift 2;;--live) LIVE=1;shift;;--dry-run) DRY=1;shift;;--cleanup) CLEAN=1;shift;;--qualify-existing) EXISTING=1;shift;;*) usage;exit 2;;esac;done
[[ -x $M && -r $MANIFEST && $ROOT == /* ]] || { usage;exit 2; }
(( ! EXISTING || ! CLEAN )) || { usage;exit 2; }
EXECUTION_MODE=full; (( ! EXISTING )) || EXECUTION_MODE=existing
[[ $DRY == 1 || ($LIVE == 1 && ${PRODIGY_NAMETAG_THREE_CLUSTER_LIVE:-} == 1) ]] || { echo 'REFUSE: pass --live and PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1' >&2;exit 2; }
[[ -n ${PRODIGY_MOTHERSHIP_TIDESDB_PATH:-} || $DRY == 1 ]] || { echo 'FAIL: missing PRODIGY_MOTHERSHIP_TIDESDB_PATH' >&2;exit 2; }
command -v jq >/dev/null || exit 77; mkdir -p "$ROOT/receipts"; LEDGER="$ROOT/resource-ledger.jsonl"
phases=(preflight create-ewr-ord enroll-pairs bgp permission-route deploy seed all-masters cross-site conflicts chaos final-verify)
PHASES_JSON="$(printf '%s\n' "${phases[@]}" | jq -R . | jq -sc .)"
# A chaos operation is intentionally named, not an opaque shell fragment: it is
# a Mothership-owned operation which must be advertised by `mothership help` in
# a live run.  The driver never supplies a fallback injector or oracle.
allowed='^(printClusters|clusterReport|createCluster|removeCluster|authorizeBGPOriginPrefix|revokeBGPOriginPrefix|registerRoutableSubnet|unregisterRoutableSubnet|enrollClusterPair|revokeClusterPair|crossClusterMasqueGateway|cousinPermission|cousinRoute|deploy|cancelDeployment|applicationReport|containerLogs|prepareNametagAllMasters|nametagAllMasters|faultRemoteCloudMachine|nametag(Chaos|Observe)[A-Z][A-Za-z0-9]*)$'
die(){ echo "FAIL: $*" >&2;exit 1; }
schema(){ jq -e --argjson phases "$PHASES_JSON" '
 def liveArguments:
   (.liveArgs|type=="array") and (.liveArgsResolved==true) and
   all(.liveArgs[]; type=="string" and length>0 and test("^(fixture|todo|replace|<|\\$\\{|\\[)";"i")|not);
 def liveActions: [.commands[], .cleanup[], .chaos[].injection, .chaos[].observation];
 def mutable:
   (.operation == "createCluster" and .resourceType == "cluster") or
   (.operation == "authorizeBGPOriginPrefix" and .resourceType == "prefix") or
   (.operation == "registerRoutableSubnet" and .resourceType == "prefix") or
   (.operation == "enrollClusterPair" and .resourceType == "pairOperation") or
   (.operation == "crossClusterMasqueGateway" and .resourceType == "gateway" and .args[0] == "configure") or
   (.operation == "cousinPermission" and .resourceType == "permission") or
   (.operation == "cousinRoute" and .resourceType == "route") or
   (.operation == "deploy" and .resourceType == "deployment");
 def inverseFor($operation; $type):
   if $operation == "createCluster" and $type == "cluster" then .operation == "removeCluster"
   elif $operation == "authorizeBGPOriginPrefix" and $type == "prefix" then .operation == "revokeBGPOriginPrefix"
   elif $operation == "registerRoutableSubnet" and $type == "prefix" then .operation == "unregisterRoutableSubnet"
   elif $operation == "enrollClusterPair" and $type == "pairOperation" then .operation == "revokeClusterPair"
   elif $operation == "crossClusterMasqueGateway" and $type == "gateway" then .operation == "crossClusterMasqueGateway" and .args[0] == "withdraw"
   elif $operation == "cousinPermission" and $type == "permission" then .operation == "cousinPermission"
   elif $operation == "cousinRoute" and $type == "route" then .operation == "cousinRoute"
   elif $operation == "deploy" and $type == "deployment" then .operation == "cancelDeployment"
   else false end;
 . as $manifest |
 ($manifest.topology.gatewayMachines | map({key:(.site + ":" + (.slot|tostring)),value:.machineUUID}) | from_entries) as $machineForSiteSlot |
 ([$manifest.topology.masque.paths[].authorities[]]) as $authorities |
 ([$manifest.topology.masque.paths[].authorities[].id]|sort) as $authorityIDs |
 ([$manifest.commands[] | select(mutable) | [.resourceType, .resourceID]]) as $created |
 .version==2 and
 (.execution|type=="object") and (.execution.fixtureOnly|type=="boolean") and (.execution.liveCommandArgumentsResolved|type=="boolean") and
 (if .execution.fixtureOnly then .execution.liveCommandArgumentsResolved == false else .execution.liveCommandArgumentsResolved == true and all(liveActions[]; liveArguments) end) and
 (if .execution.fixtureOnly then true else
    (.qualification|type=="object") and
    (.qualification.allMastersOperationUUID|type=="string" and test("^[0-9a-f]{32}$")) and
    (.qualification.probeDeploymentIDs|type=="object") and
    all([.qualification.probeDeploymentIDs.ewr,.qualification.probeDeploymentIDs.ord,.qualification.probeDeploymentIDs.lan][];
      type=="number" and floor==. and .>0 and ((./281474976710656)|floor)==11)
  end) and
 (.protected|type=="object") and (.protected.names|type=="array") and (.protected.uuids|type=="array") and (.protected.prefixes|type=="array") and
 (.resources|type=="array") and all(.resources[];(.type|IN("cluster","prefix","permission","pairOperation","gateway","route","deployment","artifact","plan","intent")) and (.id|type=="string") and (.name|type=="string")) and
 ([.resources[] | [.type,.id]] | unique | length) == ([.resources[]] | length) and
 (.roles.ewr and .roles.ord and .roles.lan and
  (.topology|type=="object") and
  (.topology.sites|type=="array") and (.topology.sites|length)==3 and ([.topology.sites[].id]|sort)==["ewr","lan","ord"] and
  all(.topology.sites[]; (.prefix|type=="string") and (.datacenterTag|type=="number") and (.datacenterTag|floor)==.datacenterTag and .datacenterTag > 0 and .datacenterTag < 256) and
  ([.topology.sites[].datacenterTag]|unique|length)==3 and
  ([.topology.sites[].prefix]|unique|length)==3 and
  (.topology.routeAdvertisements|type=="array") and (.topology.routeAdvertisements|length)==3 and
  ([.topology.routeAdvertisements[].site]|sort)==["ewr","lan","ord"] and
  ([.topology.routeAdvertisements[].prefix]|sort)==([.topology.sites[].prefix]|sort) and
  all(.topology.routeAdvertisements[]; .scope=="site-local") and
  (.topology.gatewayMachines|type=="array") and (.topology.gatewayMachines|length)==9 and
  all(.topology.gatewayMachines[]; (.site|IN("ewr","ord","lan")) and (.slot|type=="number") and (.slot|floor)==.slot and (.slot>=0 and .slot<3) and (.machineUUID|type=="string") and (.machineUUID|test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))) and
  ([.topology.gatewayMachines[].machineUUID]|unique|length)==9 and
  ([.topology.gatewayMachines[] | [.site,.slot]]|unique|length)==9 and
  all(["ewr","ord","lan"][]; . as $site |
    [$manifest.topology.gatewayMachines[]|select(.site==$site)] as $machines |
    ($machines|length)==3 and ([$machines[].slot]|sort)==[0,1,2]) and
  (.topology.masque|type=="object") and (.topology.masque.paths|type=="array") and (.topology.masque.paths|length)==9 and
  ([.topology.masque.paths[] | (.sites | join("-"))]|sort)==["ewr-lan","ewr-lan","ewr-lan","ewr-ord","ewr-ord","ewr-ord","ord-lan","ord-lan","ord-lan"] and
  ([.topology.masque.paths[] | . as $path | [$path.sites|join("-"), $path.slot]]|unique|length)==9 and
  ($authorities|length)==18 and ([ $authorities[].id ]|unique|length)==18 and ([ $authorities[].interface ]|unique|length)==18 and
  all($manifest.topology.masque.paths[]; . as $path |
    $path.sites as $pathSites | $path.authorities as $pathAuthorities |
    ($pathSites|type=="array") and ($pathSites|length)==2 and $pathSites[0] != $pathSites[1] and
    ($path.slot|type=="number") and ($path.slot|floor)==$path.slot and ($path.slot>=0 and $path.slot<3) and
    ($path.path == (($pathSites|join("-")) + "-" + ($path.slot|tostring))) and
    ($pathAuthorities|type=="array") and ($pathAuthorities|length)==2 and
    ([$pathAuthorities[].site]|sort)==($pathSites|sort) and
    all($pathAuthorities[]; . as $authority |
      (.id|type=="string") and (.id|length)>0 and (.site|type=="string") and (.peer|type=="string") and .site != .peer and (.slot == $path.slot) and (.machineUUID|type=="string") and (.peerMachineUUID|type=="string") and (.interface|type=="string") and (.interface|length)>0 and
      ($authority.machineUUID == $machineForSiteSlot[($authority.site + ":" + ($authority.slot|tostring))]) and
      ($authority.peerMachineUUID == $machineForSiteSlot[($authority.peer + ":" + ($authority.slot|tostring))])) and
    ($path.authorities[0] as $a | $path.authorities[1] as $b |
      $a.site==$b.peer and $a.peer==$b.site and $a.slot==$b.slot and $a.machineUUID==$b.peerMachineUUID and $a.peerMachineUUID==$b.machineUUID)) and
  all($manifest.topology.gatewayMachines[]; . as $machine |
    [$authorities[]|select(.site==$machine.site and .machineUUID==$machine.machineUUID)] as $owned |
    ($owned|length)==2 and ([$owned[].slot]|unique)==[$machine.slot] and
    ([$owned[].peer]|sort)==(["ewr","ord","lan"]|map(select(.!=$machine.site))|sort)) and
  (.topology.siteLocalPrefixOwnership == true) and
  (.topology.stores|type=="object") and
  all(["Hot","Cold"][]; . as $store | ($manifest.topology.stores[$store] | .groups==[0,1,2] and .writableReplicasPerGroupPerSite==3)) and
  all(["Radar","Pulse"][]; . as $store | ($manifest.topology.stores[$store] | .groups==[0] and .writableReplicasPerGroupPerSite==3)) and
  (.topology.stores.Truth.groups==[0] and .topology.stores.Truth.globalWriters==1 and .topology.stores.Truth.writerSite=="ewr" and (.topology.stores.Truth.writerReplica|type=="string") and (.topology.stores.Truth.writerReplica|length)>0) and
  (.topology.app6.sites|sort)==["ewr","lan","ord"] and .topology.app6.replicasPerSite==1 and
  (.pairs|length)==3 and (.prefixes|length)>0 and (.databases|sort)==["Cold","Hot","Pulse","Radar","Truth"] and (.applications|index("app6")) and
  (.chaos|type=="array") and (.chaos|length)==17 and
  ([.chaos[].id]|sort)==["brain-hard-reboot-catchup","cousin-route-session-reconnect","ewr-ord-path-loss","graph-kv-replay-reorder","local-writer-isolation","masque-session-loss-bgp-recovery","mothership-restart-resume","permission-revoke-reinstall","pulse-fixed-matrix-dedup","radar-directed-mutations","second-stream-handoff-fence","second-truth-writer-fencing","seed-interruption-resume","sequential-user-key-writes","shared-key-commutative-writes","site-partition-local-writes","truth-claim-partition"] and
  all(.chaos[]; (.id|type=="string") and (.deadlineSeconds|type=="number") and .deadlineSeconds > 0 and (.convergenceSeconds|type=="number") and .convergenceSeconds > 0 and .convergenceSeconds <= .deadlineSeconds and
    (.injection|type=="object") and (.observation|type=="object") and
    .injection.operation != .observation.operation and
    all([.injection,.observation][]; .owner=="Mothership" and (.operation|type=="string") and (.operation|test("^nametag(Chaos|Observe)[A-Z][A-Za-z0-9]*$")) and (.args==[]) and (if $manifest.execution.fixtureOnly then true else .liveArgs==[] and .liveArgsResolved==true end) and (.resourceType=="intent") and (.resourceID|type=="string") and (.label|type=="string")) and
    (.receiptSchema|type=="object") and .receiptSchema.version==4 and (.receiptSchema.required|sort)==["allMastersOperationUUID","applicationReceipts","canonicalConvergenceWitness","convergenceDeadlineAtMilliseconds","deadlineAtMilliseconds","direction","observedAtMilliseconds","protocolVersion","rowID","runUUID","startedAtMilliseconds","witnessDigest","witnessedResult"]) and
  ([.chaos[] | .injection.label, .observation.label] | length) == ([.chaos[] | .injection.label, .observation.label] | unique | length) and
  (.oracles|type=="array") and (.oracles|length)>0 and
 (.commands|type=="array") and ([.commands[].phase]|sort|unique)==($phases|sort) and all($phases[]; . as $phase | [$manifest.commands[]|select(.phase==$phase)]|length>0) and ([.commands[].label]|length)==([.commands[].label]|unique|length) and all(.commands[];(.phase|type=="string") and (.operation|type=="string") and (.args|type=="array") and (.resourceType|type=="string") and (.resourceID|type=="string")) and
 ([.resources[]|select(.type=="gateway")|.id]|sort) == $authorityIDs and
 ([.commands[]|select(.operation=="crossClusterMasqueGateway" and .resourceType=="gateway" and .args==["configure"])|.resourceID]|sort) == $authorityIDs and
 ([.commands[]|select(.operation=="crossClusterMasqueGateway" and .resourceType=="gateway")]|length)==18 and
 (.cleanup|type=="array") and ([.cleanup[].label]|length)==([.cleanup[].label]|unique|length) and all(.cleanup[];(.operation|type=="string") and (.args|type=="array") and (.resourceType|type=="string") and (.resourceID|type=="string") and (.label|type=="string")) and
 ([.cleanup[]|select(.operation=="crossClusterMasqueGateway" and .resourceType=="gateway" and .args==["withdraw"])|.resourceID]|sort) == $authorityIDs and
 ([.cleanup[]|select(.operation=="crossClusterMasqueGateway" and .resourceType=="gateway")]|length)==18 and
 (($created|length) == ($created|unique|length)) and
 ([.cleanup[] | [.resourceType, .resourceID]]) == ($created|reverse) and
 all(.commands[] | select(mutable); . as $createdCommand |
   ([$manifest.cleanup[] | select(.resourceType == $createdCommand.resourceType and .resourceID == $createdCommand.resourceID)]) as $undo |
   ($undo|length) == 1 and ($undo[0] | inverseFor($createdCommand.operation; $createdCommand.resourceType))))' "$MANIFEST" >/dev/null || die 'manifest schema'; }
canonical_prefixes(){ python3 - "$MANIFEST" <<'PY'
import ipaddress
import json
import sys

for site in json.load(open(sys.argv[1], encoding="utf-8"))["topology"]["sites"]:
    prefix = site["prefix"]
    network = ipaddress.ip_network(prefix, strict=True)
    if network.version != 6 or network.prefixlen != 96 or str(network) != prefix:
        raise SystemExit(1)
PY
}
materialized_inputs_ready(){
 jq -er '
  [.materialization.allMastersPreparation,
   .materialization.createRequests.ewr,
   .materialization.createRequests.ord,
   (.materialization.authorityRequests | to_entries[] | .value)][] |
  [.path, .sha256] | @tsv' "$MANIFEST" |
 while IFS=$'\t' read -r path digest; do
   [[ -f $path && -r $path && $digest =~ ^[0-9a-f]{64}$ ]] || return 1
   [[ $(sha256sum "$path" | cut -d' ' -f1) == "$digest" ]] || return 1
 done
}
live_ready(){ jq -e '
 . as $manifest |
 def ready:
   (.liveArgs|type=="array") and (.liveArgsResolved==true) and
   all(.liveArgs[]; type=="string" and length>0 and test("^(fixture|todo|replace|<|\\$\\{|\\[)";"i")|not);
 $manifest.execution.fixtureOnly == false and $manifest.execution.liveCommandArgumentsResolved == true and
 all([$manifest.commands[], $manifest.cleanup[], $manifest.chaos[].injection, $manifest.chaos[].observation][]; ready) and
 ($manifest.materialization|type=="object") and
 ($manifest.materialization.allMastersPreparation|type=="object") and
 ($manifest.materialization.allMastersPreparation.path|type=="string" and startswith("/")) and
 ($manifest.materialization.allMastersPreparation.sha256|type=="string" and test("^[0-9a-f]{64}$")) and
 ($manifest.materialization.allMastersIntent|type=="object") and
 ($manifest.materialization.allMastersIntent.path|type=="string" and startswith("/")) and
 ($manifest.materialization.createRequests|type=="object" and ($manifest.materialization.createRequests|keys|sort)==["ewr","ord"]) and
 all($manifest.materialization.createRequests[]; (.path|type=="string" and startswith("/")) and (.sha256|type=="string" and test("^[0-9a-f]{64}$")) and (.name|type=="string" and length>0)) and
 ($manifest.materialization.createRequests.ewr.name != $manifest.materialization.createRequests.ord.name) and
 ($manifest.materialization.authorityRequests|type=="object") and
 (([$manifest.materialization.authorityRequests|keys[]]|sort) == ([$manifest.topology.masque.paths[].authorities[].id]|sort)) and
 all($manifest.materialization.authorityRequests[]; (.path|type=="string" and startswith("/")) and (.sha256|type=="string" and test("^[0-9a-f]{64}$")) and (.configureLiveArgs|type=="array") and (.withdrawLiveArgs|type=="array")) and
 all($manifest.resources[] | select(.type=="cluster" and (.id=="ewr" or .id=="ord"));
   .name == $manifest.materialization.createRequests[.id].name) and
 all($manifest.commands[]; . as $command |
   if $command.operation=="createCluster" and ($command.resourceID=="ewr" or $command.resourceID=="ord")
   then $command.liveArgs == ["@" + $manifest.materialization.createRequests[$command.resourceID].path]
   elif $command.operation=="nametagAllMasters"
   then $command.liveArgs == [$manifest.materialization.allMastersIntent.path]
   elif $command.operation=="crossClusterMasqueGateway" and $command.args==["configure"]
   then $command.liveArgs == $manifest.materialization.authorityRequests[$command.resourceID].configureLiveArgs
   else true end) and
 all($manifest.cleanup[]; . as $command |
   if $command.operation=="removeCluster" and ($command.resourceID=="ewr" or $command.resourceID=="ord")
   then $command.liveArgs == [$manifest.materialization.createRequests[$command.resourceID].name]
   elif $command.operation=="crossClusterMasqueGateway" and $command.args==["withdraw"]
   then $command.liveArgs == $manifest.materialization.authorityRequests[$command.resourceID].withdrawLiveArgs
   else true end)' "$MANIFEST" >/dev/null && materialized_inputs_ready; }
qualification_capabilities(){
 local output="$ROOT/nametag-qualification-capabilities.json"
 "$M" nametagQualificationCapabilities >"$output" 2>&1 || die 'Mothership qualification capability preflight failed'
 jq -e --argjson required "$(jq -c '[.chaos[] | . as $row | ["injection","observation"][] as $direction | $row[$direction] | {rowID:$row.id,direction:$direction,operation:.operation}]' "$MANIFEST")" '
  .schema == "mothership.nametag-qualification-capabilities.v1" and .receiptProtocolVersion == 4 and
  (.adapters|type=="array" and length==34) and
  all(.adapters[]; (.rowID|type=="string" and length>0) and (.direction|IN("injection","observation")) and
    (.operation|type=="string" and test("^nametag(Chaos|Observe)[A-Z][A-Za-z0-9]*$")) and
    (.implemented|type=="boolean") and
    (if .implemented then true else (.reason|type=="string" and length>0) end)) and
  ([.adapters[] | [.rowID,.direction,.operation]] | unique | length) == 34 and
  ([.adapters[] | select(.implemented != true)] | length) == 0 and
  ([.adapters[] | [.rowID,.direction,.operation]] | sort) == ([$required[] | [.rowID,.direction,.operation]] | sort)' "$output" >/dev/null ||
    die 'Mothership qualification capability preflight does not prove every chaos adapter'
}
canonical_run_uuid(){ [[ $1 =~ ^[0-9a-f]{32}$ ]]; }
canonical_cli_uuid(){
  [[ $1 =~ ^[0-9a-f]{32}$ && $1 != 00000000000000000000000000000000 ]] || return 1
  local value=$1
  while [[ ${#value} -gt 2 && ${value:0:2} == 00 ]]; do value=${value:2}; done
  printf '0x%s' "$value"
}
new_run_uuid(){ LC_ALL=C od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }
init(){
 local manifest_hash header
 manifest_hash="$(sha256sum "$MANIFEST"|cut -d' ' -f1)"
 if [[ ! -e $LEDGER ]]; then
   CAMPAIGN_RUN_UUID="$(new_run_uuid)"
   canonical_run_uuid "$CAMPAIGN_RUN_UUID" || die 'cannot generate campaign run UUID'
   jq -nc --arg manifest "$manifest_hash" --arg run_uuid "$CAMPAIGN_RUN_UUID" --arg mode "$EXECUTION_MODE" '{kind:"header",version:2,manifestSHA256:$manifest,campaignRunUUID:$run_uuid,executionMode:$mode}' >"$LEDGER"
 fi
 header="$(jq -ser --arg m "$manifest_hash" --arg mode "$EXECUTION_MODE" '
   [.[] | select(.kind=="header")] as $headers |
   if ($headers|length)==1 and ($headers[0].version==2) and ($headers[0].manifestSHA256==$m) and (($headers[0].executionMode // "full")==$mode) and ($headers[0].campaignRunUUID|type=="string" and test("^[0-9a-f]{32}$")) then $headers[0].campaignRunUUID else empty end' "$LEDGER")" || die 'ledger header fields'
 canonical_run_uuid "$header" || die 'ledger header fields'
 CAMPAIGN_RUN_UUID="$header"
}
done_phase(){ jq -e --arg p "$1" 'select(.kind=="phase" and .phase==$p and .status=="success")' "$LEDGER" >/dev/null; }
protected(){ local id=$1; jq -e --arg x "$id" '(.protected.names+.protected.uuids+.protected.prefixes)|index($x)!=null' "$MANIFEST" >/dev/null; }
resource(){ jq -e --arg t "$1" --arg id "$2" '.resources[]|select(.type==$t and .id==$id)' "$MANIFEST" >/dev/null; }
mutable(){ case "$1:$2" in createCluster:cluster|authorizeBGPOriginPrefix:prefix|registerRoutableSubnet:prefix|enrollClusterPair:pairOperation|cousinPermission:permission|cousinRoute:route|deploy:deployment) return 0;;crossClusterMasqueGateway:gateway) [[ $(jq -r '.[0] // empty' <<<"$3") =~ ^(configure|configurePair)$ ]];return;;*) return 1;;esac; }
compatible(){ [[ $2 == intent && $1 =~ ^nametag(Chaos|Observe)[A-Z][A-Za-z0-9]*$ ]] && return 0; case "$1:$2" in printClusters:cluster|clusterReport:cluster|applicationReport:deployment|containerLogs:deployment|createCluster:cluster|removeCluster:cluster|authorizeBGPOriginPrefix:prefix|revokeBGPOriginPrefix:prefix|registerRoutableSubnet:prefix|unregisterRoutableSubnet:prefix|enrollClusterPair:pairOperation|revokeClusterPair:pairOperation|crossClusterMasqueGateway:gateway|cousinPermission:permission|cousinRoute:route|deploy:deployment|cancelDeployment:deployment|nametagAllMasters:intent|faultRemoteCloudMachine:cluster) return 0;;*) return 1;;esac; }
arguments_for(){ if ((LIVE && !DRY)); then jq -c .liveArgs <<<"$1"; else jq -c .args <<<"$1"; fi; }
prepared_all_masters_ready(){ local preparation preparation_sha256 intent record; preparation="$(jq -er '.materialization.allMastersPreparation.path' "$MANIFEST")"; preparation_sha256="$(jq -er '.materialization.allMastersPreparation.sha256' "$MANIFEST")"; intent="$(jq -er '.materialization.allMastersIntent.path' "$MANIFEST")"; record="$(jq -ser --arg preparation "$preparation" --arg preparation_sha256 "$preparation_sha256" --arg intent "$intent" '[.[] | select(.kind=="allMastersPreparation" and .status=="success" and .preparationPath==$preparation and .preparationSHA256==$preparation_sha256 and .intentPath==$intent)] | if length==1 then .[0] else empty end' "$LEDGER")" || return 1; [[ -n $record && -f $intent && -r $intent ]] || return 1; [[ $(sha256sum "$intent" | cut -d' ' -f1) == "$(jq -r '.intentSHA256' <<<"$record")" ]]; }
prepare_all_masters(){ local preparation preparation_sha256 intent intent_sha256; prepared_all_masters_ready && return 0; preparation="$(jq -er '.materialization.allMastersPreparation.path' "$MANIFEST")"; preparation_sha256="$(jq -er '.materialization.allMastersPreparation.sha256' "$MANIFEST")"; intent="$(jq -er '.materialization.allMastersIntent.path' "$MANIFEST")"; if jq -e 'select(.kind=="allMastersPreparation" and .status=="success")' "$LEDGER" >/dev/null; then die 'all-masters intent is absent, tampered, or was not prepared for this ledger'; fi; call prepare-all-masters prepareNametagAllMasters "$(jq -nc --arg preparation "$preparation" --arg intent "$intent" '[$preparation,$intent]')"; [[ -f $intent && -r $intent ]] || die 'Mothership did not produce all-masters intent'; intent_sha256="$(sha256sum "$intent" | cut -d' ' -f1)"; [[ $intent_sha256 =~ ^[0-9a-f]{64}$ ]] || die 'all-masters intent digest'; jq -nc --arg preparation "$preparation" --arg preparation_sha256 "$preparation_sha256" --arg intent "$intent" --arg intent_sha256 "$intent_sha256" '{kind:"allMastersPreparation",status:"success",preparationPath:$preparation,preparationSHA256:$preparation_sha256,intentPath:$intent,intentSHA256:$intent_sha256}' >>"$LEDGER"; }
# On a failed checkpoint, stop only the unreaped child owned by this driver.
stop_restart_child(){
 python3 - "$1" "$$" "$2" <<'PYPROC'
import hashlib, os, signal, sys
pid, parent, expected = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
def identity():
    with open(f'/proc/{pid}/stat', encoding='ascii') as stat:
        fields = stat.read().rsplit(')', 1)[1].split()
    return int(fields[1]), fields[19]
try:
    fd = os.pidfd_open(pid, 0)
    before = identity()
    if before[0] != parent:
        raise ValueError('not our child')
    h = hashlib.sha256()
    with open(f'/proc/{pid}/exe', 'rb') as executable:
        for chunk in iter(lambda: executable.read(1024 * 1024), b''):
            h.update(chunk)
    if h.hexdigest() != expected or identity() != before:
        raise ValueError('child identity changed')
    signal.pidfd_send_signal(fd, signal.SIGTERM)
    os.close(fd)
except (OSError, ValueError, IndexError, AttributeError):
    sys.exit(1)
PYPROC
}
# Pin the driver-owned child before validating and signaling its checkpoint.
signal_checkpoint_child(){
 python3 - "$1" "$2" "$3" "$4" "$$" <<'PYPROC'
import hashlib, os, signal, sys
pid, expected_start, expected_boot, expected_binary, expected_parent = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
def start():
    with open(f'/proc/{pid}/stat', encoding='ascii') as stat:
        fields = stat.read().rsplit(')', 1)[1].split()
        if int(fields[1]) != expected_parent:
            raise ValueError('not our child')
        return fields[19]
try:
    fd = os.pidfd_open(pid, 0)
    with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as boot:
        actual_boot = boot.read().strip()
    if start() != expected_start or actual_boot != expected_boot:
        raise ValueError('process incarnation changed')
    h = hashlib.sha256()
    with open(f'/proc/{pid}/exe', 'rb') as executable:
        for chunk in iter(lambda: executable.read(1024 * 1024), b''):
            h.update(chunk)
    actual_binary = h.hexdigest()
    if actual_binary != expected_binary or start() != expected_start:
        raise ValueError('process executable or incarnation changed')
    signal.pidfd_send_signal(fd, signal.SIGTERM)
    os.close(fd)
except (OSError, ValueError, IndexError, AttributeError):
    sys.exit(1)
PYPROC
}
# Restart only the child launched for this exact qualification operation.
# The persisted checkpoint binds run/nonce; /proc prevents signaling a reused PID.
restart_qualification(){
 local label=$1 op=$2 run_cli=$3 all_masters_cli=$4 ewr_probe=$5 ord_probe=$6 lan_probe=$7
 local child marker nonce start boot binary expected_binary current_start wait_status checkpoint
 checkpoint="$ROOT/receipts/$label-restart-checkpoint.json"
 expected_binary="$(sha256sum "$M" | cut -d' ' -f1)" || return 1
 if [[ -e $checkpoint ]]; then
   marker="$(cat "$checkpoint")" || return 1
   nonce="$(jq -er --arg run "$run_cli" --arg digest "$expected_binary" '
     select(.restartCheckpoint==true and .runUUID==$run and .binarySHA256==$digest and
       (.nonce|type=="string" and test("^0x[0-9a-f]+$"))) | .nonce' <<<"$marker")" || return 1
   child="$(jq -er '.pid | select(type=="number" and .>1)' <<<"$marker")" || return 1
   start="$(jq -er '.startTime | select(type=="number" and .>0)' <<<"$marker")" || return 1
   boot="$(jq -er '.bootID | select(type=="string" and length>0)' <<<"$marker")" || return 1
   [[ $(cat /proc/sys/kernel/random/boot_id) == "$boot" ]] || return 1
   if [[ -e /proc/$child/stat ]]; then
     current_start="$(python3 - "$child" <<'PYPROC'
import sys
try:
    with open('/proc/' + sys.argv[1] + '/stat', encoding='ascii') as stat:
        print(stat.read().rsplit(')', 1)[1].split()[19])
except (OSError, ValueError, IndexError):
    sys.exit(1)
PYPROC
)" || return 1
     [[ $current_start != "$start" ]] || return 1
   fi
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$PRODIGY_MOTHERSHIP_TIDESDB_PATH" \
    PRODIGY_NAMETAG_QUALIFICATION_RUN_UUID="$run_cli" PRODIGY_NAMETAG_QUALIFICATION_ALL_MASTERS_OPERATION_UUID="$all_masters_cli" \
    PRODIGY_NAMETAG_QUALIFICATION_EWR_PROBE_DEPLOYMENT_ID="$ewr_probe" PRODIGY_NAMETAG_QUALIFICATION_ORD_PROBE_DEPLOYMENT_ID="$ord_probe" \
    PRODIGY_NAMETAG_QUALIFICATION_LAN_PROBE_DEPLOYMENT_ID="$lan_probe" PRODIGY_NAMETAG_RESTART_MODE=resume PRODIGY_NAMETAG_RESTART_NONCE="$nonce" \
    "$M" "$op" >>"$ROOT/$label.log" 2>&1
   return
 fi
 env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$PRODIGY_MOTHERSHIP_TIDESDB_PATH" \
  PRODIGY_NAMETAG_QUALIFICATION_RUN_UUID="$run_cli" PRODIGY_NAMETAG_QUALIFICATION_ALL_MASTERS_OPERATION_UUID="$all_masters_cli" \
  PRODIGY_NAMETAG_QUALIFICATION_EWR_PROBE_DEPLOYMENT_ID="$ewr_probe" PRODIGY_NAMETAG_QUALIFICATION_ORD_PROBE_DEPLOYMENT_ID="$ord_probe" \
  PRODIGY_NAMETAG_QUALIFICATION_LAN_PROBE_DEPLOYMENT_ID="$lan_probe" PRODIGY_NAMETAG_RESTART_MODE=arm \
  "$M" "$op" >"$ROOT/$label.log" 2>&1 & child=$!
 marker=
 for ((attempt=0; attempt<900; attempt++)); do
   marker="$(jq -Rsc '[split("\n")[] | try fromjson catch empty | select(.restartCheckpoint==true)] | last // empty' "$ROOT/$label.log")" || marker=
   [[ -n $marker ]] && break
   kill -0 "$child" 2>/dev/null || { wait "$child" || :; return 1; }
   sleep 0.1
 done
 [[ -n $marker ]] || { stop_restart_child "$child" "$expected_binary" || :; wait "$child" || :; return 1; }
 nonce="$(jq -er --arg run "$run_cli" --argjson pid "$child" --arg digest "$expected_binary" '
   select(.runUUID==$run and .pid==$pid and .binarySHA256==$digest and
     (.nonce|type=="string" and test("^0x[0-9a-f]+$")) and
     (.startTime|type=="number" and .>0) and (.bootID|type=="string" and length>0)) | .nonce' <<<"$marker")" || { stop_restart_child "$child" "$expected_binary" || :; wait "$child" || :; return 1; }
 start="$(jq -r .startTime <<<"$marker")"; boot="$(jq -r .bootID <<<"$marker")"; binary="$(jq -r .binarySHA256 <<<"$marker")"
 printf '%s\n' "$marker" >"$checkpoint.tmp" && mv "$checkpoint.tmp" "$checkpoint" || { stop_restart_child "$child" "$expected_binary" || :; wait "$child" || :; return 1; }
 signal_checkpoint_child "$child" "$start" "$boot" "$binary" || { stop_restart_child "$child" "$expected_binary" || :; wait "$child" || :; return 1; }
 wait_status=0; wait "$child" || wait_status=$?
 [[ $wait_status == 143 ]] || return 1
 env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$PRODIGY_MOTHERSHIP_TIDESDB_PATH" \
  PRODIGY_NAMETAG_QUALIFICATION_RUN_UUID="$run_cli" PRODIGY_NAMETAG_QUALIFICATION_ALL_MASTERS_OPERATION_UUID="$all_masters_cli" \
  PRODIGY_NAMETAG_QUALIFICATION_EWR_PROBE_DEPLOYMENT_ID="$ewr_probe" PRODIGY_NAMETAG_QUALIFICATION_ORD_PROBE_DEPLOYMENT_ID="$ord_probe" \
  PRODIGY_NAMETAG_QUALIFICATION_LAN_PROBE_DEPLOYMENT_ID="$lan_probe" PRODIGY_NAMETAG_RESTART_MODE=resume PRODIGY_NAMETAG_RESTART_NONCE="$nonce" \
  "$M" "$op" >>"$ROOT/$label.log" 2>&1
}
call(){ local label=$1 op=$2 args_json=$3; [[ $op =~ $allowed ]] || die "unsupported Mothership op $op"; if ((DRY));then jq -nc --arg label "$label" --arg operation "$op" --argjson args "$args_json" '{dryRun:true,label:$label,operation:$operation,args:$args}';return 0;fi; [[ $op != nametagAllMasters ]] || prepared_all_masters_ready || die 'all-masters intent is absent, tampered, or was not prepared for this ledger'; local -a argv=();local a;while IFS= read -r a;do argv+=("$a");done < <(jq -r '.[]' <<<"$args_json"); if [[ $op =~ ^nametag(Chaos|Observe)[A-Z][A-Za-z0-9]*$ ]]; then local all_masters ewr_probe ord_probe lan_probe run_cli all_masters_cli; all_masters="$(jq -er '.qualification.allMastersOperationUUID' "$MANIFEST")"; run_cli="$(canonical_cli_uuid "$CAMPAIGN_RUN_UUID")" || die 'invalid campaign run UUID'; all_masters_cli="$(canonical_cli_uuid "$all_masters")" || die 'invalid all-masters UUID'; ewr_probe="$(jq -er '.qualification.probeDeploymentIDs.ewr' "$MANIFEST")"; ord_probe="$(jq -er '.qualification.probeDeploymentIDs.ord' "$MANIFEST")"; lan_probe="$(jq -er '.qualification.probeDeploymentIDs.lan' "$MANIFEST")"; if [[ $op == nametagChaosMothershipRestartResume ]]; then restart_qualification "$label" "$op" "$run_cli" "$all_masters_cli" "$ewr_probe" "$ord_probe" "$lan_probe"; return; fi; env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$PRODIGY_MOTHERSHIP_TIDESDB_PATH" PRODIGY_NAMETAG_QUALIFICATION_RUN_UUID="$run_cli" PRODIGY_NAMETAG_QUALIFICATION_ALL_MASTERS_OPERATION_UUID="$all_masters_cli" PRODIGY_NAMETAG_QUALIFICATION_EWR_PROBE_DEPLOYMENT_ID="$ewr_probe" PRODIGY_NAMETAG_QUALIFICATION_ORD_PROBE_DEPLOYMENT_ID="$ord_probe" PRODIGY_NAMETAG_QUALIFICATION_LAN_PROBE_DEPLOYMENT_ID="$lan_probe" "$M" "$op" >"$ROOT/$label.log" 2>&1; else if ((${#argv[@]})); then env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$PRODIGY_MOTHERSHIP_TIDESDB_PATH" "$M" "$op" "${argv[@]}" >"$ROOT/$label.log" 2>&1; else env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$PRODIGY_MOTHERSHIP_TIDESDB_PATH" "$M" "$op" >"$ROOT/$label.log" 2>&1; fi; fi; }
run_phase(){ local p=$1; done_phase "$p"&&return 0; while IFS= read -r command;do local op rt rid args label name args_sha256;op=$(jq -r .operation<<<"$command");rt=$(jq -r .resourceType<<<"$command");rid=$(jq -r .resourceID<<<"$command");args=$(arguments_for "$command");label=$(jq -r .label<<<"$command");name=$(jq -er --arg t "$rt" --arg id "$rid" '.resources[]|select(.type==$t and .id==$id)|.name' "$MANIFEST");resource "$rt" "$rid"||die "$p unknown resource";compatible "$op" "$rt"||die "$p incompatible $op:$rt";if mutable "$op" "$rt" "$args";then protected "$rid"&&die "$p protected mutable resource";fi;call "$label" "$op" "$args";if mutable "$op" "$rt" "$args";then args_sha256=$(jq -jc . <<<"$args" | sha256sum | cut -d' ' -f1); jq -nc --arg p "$p" --arg op "$op" --arg t "$rt" --arg id "$rid" --arg name "$name" --arg args_sha256 "$args_sha256" '{kind:"resource",phase:$p,operation:$op,resourceType:$t,resourceID:$id,resourceName:$name,argumentsSHA256:$args_sha256,status:"success"}' >>"$LEDGER";fi;done < <(jq -c --arg p "$p" '.commands[]|select(.phase==$p)' "$MANIFEST"); jq -nc --arg p "$p" '{kind:"phase",phase:$p,status:"success"}' >>"$LEDGER"; }
cleanup_done(){ jq -e --arg t "$1" --arg id "$2" 'select(.kind=="cleanup" and .status=="success" and .resourceType==$t and .resourceID==$id)' "$LEDGER" >/dev/null; }
cleanup(){ while IFS= read -r command;do local op rt rid args label;op=$(jq -r .operation<<<"$command");rt=$(jq -r .resourceType<<<"$command");rid=$(jq -r .resourceID<<<"$command");args=$(arguments_for "$command");label=$(jq -r .label<<<"$command");resource "$rt" "$rid"||die 'cleanup resource mismatch';protected "$rid"&&die 'cleanup protected fence';compatible "$op" "$rt"||die "cleanup incompatible $op:$rt";jq -e --arg t "$rt" --arg id "$rid" 'select(.kind=="resource" and .status=="success" and .resourceType==$t and .resourceID==$id)' "$LEDGER">/dev/null||continue;cleanup_done "$rt" "$rid"&&continue;call "$label" "$op" "$args";jq -nc --arg op "$op" --arg t "$rt" --arg id "$rid" '{kind:"cleanup",operation:$op,resourceType:$t,resourceID:$id,status:"success"}' >>"$LEDGER";done < <(jq -c '.cleanup[]' "$MANIFEST"); }
dry_chaos_receipt(){ local row=$1; jq -nc --argjson row "$row" '{schema:$row.receiptSchema,rowID:$row.id,status:"dry-run",fixtureOnly:true}' >"$ROOT/receipts/chaos-$(jq -r .id <<<"$row").json"; }
structured_chaos_receipt(){ local label=$1 op=$2 id=$3 direction=$4 required=$5 deadline=$6 convergence=$7 log="$ROOT/$label.log" receipt witness_digest canonical_digest expected_witness; expected_witness="$(jq -er --arg id "$id" '.chaos | to_entries[] | select(.value.id==$id) | (.key+1)' "$MANIFEST")"; receipt="$(jq -eRsc --arg op "$op" --arg id "$id" --arg direction "$direction" --arg run_uuid "$CAMPAIGN_RUN_UUID" --arg all_masters "$(jq -er '.qualification.allMastersOperationUUID' "$MANIFEST")" --argjson probes "$(jq -c '[.qualification.probeDeploymentIDs.ewr,.qualification.probeDeploymentIDs.ord,.qualification.probeDeploymentIDs.lan]' "$MANIFEST")" --argjson required "$required" --argjson deadline "$deadline" --argjson convergence "$convergence" --argjson expected_witness "$expected_witness" '
 [split("\n")[] | try fromjson catch empty | select(type=="object") | select(.success==true and .operation==$op and .rowID==$id and .completed==true and (.receipt|type=="object")) | .receipt |
   . as $receipt | select(
     .protocolVersion==4 and .runUUID==$run_uuid and .rowID==$id and .direction==$direction and
     .allMastersOperationUUID==$all_masters and (.applicationReceipts|type=="array") and (.applicationReceipts|length)==3 and
     ([.applicationReceipts[].clusterUUID]|unique|length)==3 and
     ([.applicationReceipts[].deploymentID])==$probes and
     all(.applicationReceipts[]; (.clusterUUID|type=="string" and test("^[0-9a-f]{32}$")) and (.deploymentID|type=="number" and floor==. and .>0) and (.witnessDigest|type=="string" and test("^[0-9a-f]{64}$"))) and
     (.startedAtMilliseconds|type=="number" and floor==. and .>0) and
     (.deadlineAtMilliseconds == (.startedAtMilliseconds + ($deadline * 1000))) and
     (.convergenceDeadlineAtMilliseconds == (.startedAtMilliseconds + ($convergence * 1000))) and
     (.observedAtMilliseconds|type=="number" and floor==.) and
     .observedAtMilliseconds>=.startedAtMilliseconds and .observedAtMilliseconds<=.convergenceDeadlineAtMilliseconds and
     .deadlineSeconds==$deadline and .convergenceSeconds==$convergence and
     (.witnessedResult|type=="number" and floor==. and .==$expected_witness) and
     (.canonicalConvergenceWitness|type=="string" and startswith("nametag-qualification-v4:" + $id + ":") and length>0) and
     (.witnessDigest|type=="string" and test("^[0-9a-f]{64}$")) and
     all($required[]; . as $field | $receipt | has($field)))] | last // empty' "$log")" || return
 witness_digest="$(jq -r '.witnessDigest' <<<"$receipt")"
 canonical_digest="$(jq -jr '.canonicalConvergenceWitness' <<<"$receipt" | sha256sum | cut -d' ' -f1)"
 [[ $witness_digest == "$canonical_digest" ]] || return
 printf '%s\n' "$receipt"; }
run_chaos(){
 local row id deadline convergence; while IFS= read -r row; do
   id=$(jq -r .id <<<"$row"); deadline=$(jq -r .deadlineSeconds <<<"$row"); convergence=$(jq -r .convergenceSeconds <<<"$row")
   (( deadline > 0 && convergence > 0 && convergence <= deadline )) || die "chaos $id invalid bounds"
   local part op rt rid args label direction
   for part in injection observation; do
     op=$(jq -r ".$part.operation" <<<"$row"); rt=$(jq -r ".$part.resourceType" <<<"$row"); rid=$(jq -r ".$part.resourceID" <<<"$row"); args=$(arguments_for "$(jq -c ".$part" <<<"$row")"); label=$(jq -r ".$part.label" <<<"$row")
     resource "$rt" "$rid" || die "chaos $id unknown resource"
     compatible "$op" "$rt" || die "chaos $id incompatible $op:$rt"
     call "$label" "$op" "$args"
     direction=$part
     if (( ! DRY )); then
       structured_chaos_receipt "$label" "$op" "$id" "$direction" "$(jq -c .receiptSchema.required <<<"$row")" "$deadline" "$convergence" >/dev/null || die "chaos $id $part lacks a completed typed v4 Mothership receipt"
     fi
   done
   if ((DRY)); then
     dry_chaos_receipt "$row"
   else
     structured_chaos_receipt "$label" "$op" "$id" "$direction" "$(jq -c .receiptSchema.required <<<"$row")" "$deadline" "$convergence" >"$ROOT/receipts/chaos-$id.json"
   fi
 done < <(jq -c '.chaos[]' "$MANIFEST")
}
schema; canonical_prefixes || die 'manifest has a non-canonical IPv6 /96'
if ((LIVE && !DRY)); then
 live_ready || die 'manifest is fixture-only or has unresolved live command arguments'
 ((CLEAN)) || qualification_capabilities
fi
init
if ((CLEAN));then cleanup;exit 0;fi
# Provisioning may precede manifest materialization: machine UUIDs only exist
# after Mothership creates the fleet. Qualify that already-owned deployment
# without inventing creation evidence or importing its cleanup ownership.
if ((EXISTING)); then
 if ((!DRY)); then
   "$M" help >"$ROOT/mothership-help.txt" 2>&1 || die 'help failed'
   while read -r operation; do
     grep -Fq -- "$operation" "$ROOT/mothership-help.txt" || die "Mothership lacks required operation $operation"
   done < <({ jq -r '.commands[] | select(.phase=="preflight" or .phase=="chaos" or .phase=="final-verify") | .operation' "$MANIFEST";
             jq -r '.chaos[].injection.operation,.chaos[].observation.operation' "$MANIFEST";
             echo prepareNametagAllMasters; } | sort -u)
   # Existing mode may only inspect the selected endpoints and verify the
   # production-owned all-masters seed operation before dispatching faults.
   jq -e 'all(.commands[] | select(.phase=="preflight" or .phase=="chaos" or .phase=="final-verify");
     .operation=="clusterReport" or .operation=="applicationReport" or .operation=="nametagAllMasters")' "$MANIFEST" >/dev/null ||
     die 'existing qualification phase contains provisioning or cleanup'
 fi
 run_phase preflight
 ((DRY)) || prepare_all_masters
 run_phase chaos
 run_chaos
 run_phase final-verify
 exit 0
fi
if ((DRY));then for p in "${phases[@]}";do run_phase "$p"; [[ $p == chaos ]] && run_chaos; done;cleanup;exit 0;fi
"$M" help >"$ROOT/mothership-help.txt" 2>&1 || die 'help failed'; while read -r o;do grep -Fq -- "$o" "$ROOT/mothership-help.txt"||die "Mothership lacks required operation $o";done < <({ jq -r '.commands[].operation,.cleanup[].operation,.chaos[].injection.operation,.chaos[].observation.operation' "$MANIFEST"; echo prepareNametagAllMasters; }|sort -u)
for p in "${phases[@]}";do run_phase "$p"; [[ $p == bgp ]] && prepare_all_masters; [[ $p == chaos ]] && run_chaos; done
cleanup
