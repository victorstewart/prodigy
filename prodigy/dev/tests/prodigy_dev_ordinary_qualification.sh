#!/usr/bin/env bash
# One fixed ordinary no-migration scenario. Mothership owns all mutation.
set -Eeuo pipefail
if [[ "${1:-}" == --validate-only && $# = 1 ]]; then bash -n "$0"; exit 0; fi
ORIGINAL_ARGS=("$@"); PRODIGY_BIN=${1:-}; MOTHERSHIP_BIN=${2:-}; PINGPONG_BIN=${3:-}; shift $(( $# >= 3 ? 3 : $# ))
OBSERVER_MOTHERSHIP=$MOTHERSHIP_BIN; INITIAL_BUNDLE=
while (($#)); do case "$1" in --observer-mothership) OBSERVER_MOTHERSHIP=$2; shift 2;; --initial-bundle) INITIAL_BUNDLE=$2; shift 2;; *) echo "usage: $0 prodigy mothership pingpong [--observer-mothership PATH] [--initial-bundle PATH]" >&2; exit 2;; esac; done
[[ -x "$PRODIGY_BIN" && -x "$MOTHERSHIP_BIN" && -x "$PINGPONG_BIN" && -x "$OBSERVER_MOTHERSHIP" && ( -z "$INITIAL_BUNDLE" || -r "$INITIAL_BUNDLE" ) ]] || exit 2
[[ $EUID = 0 ]] || { echo "SKIP: Mothership test clusters require root" >&2; exit 77; }
for x in date jq mktemp python3 readlink rg sha256sum sleep timeout uname; do command -v "$x" >/dev/null || exit 77; done
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"; REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd -P)"
source "$SCRIPT_DIR/prodigy_dev_discombobulator_artifact_helpers.sh"
SELF="$(readlink -f "${BASH_SOURCE[0]}")"; prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_ORDINARY_MOUNT_NS_READY bash "$SELF" "${ORIGINAL_ARGS[@]}"
PRODIGY_BIN="$(readlink -f "$PRODIGY_BIN")"; MOTHERSHIP_BIN="$(readlink -f "$MOTHERSHIP_BIN")"; PINGPONG_BIN="$(readlink -f "$PINGPONG_BIN")"; OBSERVER_MOTHERSHIP="$(readlink -f "$OBSERVER_MOTHERSHIP")"; [[ -z "$INITIAL_BUNDLE" ]] || INITIAL_BUNDLE="$(readlink -f "$INITIAL_BUNDLE")"
case "$(uname -m)" in x86_64) ARCH=x86_64;; aarch64|arm64) ARCH=aarch64;; *) exit 77;; esac
BUNDLE="$(dirname "$PRODIGY_BIN")/prodigy.$ARCH.bundle.tar.zst"; [[ -r "$BUNDLE" ]] || exit 1
ROOT="$(mktemp -d "$REPO_ROOT/.run/prodigy-ordinary.XXXXXX")"; mkdir -p "$ROOT/share/prodigy"; ln "$BUNDLE" "$ROOT/share/prodigy/prodigy.$ARCH.bundle.tar.zst"; [[ -r "$BUNDLE.sha256" ]] && ln "$BUNDLE.sha256" "$ROOT/share/prodigy/prodigy.$ARCH.bundle.tar.zst.sha256"; export XDG_DATA_HOME="$ROOT/share"; DB="$ROOT/mothership.tidesdb"; C="ordinary-$$-$RANDOM"; W="$ROOT/workspace"; M="$W/test-cluster-manifest.json"; CREATED=0; REMOVED=0
mkdir -p "$ROOT/receipts"
observer_m() { local label=$1 seconds=$2 log=$3; shift 3; local start="$(date +%s%3N)" rc; if timeout "${seconds}s" env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$DB" "$OBSERVER_MOTHERSHIP" "$@" >"$log" 2>&1; then rc=0; else rc=$?; fi; jq -nc --arg label "$label" --arg operation "$1" --argjson status "$rc" --argjson startedMs "$start" --argjson endedMs "$(date +%s%3N)" --arg role observer '{label:$label,operation:$operation,status:$status,startedMs:$startedMs,endedMs:$endedMs,role:$role}' >"$ROOT/receipts/$label-$start.json"; return "$rc"; }
m() { local label=$1 seconds=$2 log=$3; shift 3; local start="$(date +%s%3N)" rc; if timeout "${seconds}s" env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$DB" "$MOTHERSHIP_BIN" "$@" >"$log" 2>&1; then rc=0; else rc=$?; fi; jq -nc --arg label "$label" --arg operation "$1" --argjson status "$rc" --argjson startedMs "$start" --argjson endedMs "$(date +%s%3N)" '{label:$label,operation:$operation,status:$status,startedMs:$startedMs,endedMs:$endedMs}' >"$ROOT/receipts/$label-$start.json"; return "$rc"; }
ok() { rg -q "(^|[[:space:]])$2[[:space:]].*success=1([[:space:]]|$)" "$1"; }
copy_logs() { [[ -r "$M" ]] || return 0; mkdir -p "$ROOT/logs"; cp -p "$M" "$ROOT/logs/manifest.json"; while IFS=$'\t' read -r i role out err; do [[ -r "$out" ]] && cp -p "$out" "$ROOT/logs/machine$i.$role.out"; [[ -r "$err" ]] && cp -p "$err" "$ROOT/logs/machine$i.$role.err"; done < <(jq -r '.nodes[]|[.index,.role,.stdoutLog,(.stderrLog // "")]|@tsv' "$M"); return 0; }
cleanup() {
   local rc=$?
   trap - EXIT HUP INT TERM
   set +e
   # Let the bounded observer release its registry/provider ownership first.
   if [[ -n "${TRAFFIC_PID:-}" ]]; then
      wait "$TRAFFIC_PID" || rc=1
      TRAFFIC_PID=
   fi
   copy_logs || rc=1
   if ((CREATED && !REMOVED)); then
      m remove 180 "$ROOT/remove.log" removeCluster "$C" && ok "$ROOT/remove.log" removeCluster || rc=1
   fi
   [[ ! -e "$M" ]] || rc=1
   jq -nc --argjson exitCode "$rc" '{exitCode:$exitCode}' >"$ROOT/result.json"
   printf 'ORDINARY_EVIDENCE=%s\n' "$ROOT"
   exit "$rc"
}
trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
request() { jq -nc --arg name "$C" --arg workspace "$W" '{name:$name,deploymentMode:"test",nBrains:3,autoscaleIntervalSeconds:180,machineSchemas:[{schema:"ordinary-machine",kind:"vm",vmImageURI:"test://virtual-datacenter"}],test:{workspaceRoot:$workspace,machineCount:3,machineLogicalCores:4,machineMemoryMB:8192,machineStorageMB:8192,brainBootstrapFamily:"ipv4",enableFakeIpv4Boundary:false,interContainerMTU:9000}}'; }
ready() { [[ $(rg -c '^\s*Machine: state=healthy role=brain ' "$1" || true) = 3 && $(rg -c '^\s*lifecycle controlPlaneReachable=1 runtimeReady=1 ' "$1" || true) = 3 && $(rg -c '^\s*lifecycle .*currentMaster=1([[:space:]]|$)' "$1" || true) = 1 ]]; }
report() { m "report-$1" 8 "$ROOT/$1.cluster-report.log" clusterReport "$C"; }
local_report() { local label=$1 socket; socket="$(jq -er '.controlSocketPath | select(type == "string" and length > 0)' "$M")"; PRODIGY_MOTHERSHIP_SOCKET="$socket" timeout 8 "$MOTHERSHIP_BIN" clusterReport local >"$ROOT/$label.cluster-report.log" 2>&1; }
wait_ready() { local label=$1 end=$(( $(date +%s%3N)+120000 )); while (( $(date +%s%3N)<end )); do report "$label" && ready "$ROOT/$label.cluster-report.log" && return; sleep .25; done; return 1; }
master() { python3 - "$1" <<'PY'
import pathlib,re,sys
for b in re.findall(r'(?ms)^\s*Machine:.*?(?=^\s*Machine:|\Z)',pathlib.Path(sys.argv[1]).read_text()):
 a=re.search(r'(?m)^\s*identity uuid=((?:0x)?[0-9a-fA-F]+).*sshAddress=(\S+)',b)
 if a and re.search(r'(?m)^\s*lifecycle .*\bcurrentMaster=1(?:\s|$)',b): print(int(a.group(2).rsplit('.',1)[-1])-9,hex(int(a.group(1),16)),sep='\t'); break
else: raise SystemExit(1)
PY
}
app_ok() { python3 - "$1" <<'PY'
import pathlib,re,sys
s=pathlib.Path(sys.argv[1]).read_text(); assert len(re.findall(r'^\s*versionID:',s,re.M))==1; assert len(re.findall(r'^\s*state:\s*DeploymentState::running\s*$',s,re.M))==1
for k in ('nTarget','nDeployed','nHealthy'): assert re.findall(r'^\s*'+k+r':\s*1\s*$',s,re.M),k
v=re.findall(r'^\s*nCrashes:\s*([0-9]+)\s*$',s,re.M); assert len(v)==1; print(v[0])
PY
}
app_report() { m "app-$1" 8 "$ROOT/$1.app-report.log" applicationReport "$C" "$APP"; }
local_app_report() { local label=$1 socket; socket="$(jq -er ' .controlSocketPath | select(type == "string" and length > 0)' "$M")"; PRODIGY_MOTHERSHIP_SOCKET="$socket" timeout 8 "$MOTHERSHIP_BIN" applicationReport local "$APP" >"$ROOT/$label.app-report.log" 2>&1; }
wait_app() { local label=$1 end=$(( $(date +%s%3N)+120000 )); while (( $(date +%s%3N)<end )); do app_report "$label" && app_ok "$ROOT/$label.app-report.log" >/dev/null && return; sleep .25; done; return 1; }
traffic() { local label=$1 count=$2 interval=$3 rc=0; observer_m "traffic-$label" 611 "$ROOT/$label.traffic.log" probeTestClusterTraffic "$C" "$TRAFFIC_ADDRESS" 19090 ping pong 1000 0 4 "$count" "$interval" || rc=$?; python3 "$SCRIPT_DIR/prodigy_dev_ordinary_traffic_metrics.py" "$ROOT/$label.traffic.log" --clients 4 --requests-per-client "$count" --bucket 600 --label "$label" >"$ROOT/$label.metrics.json"; [[ $rc = 0 ]]; }
select_traffic_address() {
   local label=$1 address index=0
   while IFS= read -r address; do
      index=$((index + 1))
      if m "discover-$label-$index" 3 "$ROOT/$label.discovery-$index.log" \
         probeTestCluster "$C" "$address" 19090 ping pong 1500 0; then
         TRAFFIC_ADDRESS=$address
         printf '%s\n' "$address" >"$ROOT/$label.traffic-address.txt"
         return 0
      fi
   done < <(jq -er '.nodes[].ipv4' "$M")
   echo "FAIL: standard pingpong endpoint unavailable" >&2
   return 1
}
sample() { local label=$1; python3 "$SCRIPT_DIR/prodigy_dev_ordinary_resource_snapshot.py" --workspace "$W" --application-report "$ROOT/$label.app-report.log" >"$ROOT/$label.resources.json"; }
sha256sum "$PRODIGY_BIN" "$MOTHERSHIP_BIN" "$OBSERVER_MOTHERSHIP" "$PINGPONG_BIN" "$BUNDLE" >"$ROOT/artifact-identities.sha256"; printf "runtimeMothership=%s\nobserverMothership=%s\ninitialBundle=%s\n" "$MOTHERSHIP_BIN" "$OBSERVER_MOTHERSHIP" "${INITIAL_BUNDLE:-default-sibling-bundle}" >"$ROOT/control-identities.txt"; observer_m observer-help 15 "$ROOT/observer-help.log" help; rg -q "probeTestClusterTraffic" "$ROOT/observer-help.log"; m runtime-help 15 "$ROOT/runtime-help.log" help; if [[ -n "$INITIAL_BUNDLE" ]]; then rg -q "optional test initial bundle" "$ROOT/runtime-help.log" || { echo "runtime Mothership does not advertise optional initial bundle" >&2; exit 1; }; fi; request >"$ROOT/create.json"; CREATED=1; m create 180 "$ROOT/create.log" createCluster "$(<"$ROOT/create.json")" ${INITIAL_BUNDLE:+"$INITIAL_BUNDLE"}; wait_ready ready
python3 "$SCRIPT_DIR/prodigy_dev_ordinary_resource_snapshot.py" --workspace "$W" >"$ROOT/ready.resources.json"
APP="OrdinaryPing-$RANDOM"; m reserve 30 "$ROOT/reserve.log" reserveApplicationID "$C" "$(jq -nc --arg applicationName "$APP" '{applicationName:$applicationName,createIfMissing:true}')"; APPID="$(rg -m1 -o 'appID=[1-9][0-9]*' "$ROOT/reserve.log"|sed 's/appID=//')"; [[ "$APPID" =~ ^[1-9][0-9]*$ ]]; m reserve-service 30 "$ROOT/reserve-service.log" reserveServiceID "$C" "$(jq -nc --arg applicationName "$APP" --arg serviceName server --arg kind stateless --argjson applicationID "$APPID" '{applicationName:$applicationName,applicationID:$applicationID,serviceName:$serviceName,kind:$kind,createIfMissing:true}')"
BLOB="$(dirname "$PRODIGY_BIN")/prodigy-pingpong.$ARCH.container.zst"; [[ -r "$BLOB" ]] || { echo "missing frozen standard pingpong artifact: $BLOB" >&2; exit 1; }; sha256sum "$BLOB" >"$ROOT/standard-artifact.sha256"
jq -nc --argjson app "$APPID" --arg arch "$ARCH" --arg application "$APP" '{config:{type:"ApplicationType::stateless",applicationID:$app,versionID:1,architecture:$arch,filesystemMB:64,storageMB:64,rootFilesystemReadOnly:false,runAsID:0,memoryMB:256,nLogicalCores:1,msTilHealthy:10000,sTilHealthcheck:15,sTilKillable:30},useHostNetworkNamespace:true,apiCredentials:{applicationID:$app,requiredCredentialNames:[]},minimumSubscriberCapacity:1024,isStateful:false,stateless:{nBase:1,maxPerRackRatio:1.0,maxPerMachineRatio:1.0,moveableDuringCompaction:true},advertisements:[{service:("${service:"+$application+"/server}"),startAt:"ContainerState::scheduled",stopAt:"ContainerState::destroying",port:19090}],moveConstructively:true,requiresDatacenterUniqueTag:false}' >"$ROOT/plan.json"
m deploy 180 "$ROOT/deploy.log" deploy "$C" "$(cat "$ROOT/plan.json")" "$BLOB"
rg -q 'SpinApplicationResponseCode::okay$' "$ROOT/deploy.log"
wait_app deployed
select_traffic_address pre
traffic pre 150 0
report pre-fault
app_report pre-fault
sample pre-fault
PRE_FAULT_CRASHES="$(app_ok "$ROOT/pre-fault.app-report.log")"
[[ "$PRE_FAULT_CRASHES" = 0 ]]
IFS=$'\t' read -r old_index old_uuid < <(master "$ROOT/pre-fault.cluster-report.log")
m fault 45 "$ROOT/fault.log" faultTestCluster "$C" crash "$old_index" 3000 0 0 0
ok "$ROOT/fault.log" faultTestCluster
wait_ready recovered
wait_app recovered
sample recovered
IFS=$'\t' read -r new_index new_uuid < <(master "$ROOT/recovered.cluster-report.log")
[[ "$new_uuid" != "$old_uuid" ]]
BASE_CRASHES="$(app_ok "$ROOT/recovered.app-report.log")"
printf 'oldMasterUUID=%s newMasterUUID=%s preFaultCrashes=%s recoveredWorkloadCrashes=%s faultWindowCrashDelta=%s\n' \
   "$old_uuid" "$new_uuid" "$PRE_FAULT_CRASHES" "$BASE_CRASHES" "$((BASE_CRASHES-PRE_FAULT_CRASHES))" >"$ROOT/fault.txt"
select_traffic_address post
traffic post 150 0
# One continuous 20-minute command; reports use the read-only local socket.
# The owner permits 1201s of scheduled work plus 10s cleanup; leave a wrapper margin.
observer_m soak-traffic 1220 "$ROOT/soak.traffic.log" probeTestClusterTraffic \
   "$C" "$TRAFFIC_ADDRESS" 19090 ping pong 1000 0 4 12000 100 &
TRAFFIC_PID=$!
origin=$(python3 -c 'import time; print(time.monotonic_ns())')
for minute in $(seq 1 20); do
   python3 - "$origin" "$minute" <<'WAIT'
import sys,time
deadline=int(sys.argv[1])+int(sys.argv[2])*60_000_000_000
time.sleep(max(0,(deadline-time.monotonic_ns())/1e9))
WAIT
   local_report "soak-$minute"
   ready "$ROOT/soak-$minute.cluster-report.log"
   local_app_report "soak-$minute"
   [[ "$(app_ok "$ROOT/soak-$minute.app-report.log")" = "$BASE_CRASHES" ]]
   sample "soak-$minute"
done
traffic_status=0
wait "$TRAFFIC_PID" || traffic_status=$?
TRAFFIC_PID=
python3 "$SCRIPT_DIR/prodigy_dev_ordinary_traffic_metrics.py" "$ROOT/soak.traffic.log" \
   --clients 4 --requests-per-client 12000 --bucket 600 --label soak >"$ROOT/soak.metrics.json"
[[ "$traffic_status" = 0 ]]
copy_logs
m remove 180 "$ROOT/remove.log" removeCluster "$C"
ok "$ROOT/remove.log" removeCluster
REMOVED=1
