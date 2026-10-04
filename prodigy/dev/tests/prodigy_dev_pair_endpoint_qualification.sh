#!/usr/bin/env bash
# Bounded Mothership-client VIP handoff observations; not a migration claim.
set -Eeuo pipefail
if [[ "${1:-}" == "--validate-only" && "$#" = 1 ]]; then bash -n "$0"; exit 0; fi
PRODIGY_BIN="${1:-}"; MOTHERSHIP_BIN="${2:-}"; PINGPONG_BIN="${3:-}"
MODE="${4:-endpoint}"
[[ ( $# = 3 || $# = 4 ) && ( "$MODE" = endpoint || "$MODE" = admission || "$MODE" = admission-master-crash || "$MODE" = admission-cold || "$MODE" = admission-source-crash ) && -x "$PRODIGY_BIN" && -x "$MOTHERSHIP_BIN" && -x "$PINGPONG_BIN" ]] || { echo "usage: $0 prodigy mothership pingpong [endpoint|admission|admission-master-crash|admission-cold|admission-source-crash]" >&2; exit 2; }
[[ $EUID = 0 ]] || { echo "SKIP: Mothership test clusters require root" >&2; exit 77; }
for x in awk cat date jq mktemp python3 readlink rg sed sha256sum sleep timeout uname; do command -v "$x" >/dev/null || { echo "SKIP: missing $x" >&2; exit 77; }; done
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd -P)"
source "$SCRIPT_DIR/prodigy_dev_discombobulator_artifact_helpers.sh"
SCRIPT_SELF="$(readlink -f "${BASH_SOURCE[0]}")"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_PAIR_ENDPOINT_MOUNT_NS_READY bash "$SCRIPT_SELF" "$@"
PRODIGY_BIN="$(readlink -f "$PRODIGY_BIN")"; MOTHERSHIP_BIN="$(readlink -f "$MOTHERSHIP_BIN")"; PINGPONG_BIN="$(readlink -f "$PINGPONG_BIN")"
[[ "$(dirname "$PRODIGY_BIN")" = "$(dirname "$MOTHERSHIP_BIN")" ]] || { echo "FAIL: release binaries are not siblings" >&2; exit 1; }
case "$(uname -m)" in x86_64) ARCH=x86_64;; aarch64|arm64) ARCH=aarch64;; riscv64) ARCH=riscv64;; *) exit 77;; esac
[[ -r "$(dirname "$PRODIGY_BIN")/prodigy.$ARCH.bundle.tar.zst" ]] || { echo "FAIL: missing sibling bundle" >&2; exit 1; }
BUNDLE="$(dirname "$PRODIGY_BIN")/prodigy.$ARCH.bundle.tar.zst"
EXPECTED_BUNDLE_SHA256="$(sha256sum "$BUNDLE" | cut -d' ' -f1)"
ROOT="$(mktemp -d "$REPO_ROOT/.run/prodigy-pair-endpoint.XXXXXX")"; DB="$ROOT/mothership.tidesdb"; mkdir -p "$ROOT/receipts"
S="pair-source-$$-$RANDOM"; T="pair-target-$$-$RANDOM"; SW="$ROOT/source-workspace"; TW="$ROOT/target-workspace"; SM="$SW/test-cluster-manifest.json"; TM="$TW/test-cluster-manifest.json"
OP="$(python3 - <<'PY'
import secrets
n=secrets.randbits(128) or 1
print("0x"+n.to_bytes((n.bit_length()+7)//8,"big").hex())
PY
)"; BAD="$(python3 - "$OP" <<'PY'
import sys
n=(int(sys.argv[1],16)^1) or 2
print("0x"+n.to_bytes((n.bit_length()+7)//8,"big").hex())
PY
)"
SA=0; TA=0; OPEN=0; HELD=; SOURCE_SAMPLER=; RETIRE_PID=; RC="$ROOT/held.rc"; VIP=198.18.0.1; PORT=19090
printf 'scenario=pair-%s migrationCoverage=0 vip=%s port=%s sourceMachineIndex=1 targetMachineIndex=1\n' "$MODE" "$VIP" "$PORT" >"$ROOT/scenario.txt"
sha256sum "$PRODIGY_BIN" "$MOTHERSHIP_BIN" "$PINGPONG_BIN" "$BUNDLE" >"$ROOT/artifact-identities.sha256"
m() { local l=$1 sec=$2 log=$3; shift 3; local a b st op=$1; a=$(date +%s%3N); if timeout "${sec}s" env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$DB" "$MOTHERSHIP_BIN" "$@" >"$log" 2>&1; then st=0; else st=$?; fi; b=$(date +%s%3N); jq -nc --arg label "$l" --arg operation "$op" --argjson status "$st" --argjson startedMs "$a" --argjson endedMs "$b" '{label:$label,operation:$operation,status:$status,startedMs:$startedMs,endedMs:$endedMs}' >"$ROOT/receipts/$l-$a-$BASHPID.json"; return "$st"; }
ok() {
   rg -q "(^|[[:space:]])$2[[:space:]].*success=1([[:space:]]|$)" "$1"
}
accepted_deploy() {
   rg -q 'SpinApplicationResponseCode::okay$' "$1"
}
expect_reason() {
   local log="$1" reason="$2"
   shift 2
   if m "reject-$(basename "$log" .log)" 30 "$log" "$@"; then
      echo "FAIL: expected rejection: $*" >&2
      return 1
   fi
   rg -Fq "failure=$reason" "$log"
}
copy_cluster_observations() {
   local label="$1" manifest="$2" out="$ROOT/$1-logs" index role stdout stderr
   [[ -s "$manifest" ]] || return 0
   mkdir -p "$out"
   cp -p "$manifest" "$out/test-cluster-manifest.json" 2>/dev/null || true
   while IFS=$'\t' read -r index role stdout stderr; do
      [[ -r "$stdout" ]] && cp -p "$stdout" "$out/machine${index}.${role}.stdout.log" 2>/dev/null || true
      [[ -r "$stderr" ]] && cp -p "$stderr" "$out/machine${index}.${role}.stderr.log" 2>/dev/null || true
   done < <(jq -r '.nodes[] | [.index, .role, .stdoutLog, .stderrLog] | @tsv' "$manifest" 2>/dev/null)
}

# These copies are read-only evidence and must precede every Mothership remove;
# the provider owns process and namespace cleanup after that command.
copy_pair_observations() {
   copy_cluster_observations source "$SM"
   copy_cluster_observations target "$TM"
}

rmcluster() {
   if m "remove-$1" 120 "$2" removeCluster "$1"; then
      ok "$2" removeCluster
   else
      rg -q "removeCluster success=0 removed=0 identity=$1 failure=record not found" "$2"
   fi
}

cleanup() {
   local st=$?
   trap - EXIT HUP INT TERM
   set +e
   [[ -z "$HELD" ]] || wait "$HELD" || st=1
   if [[ -n "$SOURCE_SAMPLER" ]]; then
      : >"$ROOT/source-fault-sampler.stop"
      wait "$SOURCE_SAMPLER" || st=1
   fi
   # A bounded retirement client can own the pair lifecycle lock; do not remove
   # its boundary or either cluster until that client has returned.
   if [[ -n "$RETIRE_PID" ]]; then
      wait "$RETIRE_PID" || st=1
      RETIRE_PID=
   fi
   copy_pair_observations
   [[ $OPEN != 1 ]] || {
      m boundary-remove-cleanup 180 "$ROOT/boundary-remove-cleanup.log" pairBoundary "$OP" remove &&
         ok "$ROOT/boundary-remove-cleanup.log" pairBoundary || st=1
   }
   [[ $SA != 1 ]] || rmcluster "$S" "$ROOT/remove-source-cleanup.log" || st=1
   [[ $TA != 1 ]] || rmcluster "$T" "$ROOT/remove-target-cleanup.log" || st=1
   [[ ! -e "$SM" && ! -e "$TM" ]] || st=1
   jq -nc --arg result "$( [[ "$st" = 0 ]] && echo pass || echo fail )" --arg operationID "$OP" \
      '{result:$result,operationID:$operationID}' >"$ROOT/result.json"
   echo "PAIR_ENDPOINT_EVIDENCE=$ROOT"
   exit "$st"
}
trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
request() { jq -nc --arg name "$1" --arg workspace "$2" '{name:$name,deploymentMode:"test",nBrains:3,autoscaleIntervalSeconds:180,machineSchemas:[{schema:"pair-machine",kind:"vm",vmImageURI:"test://virtual-datacenter"}],test:{workspaceRoot:$workspace,machineCount:3,machineLogicalCores:4,machineMemoryMB:8192,machineStorageMB:8192,brainBootstrapFamily:"ipv4",enableFakeIpv4Boundary:false,interContainerMTU:9000}}'; }
create() { local q; q="$(request "$1" "$2")"; printf '%s\n' "$q" >"$ROOT/$1-request.json"; m "create-$1" 180 "$3" createCluster "$q" && ok "$3" createCluster; }
ready() {
   [[ $(rg -c '^[[:space:]]*Machine: state=healthy role=brain ' "$1" || true) = 3 &&
      $(rg -c '^[[:space:]]*lifecycle controlPlaneReachable=1 runtimeReady=1 ' "$1" || true) = 3 &&
      $(rg -c '^[[:space:]]*lifecycle .*currentMaster=1([[:space:]]|$)' "$1" || true) = 1 &&
      $(rg -c "approvedBundleSHA256=$EXPECTED_BUNDLE_SHA256 " "$1" || true) = 3 ]]
}
waitready() { local end=$(( $(date +%s%3N)+120000 )) r="$ROOT/$2-report.log"; while [[ $(date +%s%3N) -lt $end ]]; do m "report-$2" 8 "$r" clusterReport "$1" && ready "$r" && return; sleep .25; done; sed -n '1,220p' "$r" >&2; return 1; }
uuid() { python3 - "$1" "$2" <<'PY'
import json,pathlib,re,sys
r,m=pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2])
a=next(x["ipv4"] for x in json.loads(m.read_text())["nodes"] if int(x["index"])==1)
for b in re.findall(r"(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)",r.read_text()):
 q=re.search(r"(?m)^[ \t]*identity uuid=((?:0x)?[0-9a-fA-F]+) .*sshAddress=(\S+)",b)
 if q and q.group(2)==a: print(hex(int(q.group(1),16))); break
else: raise SystemExit(1)
PY
}
reserve() { local q id; q="$(jq -nc --arg applicationName "$2" '{applicationName:$applicationName,createIfMissing:true}')"; m "reserve-$1-$2" 30 "$3" reserveApplicationID "$1" "$q" && ok "$3" reserveApplicationID || return; id=$(rg -m1 -o 'appID=[1-9][0-9]*' "$3"|sed 's/appID=//'); [[ $id =~ ^[1-9][0-9]*$ ]] && echo "$id"; }
did() { python3 - "$1" <<'PY'
import sys
print((int(sys.argv[1])<<48)|1)
PY
}
plan() { cat >"$1" <<EOF
{"config":{"type":"ApplicationType::stateless","applicationID":$2,"versionID":1,"architecture":"$ARCH","filesystemMB":64,"storageMB":64,"memoryMB":256,"nLogicalCores":1,"msTilHealthy":2000,"sTilHealthcheck":3,"sTilKillable":30},"apiCredentials":{"applicationID":$2,"requiredCredentialNames":[]},"useHostNetworkNamespace":false,"minimumSubscriberCapacity":1024,"isStateful":false,"stateless":{"nBase":1,"maxPerRackRatio":1.0,"maxPerMachineRatio":1.0,"moveableDuringCompaction":true},"wormholes":[{"name":"pair-endpoint","source":"registeredRoutablePrefix","routablePrefixUUID":"$3","externalPort":19090,"containerPort":19090,"layer4":"TCP","isQuic":false}],"moveConstructively":true,"requiresDatacenterUniqueTag":false}
EOF
}
# The application report is a presentation format, so grep-based checks can
# accidentally accept 10 or two version blocks.  This verifier requires the
# one admitted version-1 runtime and exact one-container counters.
application_report_exact_one() {
   python3 - "$1" "$2" <<'PY2'
import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace')
crash_mode=sys.argv[2]
def exactly(pattern, expected):
    values=re.findall(pattern, text, re.M)
    assert values == [expected], (pattern, values)
assert len(re.findall(r'^\s*versionID:\s*1\s*$', text, re.M)) == 1
assert len(re.findall(r'^\s*versionID:', text, re.M)) == 1
exactly(r'\bnTarget:\s*([0-9]+)', '1')
exactly(r'^\s*nDeployed:\s*([0-9]+)\s*$', '1')
exactly(r'^\s*nHealthy:\s*([0-9]+)\s*$', '1')
runtimes=re.findall(r'^\s*containerRuntime:.*\buuid=([0-9]+)\s*$', text, re.M)
assert len(runtimes) == 1 and len(set(runtimes)) == 1, runtimes
crashes=re.findall(r'^\s*nCrashes:\s*([0-9]+)\s*$', text, re.M)
assert len(crashes) == 1, crashes
if crash_mode == 'zero': assert crashes == ['0'], crashes
print(crashes[0])
PY2
}

source_report_retired() {
   python3 - "$1" <<'PY2'
import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace')
assert not re.search(r'(?m)^\s*containerRuntime:', text)
assert re.search(r'(?m)^\s*nDeployed:\s*0\s*$', text)
assert re.search(r'(?m)^\s*nHealthy:\s*0\s*$', text)
PY2
}

waitapp() {
   local end=$(( $(date +%s%3N)+120000 )) report="$ROOT/$3-app.log"
   while [[ $(date +%s%3N) -lt $end ]]; do
      if m "app-$3" 8 "$report" applicationReport "$1" "$2" &&
         application_report_exact_one "$report" zero >/dev/null 2>&1; then
         return 0
      fi
      sleep .25
   done
   sed -n '1,220p' "$report" >&2
   return 1
}

# A whole-machine provider fault proves a new machine incarnation from its
# receipt plus bootTimeMs; application crash counters are not the fault oracle
# because a cold restart can restore their checkpoint independently.
wait_recovered_target_app() {
   local end=$(( $(date +%s%3N)+120000 )) report="$ROOT/target-after-fault-app.log" crashes=""
   while [[ $(date +%s%3N) -lt $end ]]; do
      if m app-target-after-fault 8 "$report" applicationReport "$T" "PairTarget-${OP#0x}"; then
         crashes="$(application_report_exact_one "$report" any 2>/dev/null)" || { sleep .25; continue; }
         printf 'targetRecoveryCrashes=%s targetRecoveryExpectedCrash=checkpoint-dependent\n' "$crashes" >>"$ROOT/scenario.txt"
         return 0
      fi
      sleep .25
   done
   sed -n '1,220p' "$report" >&2
   return 1
}

faulted_cluster_incarnations_changed() {
   python3 - "$1" "$2" "$3" "$4" <<'PY2'
import json,pathlib,re,sys
before,after,manifest,indices=sys.argv[1:]
nodes={str(n['ipv4']): int(n['index']) for n in json.loads(pathlib.Path(manifest).read_text())['nodes']}
def boots(path):
    result={}
    text=pathlib.Path(path).read_text(encoding='utf-8',errors='replace')
    for block in re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)', text):
        address=re.search(r'(?m)^[ \t]*identity uuid=(?:0x)?[0-9a-fA-F]+ .*sshAddress=(\S+)', block)
        boot=re.search(r'(?m)^[ \t]*lifecycle .*\bbootTimeMs=([0-9]+)(?:\s|$)', block)
        if address and boot and address.group(1) in nodes: result[nodes[address.group(1)]]=int(boot.group(1))
    return result
old,new=boots(before),boots(after)
for index in map(int,indices.split(',')):
    assert index in old and index in new and old[index] != new[index], (index,old,new)
PY2
}

# Recovery prepares the existing pair router before the fault while its selector
# remains source.  The sampler uses that router's typed probe, which verifies
# pingpong's identity:<sequence> reply from the Neuron-provided deployment and
# container identity.  Each CLI owns only a brief registry read before its
# provider probe; no lifecycle lock is held.
source_fault_sampler() {
   local sequence=0 start end status log
   while [[ ! -e "$ROOT/source-fault-sampler.stop" ]]; do
      log="$ROOT/source-fault-probe-$sequence.log"
      start="$(date +%s%3N)"
      if m "source-fault-probe-$sequence" 8 "$log" probePairBoundary "$OP" "$AD" 1 0 &&
         ok "$log" probePairBoundary &&
         rg -q '^PAIR_BOUNDARY_REQUEST .*"ok": true' "$log"; then
         status=0
      else
         status=1
      fi
      end="$(date +%s%3N)"
      printf '%s\t%s\t%s\t%s\n' "$start" "$end" "$status" "$log" >>"$ROOT/source-fault-observations.tsv"
      : >"$ROOT/source-fault-sampler.ready"
      sequence=$((sequence + 1))
      sleep .1
   done
}

target_master_identity() {
   python3 - "$1" "$TM" <<'PY2'
import json,pathlib,re,sys
report=pathlib.Path(sys.argv[1]).read_text(encoding='utf-8',errors='replace')
nodes={str(node['ipv4']): int(node['index']) for node in json.loads(pathlib.Path(sys.argv[2]).read_text())['nodes']}
for block in re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)', report):
    address=re.search(r'(?m)^[ \t]*identity uuid=((?:0x)?[0-9a-fA-F]+) .*sshAddress=(\S+)', block)
    master=re.search(r'(?m)^[ \t]*lifecycle .*\bcurrentMaster=1(?:\s|$)', block)
    if address and master and address.group(2) in nodes:
        print(nodes[address.group(2)],hex(int(address.group(1),16)),sep='\t')
        raise SystemExit(0)
raise SystemExit(1)
PY2
}

archive_fault_phase() {
   local phase="$1" out file receipt
   local -a files receipts
   out="$ROOT/$phase"
   mkdir -p "$out/receipts"
   files=("$ROOT/target-before-fault-report.log" "$ROOT/target-master-fault.log"
      "$ROOT/source-fault-observations.tsv" "$ROOT/target-fault-window.tsv"
      "$ROOT/target-after-fault-report.log" "$ROOT/target-after-fault-app.log"
      "$ROOT/admit-target-after-fault.log" "$ROOT/prepare-target-after-fault.log"
      "$ROOT"/source-fault-probe-*.log)
   for file in "${files[@]}"; do
      [[ -e "$file" ]] && cp -p "$file" "$out/"
   done
   receipts=("$ROOT"/receipts/report-target-before-fault-*.json "$ROOT"/receipts/target-master-fault-*.json
      "$ROOT"/receipts/source-fault-probe-*.json "$ROOT"/receipts/app-target-after-fault-*.json
      "$ROOT"/receipts/admit-target-after-fault-*.json "$ROOT"/receipts/prepare-target-after-fault-*.json)
   for receipt in "${receipts[@]}"; do
      [[ -e "$receipt" ]] && cp -p "$receipt" "$out/receipts/"
   done
   return 0
}

uuid_is_greater() {
   python3 - "$1" "$2" <<'PY2'
import sys
raise SystemExit(0 if int(sys.argv[1], 16) > int(sys.argv[2], 16) else 1)
PY2
}


source_master_identity() {
   python3 - "$1" "$SM" <<'PY2'
import json,pathlib,re,sys
report=pathlib.Path(sys.argv[1]).read_text(encoding='utf-8',errors='replace')
nodes={str(node['ipv4']): int(node['index']) for node in json.loads(pathlib.Path(sys.argv[2]).read_text())['nodes']}
for block in re.findall(r"(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)", report):
    address=re.search(r'(?m)^[ \t]*identity uuid=((?:0x)?[0-9a-fA-F]+) .*sshAddress=(\S+)', block)
    master=re.search(r'(?m)^[ \t]*lifecycle .*\bcurrentMaster=1(?:\s|$)', block)
    if address and master and address.group(2) in nodes:
        print(nodes[address.group(2)],hex(int(address.group(1),16)),sep='\t')
        raise SystemExit(0)
raise SystemExit(1)
PY2
}

run_source_retirement_fault() {
   local before="$ROOT/source-before-retirement-fault-report.log" after="$ROOT/source-after-retirement-fault-report.log"
   local master old_uuid fault_start fault_end sealed_deadline retire_rc completed_ms
   m source-before-retirement-fault 30 "$before" clusterReport "$S" && ready "$before" || return 1
   IFS=$'\t' read -r master old_uuid < <(source_master_identity "$before") || return 1
   [[ "$master" =~ ^[1-3]$ ]] || return 1
   # This is deliberately before the retirement caller starts: that caller owns
   # TestPairLifecycleLock until it returns, so no pair probe may intervene.
   m target-before-source-fault 45 "$ROOT/target-before-source-fault.log" probePairBoundary "$OP" "$BD" 5 0 &&
      ok "$ROOT/target-before-source-fault.log" probePairBoundary && rg -q '"ok": true' "$ROOT/target-before-source-fault.log" || return 1
   # Preserve the first caller result. It must remain pending after the durable
   # fence appears; the later fresh caller is the same-operation recovery proof.
   ( set +e; m retire-source-first 210 "$ROOT/retire-source-first.log" retireTestPairSource "$OP"; rc=$?; printf '%s\n' "$rc" >"$ROOT/retire-source-first.rc"; exit 0 ) &
   RETIRE_PID=$!
   sealed_deadline=$(( $(date +%s%3N) + 60000 ))
   while [[ $(date +%s%3N) -lt $sealed_deadline ]]; do
      rg -q 'retireTestPairSource progress=sealed terminal=0' "$ROOT/retire-source-first.log" 2>/dev/null && break
      kill -0 "$RETIRE_PID" 2>/dev/null || { wait "$RETIRE_PID" || true; RETIRE_PID=; return 1; }
      sleep .05
   done
   rg -q 'retireTestPairSource progress=sealed terminal=0' "$ROOT/retire-source-first.log" 2>/dev/null || { wait "$RETIRE_PID" || true; RETIRE_PID=; return 1; }
   kill -0 "$RETIRE_PID" 2>/dev/null || { wait "$RETIRE_PID" || true; RETIRE_PID=; return 1; }
   fault_start="$(date +%s%3N)"
   m source-master-retirement-fault 45 "$ROOT/source-master-retirement-fault.log" faultTestCluster "$S" crash "$master" 3000 0 0 0 &&
      ok "$ROOT/source-master-retirement-fault.log" faultTestCluster || return 1
   fault_end="$(date +%s%3N)"
   printf 'sourceRetirementFaultKind=master oldMasterUUID=%s oldMasterIndex=%s faultStartMs=%s faultEndMs=%s sealedBeforeFault=1 firstCallerPending=1\n' \
      "$old_uuid" "$master" "$fault_start" "$fault_end" >>"$ROOT/scenario.txt"
   # The interrupted caller must fail without observing a terminal receipt. A
   # successful first caller would not prove the intended ambiguous-completion gate.
   wait "$RETIRE_PID" || true
   RETIRE_PID=
   [[ -s "$ROOT/retire-source-first.rc" ]] || return 1
   retire_rc="$(cat "$ROOT/retire-source-first.rc")"
   completed_ms="$(date +%s%3N)"
   [[ "$retire_rc" =~ ^[1-9][0-9]*$ ]] && ! rg -q 'sealed=1[[:space:]]+terminal=1([[:space:]]|$)' "$ROOT/retire-source-first.log" || return 1
   printf 'sourceRetirementFirstCallerStatus=%s sourceRetirementFirstCallerCompletedMs=%s firstCallerTerminalReceipt=0\n' \
      "$retire_rc" "$completed_ms" >>"$ROOT/scenario.txt"
   waitready "$S" source-after-retirement-fault || return 1
   faulted_cluster_incarnations_changed "$before" "$after" "$SM" "$master" || return 1
   m target-after-source-fault 45 "$ROOT/target-after-source-fault.log" probePairBoundary "$OP" "$BD" 5 0 &&
      ok "$ROOT/target-after-source-fault.log" probePairBoundary && rg -q '"ok": true' "$ROOT/target-after-source-fault.log" || return 1
   m retire-source-resume 210 "$ROOT/retire-source-resume.log" retireTestPairSource "$OP" &&
      ok "$ROOT/retire-source-resume.log" retireTestPairSource &&
      rg -q 'sealed=1[[:space:]]+terminal=1([[:space:]]|$)' "$ROOT/retire-source-resume.log" || return 1
}

run_target_admission_fault() {
   local kind="$1" phase="${2:-$1}" report="$ROOT/target-before-fault-report.log" master old_uuid indices fault_start fault_end sampler current current_uuid
   m report-target-before-fault 8 "$report" clusterReport "$T" && ready "$report" || return 1
   IFS=$'\t' read -r master old_uuid < <(target_master_identity "$report") || return 1
   [[ "$master" =~ ^[1-3]$ ]] || return 1
   if [[ "$kind" = cold ]]; then indices=1,2,3; else indices="$master"; fi
   printf 'targetFaultPhase=%s targetFaultKind=%s oldMasterUUID=%s oldMasterIndex=%s targetFaultIndices=%s wholeMachineRecovery=1 quorumContinuity=0 retainedRuntime=0\n' \
      "$phase" "$kind" "$old_uuid" "$master" "$indices" >>"$ROOT/scenario.txt"

   rm -f "$ROOT/source-fault-sampler.stop" "$ROOT/source-fault-sampler.ready" "$ROOT/source-fault-observations.tsv"
   source_fault_sampler & SOURCE_SAMPLER=$!
   sampler="$SOURCE_SAMPLER"
   local sampler_deadline=$(( $(date +%s%3N) + 15000 ))
   while [[ ! -e "$ROOT/source-fault-sampler.ready" && $(date +%s%3N) -lt $sampler_deadline ]]; do sleep .05; done
   [[ -e "$ROOT/source-fault-sampler.ready" ]] || { : >"$ROOT/source-fault-sampler.stop"; wait "$sampler" || true; SOURCE_SAMPLER=; return 1; }

   fault_start="$(date +%s%3N)"
   if ! m "target-$kind-fault" 45 "$ROOT/target-$kind-fault.log" faultTestCluster "$T" crash "$indices" 3000 0 0 0 ||
      ! ok "$ROOT/target-$kind-fault.log" faultTestCluster; then
      : >"$ROOT/source-fault-sampler.stop"; wait "$sampler" || true; SOURCE_SAMPLER=; return 1
   fi
   fault_end="$(date +%s%3N)"
   local post_deadline=$(( $(date +%s%3N) + 15000 )) post_observed=0
   while [[ $(date +%s%3N) -lt $post_deadline ]]; do
      if python3 - "$ROOT/source-fault-observations.tsv" "$fault_end" <<'PY2'
import pathlib,sys
end=int(sys.argv[2])
sys.exit(not any(int(line.split('	',1)[0]) >= end for line in pathlib.Path(sys.argv[1]).read_text().splitlines()))
PY2
      then
         post_observed=1
         break
      fi
      sleep .05
   done
   : >"$ROOT/source-fault-sampler.stop"
   wait "$sampler" || true
   SOURCE_SAMPLER=
   [[ "$post_observed" = 1 ]] || return 1
   printf '%s\t%s\t%s\t%s\n' "$fault_start" "$fault_end" "$kind" "$indices" >"$ROOT/target-fault-window.tsv"

   python3 - "$ROOT/source-fault-observations.tsv" "$fault_start" "$fault_end" <<'PY2'
import pathlib,sys
rows=[]
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    start,end,status,log=line.split('	',3)
    rows.append((int(start),int(end),int(status),log))
lo,hi=map(int,sys.argv[2:])
assert rows and any(row[0] < hi and row[1] > lo for row in rows), 'no source probe overlapped fault command interval'
assert all(row[2] == 0 for row in rows), 'a source probe failed before, during, or after fault command'
PY2

   waitready "$T" target-after-fault || return 1
   faulted_cluster_incarnations_changed "$report" "$ROOT/target-after-fault-report.log" "$TM" "$indices" || return 1
   if [[ "$kind" = master ]]; then
      IFS=$'\t' read -r current current_uuid < <(target_master_identity "$ROOT/target-after-fault-report.log") || return 1
      [[ "$current_uuid" != "$old_uuid" ]] || return 1
      FAULT_OLD_UUID="$old_uuid"; FAULT_CURRENT_UUID="$current_uuid"; FAULT_CURRENT_INDEX="$current"
      if uuid_is_greater "$current_uuid" "$old_uuid"; then
         FAULT_DIRECTION=oldmaster_dials_after_restart_second_fault_required
      else
         FAULT_DIRECTION=newmaster_canonical_connector_one_fault_sufficient
      fi
      printf 'targetFaultPhase=%s oldMasterUUID=%s currentMasterUUID=%s currentMasterIndex=%s observedConnectionDirection=%s\n' \
         "$phase" "$old_uuid" "$current_uuid" "$current" "$FAULT_DIRECTION" >>"$ROOT/scenario.txt"
   fi
   # Resume the durable operation before waiting for the application: replay
   # itself is allowed to trigger the target's recovery scheduling.
   m admit-target-after-fault 45 "$ROOT/admit-target-after-fault.log" admitTestPairTarget "$OP" "$BLOB" &&
      ok "$ROOT/admit-target-after-fault.log" admitTestPairTarget || return 1
   m prepare-target-after-fault 45 "$ROOT/prepare-target-after-fault.log" prepareTestPairMigration \
      "$S" "$T" "$OP" "$AD" 1 1 "$VIP" "$PORT" "@$ROOT/target-plan.json" "$BLOB" &&
      ok "$ROOT/prepare-target-after-fault.log" prepareTestPairMigration || return 1
   wait_recovered_target_app || return 1
   archive_fault_phase "$phase"
}

SA=1; create "$S" "$SW" "$ROOT/create-source.log"; TA=1; create "$T" "$TW" "$ROOT/create-target.log"
waitready "$S" source || { echo "FAIL: source readiness" >&2; exit 1; }; waitready "$T" target || { echo "FAIL: target readiness" >&2; exit 1; }
SOURCE_CLUSTER_UUID="$(rg -o 'clusterUUID=0x[0-9a-f]+' "$ROOT/create-source.log" | head -n1 | cut -d= -f2)"; TARGET_CLUSTER_UUID="$(rg -o 'clusterUUID=0x[0-9a-f]+' "$ROOT/create-target.log" | head -n1 | cut -d= -f2)"
[[ -n "$SOURCE_CLUSTER_UUID" && -n "$TARGET_CLUSTER_UUID" && "$SOURCE_CLUSTER_UUID" != "$TARGET_CLUSTER_UUID" && "$(jq -r .privateIPv4Subnet "$SM")" != "$(jq -r .privateIPv4Subnet "$TM")" && "$(jq -r .privateIPv6Subnet "$SM")" != "$(jq -r .privateIPv6Subnet "$TM")" ]] || { echo "FAIL: cluster identities or boundaries overlap" >&2; exit 1; }
printf 'sourceClusterUUID=%s\ntargetClusterUUID=%s\n' "$SOURCE_CLUSTER_UUID" "$TARGET_CLUSTER_UUID" >>"$ROOT/scenario.txt"
SU="$(uuid "$ROOT/source-report.log" "$SM")"; TU="$(uuid "$ROOT/target-report.log" "$TM")"; [[ $SU =~ ^0x[0-9a-f]+$ && $TU =~ ^0x[0-9a-f]+$ ]] || exit 1
for side in source target; do
 [[ $side = source ]] && c=$S u=$SU || { c=$T; u=$TU; }
 q="$(jq -nc --arg name "pair-$side-${OP#0x}" --arg machineUUID "$u" '{name:$name,kind:"BGP",prefix:"198.18.0.1/32",usage:"wormholes",ingressScope:"singleMachine",machineUUID:$machineUUID}')"
 m "vip-$side" 30 "$ROOT/vip-$side.log" registerRoutableSubnet "$c" "$q" && ok "$ROOT/vip-$side.log" registerRoutableSubnet || exit 1
 prefix_uuid="$(rg -m1 -o 'uuid=(0x)?[0-9a-fA-F]+' "$ROOT/vip-$side.log" | cut -d= -f2)"
 [[ "$prefix_uuid" =~ ^(0x)?[0-9a-fA-F]{1,32}$ ]] || { echo "FAIL: $side routable prefix omitted UUID" >&2; exit 1; }
 [[ $side = source ]] && SOURCE_PREFIX_UUID="$prefix_uuid" || TARGET_PREFIX_UUID="$prefix_uuid"
done
DUMMY="$(reserve "$T" "PairTargetDummy-${OP#0x}" "$ROOT/reserve-dummy.log")"; A="$(reserve "$S" "PairSource-${OP#0x}" "$ROOT/reserve-source.log")"; B="$(reserve "$T" "PairTarget-${OP#0x}" "$ROOT/reserve-target.log")"; [[ $A != $B && $DUMMY != $B ]] || { echo "FAIL: application identities not distinct" >&2; exit 1; }
AD="$(did "$A")"; BD="$(did "$B")"; printf 'sourceDeploymentID=%s\ntargetDeploymentID=%s\nsourceMachineUUID=%s\ntargetMachineUUID=%s\n' "$AD" "$BD" "$SU" "$TU" >>"$ROOT/scenario.txt"
mkdir -p "$ROOT/artifact"; F="$ROOT/artifact/Pair.DiscombobuFile"; BLOB="$ROOT/pair.container.zst"; cat >"$F" <<EOF
FROM scratch for $ARCH
COPY {bin} ./$(basename "$PINGPONG_BIN") /root/pair_endpoint_container
SURVIVE /root/pair_endpoint_container
EOF
prodigy_dev_write_common_prodigy_assets "$F"; echo 'EXECUTE ["/root/pair_endpoint_container"]' >>"$F"; prodigy_dev_run_discombobulator_build "$ROOT/artifact" "$F" "$BLOB" "bin=$(dirname "$PINGPONG_BIN")" "ebpf=$(dirname "$PRODIGY_BIN")"
plan "$ROOT/source-plan.json" "$A" "$SOURCE_PREFIX_UUID"; plan "$ROOT/target-plan.json" "$B" "$TARGET_PREFIX_UUID"
if [[ "$MODE" = admission || "$MODE" = admission-master-crash || "$MODE" = admission-cold || "$MODE" = admission-source-crash ]]; then
   for role in source target; do
      jq '.moveConstructively=false' "$ROOT/$role-plan.json" >"$ROOT/$role-admission-plan.json"
      mv "$ROOT/$role-admission-plan.json" "$ROOT/$role-plan.json"
   done
fi
m deploy-source 90 "$ROOT/deploy-source.log" deploy "$S" "$(cat "$ROOT/source-plan.json")" "$BLOB" && accepted_deploy "$ROOT/deploy-source.log" || exit 1
waitapp "$S" "PairSource-${OP#0x}" source || exit 1
MISSING_BD="$(python3 -c 'import sys; print(int(sys.argv[1])+1)' "$BD")"
expect_reason "$ROOT/source-only-reject.log" "exact live deployment identity is unavailable" prepareTestPairBoundary "$S" "$T" "$BAD" "$AD" "$MISSING_BD" 1 1 "$VIP" "$PORT" || exit 1
OPEN=1
if [[ "$MODE" = admission || "$MODE" = admission-master-crash || "$MODE" = admission-cold || "$MODE" = admission-source-crash ]]; then
   # This first independent-cluster profile has no local predecessor chain.
   m admit-target 90 "$ROOT/admit-target.log" prepareTestPairMigration "$S" "$T" "$OP" "$AD" 1 1 "$VIP" "$PORT" "@$ROOT/target-plan.json" "$BLOB" && ok "$ROOT/admit-target.log" prepareTestPairMigration || exit 1
   # Every invocation is a new coordinator process and registry reopen. An
   # exact retry must adopt the original Brain receipt, not issue a second spin.
   m admit-target-retry 45 "$ROOT/admit-target-retry.log" admitTestPairTarget "$OP" "$BLOB" && ok "$ROOT/admit-target-retry.log" admitTestPairTarget || exit 1
   m prepare-retry 45 "$ROOT/prepare-retry.log" prepareTestPairMigration "$S" "$T" "$OP" "$AD" 1 1 "$VIP" "$PORT" "@$ROOT/target-plan.json" "$BLOB" && ok "$ROOT/prepare-retry.log" prepareTestPairMigration || exit 1
   jq '.config.versionID=2' "$ROOT/target-plan.json" >"$ROOT/conflicting-target-plan.json"
   expect_reason "$ROOT/conflicting-target.log" "test pair boundary operation identity conflicts or is closed" prepareTestPairMigration "$S" "$T" "$OP" "$AD" 1 1 "$VIP" "$PORT" "@$ROOT/conflicting-target-plan.json" "$BLOB" || exit 1
   waitapp "$T" "PairTarget-${OP#0x}" target || exit 1
   case "$MODE" in
      admission-master-crash|admission-cold)
         # fakeIpv4Boundary=false has no parent route for the VIP.  The pair
         # router supplies the route before the fault, but keeps source as the
         # selector until the ordinary post-recovery handoff.
         m prepare-before-target-fault 60 "$ROOT/prepare-before-target-fault.log" pairBoundary "$OP" prepare &&
            ok "$ROOT/prepare-before-target-fault.log" pairBoundary || exit 1
         m query-before-target-fault 30 "$ROOT/query-before-target-fault.log" pairBoundary "$OP" query &&
            ok "$ROOT/query-before-target-fault.log" pairBoundary &&
            rg -q 'selected=1([[:space:]]|$)' "$ROOT/query-before-target-fault.log" || exit 1
         ;;
   esac
   case "$MODE" in
      admission-master-crash)
         run_target_admission_fault master phase1 || { echo "FAIL: target master admission recovery" >&2; exit 1; }
         if [[ "$FAULT_DIRECTION" = oldmaster_dials_after_restart_second_fault_required ]]; then
            # Preserve phase1 before this second and final Mothership fault: it
            # covers the opposite connector direction without retrying a pass.
            phase1_old_master="$FAULT_OLD_UUID"
            run_target_admission_fault master phase2 || { echo "FAIL: target reverse-direction master recovery" >&2; exit 1; }
            [[ "$FAULT_CURRENT_UUID" = "$phase1_old_master" ]] || {
               echo "FAIL: second master fault did not restore original lower UUID as master" >&2; exit 1; }
            printf 'targetFaultDirectionCoverage=both sequentialMasterFaults=2\n' >>"$ROOT/scenario.txt"
         else
            printf 'targetFaultDirectionCoverage=canonical-new-master-lower sequentialMasterFaults=1\n' >>"$ROOT/scenario.txt"
         fi
         ;;
      admission-cold) run_target_admission_fault cold || { echo "FAIL: target cold admission recovery" >&2; exit 1; } ;;
      admission-source-crash) : ;;
   esac
   # This is an idempotent revalidation after recovery; the first prepare above
   # established the source-selected route used for the fault observations.
   m prepare 60 "$ROOT/prepare.log" pairBoundary "$OP" prepare && ok "$ROOT/prepare.log" pairBoundary || exit 1
else
   m deploy-target 90 "$ROOT/deploy-target.log" deploy "$T" "$(cat "$ROOT/target-plan.json")" "$BLOB" && accepted_deploy "$ROOT/deploy-target.log" || exit 1
   waitapp "$T" "PairTarget-${OP#0x}" target || exit 1
   m prepare 60 "$ROOT/prepare.log" prepareTestPairBoundary "$S" "$T" "$OP" "$AD" "$BD" 1 1 "$VIP" "$PORT" && ok "$ROOT/prepare.log" prepareTestPairBoundary || exit 1
fi
expect_reason "$ROOT/wrong-operation.log" "record not found" pairBoundary "$BAD" query || exit 1
expect_reason "$ROOT/remove-open.log" "remove the owned test pair boundary first" removeCluster "$S" || exit 1
m source-probe 45 "$ROOT/source-probe.log" probePairBoundary "$OP" "$AD" 1 0 && ok "$ROOT/source-probe.log" probePairBoundary && rg -q '"ok": true' "$ROOT/source-probe.log" || exit 1
# The provider must observe a source flow before selection; never switch on a
# failed/unsupported conntrack query.
m source-flow-gate 30 "$ROOT/source-flow-gate.log" pairBoundary "$OP" query && ok "$ROOT/source-flow-gate.log" pairBoundary && rg -q 'sourceFlows=[1-9][0-9]*' "$ROOT/source-flow-gate.log" || { echo "FAIL: source flow observation absent before selection" >&2; exit 1; }
( m held-source 45 "$ROOT/held-source.log" probePairBoundary "$OP" "$AD" 30 750 && echo 0 >"$RC" || echo $? >"$RC" ) & HELD=$!
e=$(( $(date +%s%3N)+15000 )); while [[ $(date +%s%3N) -lt $e ]] && ! rg -q '"ok": true' "$ROOT/held-source.log" 2>/dev/null; do kill -0 "$HELD" 2>/dev/null || break; sleep .05; done; rg -q '"ok": true' "$ROOT/held-source.log" || { echo "FAIL: held source no first reply" >&2; exit 1; }
m select-target 45 "$ROOT/select-target.log" pairBoundary "$OP" selectTarget && ok "$ROOT/select-target.log" pairBoundary || exit 1; m target-probe 45 "$ROOT/target-probe.log" probePairBoundary "$OP" "$BD" 5 0 && ok "$ROOT/target-probe.log" probePairBoundary && rg -q '"ok": true' "$ROOT/target-probe.log" || exit 1
if [[ "$MODE" = admission || "$MODE" = admission-master-crash || "$MODE" = admission-cold || "$MODE" = admission-source-crash ]]; then
   expect_reason "$ROOT/retire-source-wrong-operation.log" "record not found" retireTestPairSource "$BAD" || exit 1
   m selector-after-wrong-retire 30 "$ROOT/selector-after-wrong-retire.log" pairBoundary "$OP" query && ok "$ROOT/selector-after-wrong-retire.log" pairBoundary && rg -q 'selected=2([[:space:]]|$)' "$ROOT/selector-after-wrong-retire.log" || exit 1
   waitapp "$S" "PairSource-${OP#0x}" source-after-wrong-retire || { echo "FAIL: wrong operation changed the source workload" >&2; exit 1; }
   m target-after-wrong-retire 45 "$ROOT/target-after-wrong-retire.log" probePairBoundary "$OP" "$BD" 5 0 && ok "$ROOT/target-after-wrong-retire.log" probePairBoundary && rg -q '"ok": true' "$ROOT/target-after-wrong-retire.log" || exit 1
   if m retire-source-held-reject 60 "$ROOT/retire-source-held-reject.log" retireTestPairSource "$OP"; then
      echo "FAIL: source retirement succeeded while the source connection was held" >&2; exit 1
   fi
   rg -q 'failure=virtual datacenter provider failed status=1' "$ROOT/retire-source-held-reject.log" &&
      rg -q 'selected=2 drainCapability=1 sourceFlows=[1-9][0-9]*' "$ROOT/retire-source-held-reject.log" || { echo "FAIL: held retirement did not fail at the provider drain gate" >&2; exit 1; }
   waitapp "$S" "PairSource-${OP#0x}" source-after-retire-reject || { echo "FAIL: held retirement changed the source workload" >&2; exit 1; }
fi
wait "$HELD" || true; HELD=; [[ "$(cat "$RC")" = 0 && "$(rg -c '^PAIR_BOUNDARY_REQUEST .*"ok": true' "$ROOT/held-source.log" || true)" = 30 ]] || { echo "FAIL: source connection did not retain 30 identities" >&2; exit 1; }
python3 "$SCRIPT_DIR/prodigy_dev_pair_endpoint_history.py" "$ROOT" >"$ROOT/request-history.json"
# Drain is only a final provider action.  Query until all source flows have
# naturally expired; a failed query is a test failure, never an empty result.
drain_deadline=$(( $(date +%s%3N) + 150000 ))
drained=0
while [[ $(date +%s%3N) -lt $drain_deadline ]]; do
   drain_query="$ROOT/drain-query-$(date +%s%3N).log"
   m drain-query 30 "$drain_query" pairBoundary "$OP" query || exit 1
   ok "$drain_query" pairBoundary || exit 1
   if rg -q 'sourceFlows=0([[:space:]]|$)' "$drain_query"; then
      drained=1
      break
   fi
   sleep 1
done
[[ $drained = 1 ]] || { echo "FAIL: source flows did not drain within provider TIME_WAIT window" >&2; exit 1; }
m drain 30 "$ROOT/drain.log" pairBoundary "$OP" drain && ok "$ROOT/drain.log" pairBoundary || exit 1
if [[ "$MODE" = admission || "$MODE" = admission-master-crash || "$MODE" = admission-cold || "$MODE" = admission-source-crash ]]; then
   if [[ "$MODE" = admission-source-crash ]]; then
      run_source_retirement_fault || { echo "FAIL: source retirement interruption/recovery" >&2; exit 1; }
   elif ! { m retire-source 210 "$ROOT/retire-source.log" retireTestPairSource "$OP" && ok "$ROOT/retire-source.log" retireTestPairSource && rg -q 'sealed=1[[:space:]]+terminal=1([[:space:]]|$)' "$ROOT/retire-source.log"; }; then
      m source-retirement-pending-report 30 "$ROOT/source-retirement-pending-report.log" applicationReport "$S" "PairSource-${OP#0x}" || true
      m source-retirement-pending-cluster 30 "$ROOT/source-retirement-pending-cluster.log" clusterReport "$S" || true
      exit 1
   fi
   m retire-source-retry 210 "$ROOT/retire-source-retry.log" retireTestPairSource "$OP" && ok "$ROOT/retire-source-retry.log" retireTestPairSource && rg -q 'sealed=1[[:space:]]+terminal=1([[:space:]]|$)' "$ROOT/retire-source-retry.log" || exit 1
   m target-after-retire 45 "$ROOT/target-after-retire.log" probePairBoundary "$OP" "$BD" 5 0 && ok "$ROOT/target-after-retire.log" probePairBoundary && rg -q '"ok": true' "$ROOT/target-after-retire.log" || exit 1
   m source-retired-report 30 "$ROOT/source-retired-report.log" applicationReport "$S" "PairSource-${OP#0x}" && source_report_retired "$ROOT/source-retired-report.log" || { echo "FAIL: source report retains a live workload after retirement" >&2; exit 1; }
   # The shared boundary remains target-selected: rejection of the old source
   # deployment ID proves endpoint ownership, while the terminal receipt and
   # source report above prove source workload retirement.
   if m source-after-retire-probe 30 "$ROOT/source-after-retire-probe.log" probePairBoundary "$OP" "$AD" 1 0; then
      echo "FAIL: shared boundary still returns the source deployment after target selection" >&2; exit 1
   fi
fi
# After continuity and drain have completed, prove that cleanup can recover a
# dead endpoint owner. This explicit interruption is not traffic fault tolerance.
m crash-owner 30 "$ROOT/crash-owner.log" pairBoundary "$OP" crashOwner && ok "$ROOT/crash-owner.log" pairBoundary || exit 1
m boundary-remove 60 "$ROOT/boundary-remove.log" pairBoundary "$OP" remove && ok "$ROOT/boundary-remove.log" pairBoundary || exit 1; OPEN=0
copy_pair_observations
rmcluster "$S" "$ROOT/remove-source.log"; SA=0; rmcluster "$T" "$ROOT/remove-target.log"; TA=0
[[ ! -e "$SM" && ! -e "$TM" ]] || exit 1
echo 'pairBoundary=passed observedSourceHeldRequests=30 observedTargetRequests=5' >>"$ROOT/scenario.txt"
