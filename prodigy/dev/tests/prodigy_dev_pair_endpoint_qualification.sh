#!/usr/bin/env bash
# Bounded Mothership-client VIP handoff observations; not a migration claim.
set -Eeuo pipefail
if [[ "${1:-}" == "--validate-only" && "$#" = 1 ]]; then bash -n "$0"; exit 0; fi
PRODIGY_BIN="${1:-}"; MOTHERSHIP_BIN="${2:-}"; PINGPONG_BIN="${3:-}"
[[ $# = 3 && -x "$PRODIGY_BIN" && -x "$MOTHERSHIP_BIN" && -x "$PINGPONG_BIN" ]] || { echo "usage: $0 prodigy mothership pingpong" >&2; exit 2; }
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
SA=0; TA=0; OPEN=0; HELD=; RC="$ROOT/held.rc"; VIP=198.18.0.1; PORT=19090
printf 'scenario=pair-endpoint migrationCoverage=0 vip=%s port=%s sourceMachineIndex=1 targetMachineIndex=1\n' "$VIP" "$PORT" >"$ROOT/scenario.txt"
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
rmcluster() { if m "remove-$1" 120 "$2" removeCluster "$1"; then ok "$2" removeCluster; else rg -q "removeCluster success=0 removed=0 identity=$1 failure=record not found" "$2"; fi; }
cleanup() { local st=$?; trap - EXIT HUP INT TERM; set +e; [[ -z "$HELD" ]] || wait "$HELD" || st=1; [[ $OPEN != 1 ]] || { m boundary-remove-cleanup 180 "$ROOT/boundary-remove-cleanup.log" pairBoundary "$OP" remove && ok "$ROOT/boundary-remove-cleanup.log" pairBoundary || st=1; }; [[ $SA != 1 ]] || rmcluster "$S" "$ROOT/remove-source-cleanup.log" || st=1; [[ $TA != 1 ]] || rmcluster "$T" "$ROOT/remove-target-cleanup.log" || st=1; [[ ! -e "$SM" && ! -e "$TM" ]] || st=1; jq -nc --arg result "$( [[ "$st" = 0 ]] && echo pass || echo fail )" --arg operationID "$OP" '{result:$result,operationID:$operationID}' >"$ROOT/result.json"; echo "PAIR_ENDPOINT_EVIDENCE=$ROOT"; exit "$st"; }
trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
request() { jq -nc --arg name "$1" --arg workspace "$2" '{name:$name,deploymentMode:"test",nBrains:3,autoscaleIntervalSeconds:180,machineSchemas:[{schema:"pair-machine",kind:"vm",vmImageURI:"test://virtual-datacenter"}],test:{workspaceRoot:$workspace,machineCount:3,machineLogicalCores:4,machineMemoryMB:8192,machineStorageMB:8192,brainBootstrapFamily:"ipv4",enableFakeIpv4Boundary:false,interContainerMTU:9000}}'; }
create() { local q; q="$(request "$1" "$2")"; printf '%s\n' "$q" >"$ROOT/$1-request.json"; m "create-$1" 180 "$3" createCluster "$q" && ok "$3" createCluster; }
ready() { [[ $(rg -c '^[[:space:]]*Machine: state=healthy role=brain ' "$1" || true) = 3 && $(rg -c '^[[:space:]]*lifecycle controlPlaneReachable=1 runtimeReady=1 ' "$1" || true) = 3 && $(rg -c "approvedBundleSHA256=$EXPECTED_BUNDLE_SHA256 " "$1" || true) = 3 ]]; }
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
waitapp() {
   local end=$(( $(date +%s%3N)+120000 )) report="$ROOT/$3-app.log"
   while [[ $(date +%s%3N) -lt $end ]]; do
      if m "app-$3" 8 "$report" applicationReport "$1" "$2"; then
         if rg -q 'nCrashes: [1-9][0-9]*' "$report"; then break; fi
         if rg -q 'nTarget: 1' "$report" && rg -q 'nDeployed: 1' "$report" &&
            rg -q 'nHealthy: 1' "$report" && rg -q 'nCrashes: 0' "$report"; then return; fi
      fi
      sleep .25
   done
   sed -n '1,220p' "$report" >&2
   return 1
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
plan "$ROOT/source-plan.json" "$A" "$SOURCE_PREFIX_UUID"; plan "$ROOT/target-plan.json" "$B" "$TARGET_PREFIX_UUID"; m deploy-source 90 "$ROOT/deploy-source.log" deploy "$S" "$(cat "$ROOT/source-plan.json")" "$BLOB" && accepted_deploy "$ROOT/deploy-source.log" || exit 1; m deploy-target 90 "$ROOT/deploy-target.log" deploy "$T" "$(cat "$ROOT/target-plan.json")" "$BLOB" && accepted_deploy "$ROOT/deploy-target.log" || exit 1
waitapp "$S" "PairSource-${OP#0x}" source || exit 1; waitapp "$T" "PairTarget-${OP#0x}" target || exit 1
MISSING_BD="$(python3 -c 'import sys; print(int(sys.argv[1])+1)' "$BD")"
expect_reason "$ROOT/source-only-reject.log" "exact live deployment identity is unavailable" prepareTestPairBoundary "$S" "$T" "$BAD" "$AD" "$MISSING_BD" 1 1 "$VIP" "$PORT" || exit 1
OPEN=1
m prepare 60 "$ROOT/prepare.log" prepareTestPairBoundary "$S" "$T" "$OP" "$AD" "$BD" 1 1 "$VIP" "$PORT" && ok "$ROOT/prepare.log" prepareTestPairBoundary || exit 1
expect_reason "$ROOT/wrong-operation.log" "record not found" pairBoundary "$BAD" query || exit 1
expect_reason "$ROOT/remove-open.log" "remove the owned test pair boundary first" removeCluster "$S" || exit 1
m source-probe 45 "$ROOT/source-probe.log" probePairBoundary "$OP" "$AD" 1 0 && ok "$ROOT/source-probe.log" probePairBoundary && rg -q '"ok": true' "$ROOT/source-probe.log" || exit 1
# The provider must observe a source flow before selection; never switch on a
# failed/unsupported conntrack query.
m source-flow-gate 30 "$ROOT/source-flow-gate.log" pairBoundary "$OP" query && ok "$ROOT/source-flow-gate.log" pairBoundary && rg -q 'sourceFlows=[1-9][0-9]*' "$ROOT/source-flow-gate.log" || { echo "FAIL: source flow observation absent before selection" >&2; exit 1; }
( m held-source 45 "$ROOT/held-source.log" probePairBoundary "$OP" "$AD" 30 200 && echo 0 >"$RC" || echo $? >"$RC" ) & HELD=$!
e=$(( $(date +%s%3N)+15000 )); while [[ $(date +%s%3N) -lt $e ]] && ! rg -q '"ok": true' "$ROOT/held-source.log" 2>/dev/null; do kill -0 "$HELD" 2>/dev/null || break; sleep .05; done; rg -q '"ok": true' "$ROOT/held-source.log" || { echo "FAIL: held source no first reply" >&2; exit 1; }
m select-target 45 "$ROOT/select-target.log" pairBoundary "$OP" selectTarget && ok "$ROOT/select-target.log" pairBoundary || exit 1; m target-probe 45 "$ROOT/target-probe.log" probePairBoundary "$OP" "$BD" 5 0 && ok "$ROOT/target-probe.log" probePairBoundary && rg -q '"ok": true' "$ROOT/target-probe.log" || exit 1
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
# After continuity and drain have completed, prove that cleanup can recover a
# dead endpoint owner. This explicit interruption is not traffic fault tolerance.
m crash-owner 30 "$ROOT/crash-owner.log" pairBoundary "$OP" crashOwner && ok "$ROOT/crash-owner.log" pairBoundary || exit 1
m boundary-remove 60 "$ROOT/boundary-remove.log" pairBoundary "$OP" remove && ok "$ROOT/boundary-remove.log" pairBoundary || exit 1; OPEN=0
rmcluster "$S" "$ROOT/remove-source.log"; SA=0; rmcluster "$T" "$ROOT/remove-target.log"; TA=0
[[ ! -e "$SM" && ! -e "$TM" ]] || exit 1
echo 'pairBoundary=passed observedSourceHeldRequests=30 observedTargetRequests=5' >>"$ROOT/scenario.txt"
