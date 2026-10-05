#!/usr/bin/env bash
# Mothership-owned two-cluster AEGIS pair-enrollment qualification.
set -Eeuo pipefail

if [[ "${1:-}" == --validate-only && $# -eq 1 ]]; then
  bash -n "$0"
  exit 0
fi

PRODIGY_BIN=${1:-}
MOTHERSHIP_BIN=${2:-}
[[ $# -eq 2 && -x "$PRODIGY_BIN" && -x "$MOTHERSHIP_BIN" ]] || {
  echo "usage: $0 /path/to/prodigy /path/to/mothership" >&2
  exit 2
}
[[ $EUID -eq 0 ]] || { echo "SKIP: Mothership test clusters require root" >&2; exit 77; }
for command in date jq mktemp python3 readlink rg sha256sum sleep timeout uname; do
  command -v "$command" >/dev/null || { echo "SKIP: missing $command" >&2; exit 77; }
done

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd -P)
TEST_DIR="$REPO_ROOT/prodigy/dev/tests"
source "$TEST_DIR/prodigy_dev_discombobulator_artifact_helpers.sh"
SELF=$(readlink -f "${BASH_SOURCE[0]}")
prodigy_dev_reexec_in_private_mount_namespace_once \
  PRODIGY_DEV_PAIR_ENROLLMENT_MOUNT_NS_READY bash "$SELF" "$@"
"$TEST_DIR/prodigy_dev_test_cluster.sh" --check-boundary

PRODIGY_BIN=$(readlink -f "$PRODIGY_BIN")
MOTHERSHIP_BIN=$(readlink -f "$MOTHERSHIP_BIN")
[[ "$(dirname "$PRODIGY_BIN")" == "$(dirname "$MOTHERSHIP_BIN")" ]] || {
  echo "FAIL: release binaries are not siblings" >&2
  exit 1
}
case "$(uname -m)" in
  x86_64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  riscv64) ARCH=riscv64 ;;
  *) echo "SKIP: unsupported architecture" >&2; exit 77 ;;
esac
BUNDLE="$(dirname "$PRODIGY_BIN")/prodigy.$ARCH.bundle.tar.zst"
[[ -r "$BUNDLE" ]] || { echo "FAIL: missing sibling bundle" >&2; exit 1; }
EXPECTED_BUNDLE_SHA256=$(sha256sum "$BUNDLE" | cut -d' ' -f1)

ROOT=$(mktemp -d "$REPO_ROOT/.run/prodigy-pair-enrollment.XXXXXX")
DB="$ROOT/mothership.tidesdb"
mkdir -p "$ROOT/receipts"
FIRST="pair-enroll-first-$$-$RANDOM"
SECOND="pair-enroll-second-$$-$RANDOM"
FIRST_WORKSPACE="$ROOT/first-workspace"
SECOND_WORKSPACE="$ROOT/second-workspace"
FIRST_MANIFEST="$FIRST_WORKSPACE/test-cluster-manifest.json"
SECOND_MANIFEST="$SECOND_WORKSPACE/test-cluster-manifest.json"
FIRST_CREATED=0
SECOND_CREATED=0
FIRST_REMOVED=0
SECOND_REMOVED=0

new_operation() {
  python3 - <<'PY'
import secrets
value = secrets.randbits(128) or 1
print("0x" + value.to_bytes(16, "big").hex())
PY
}
OPERATION=$(new_operation)
CONFLICT_OPERATION=$(python3 - "$OPERATION" <<'PY'
import sys
value = int(sys.argv[1], 16) ^ 1
print("0x" + (value or 2).to_bytes(16, "big").hex())
PY
)

m() {
  local label=$1 seconds=$2 log=$3
  shift 3
  local started ended status
  started=$(date +%s%3N)
  if timeout "${seconds}s" env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$DB" "$MOTHERSHIP_BIN" "$@" >"$log" 2>&1; then
    status=0
  else
    status=$?
  fi
  ended=$(date +%s%3N)
  jq -nc --arg label "$label" --arg operation "$1" --argjson status "$status" \
    --argjson startedMs "$started" --argjson endedMs "$ended" \
    '{label:$label,operation:$operation,status:$status,startedMs:$startedMs,endedMs:$endedMs}' \
    >"$ROOT/receipts/$label-$started.json"
  return "$status"
}

ok() { rg -q "(^|[[:space:]])$2[[:space:]].*success=1([[:space:]]|$)" "$1"; }

copy_cluster_logs() {
  local label=$1 manifest=$2 output="$ROOT/$1-logs"
  [[ -s "$manifest" ]] || return 0
  mkdir -p "$output"
  local workspace provider_evidence
  workspace=$(dirname "$manifest")
  for provider_evidence in virtual-datacenter.log virtual-datacenter.failure machine-exits.log; do
    [[ ! -r "$workspace/$provider_evidence" ]] || cp -p "$workspace/$provider_evidence" "$output/$provider_evidence"
  done
  cp -p "$manifest" "$output/test-cluster-manifest.json" 2>/dev/null || true
  while IFS=$'\t' read -r index role stdout stderr; do
    [[ -r "$stdout" ]] && cp -p "$stdout" "$output/machine${index}.${role}.stdout.log" 2>/dev/null || true
    [[ -r "$stderr" ]] && cp -p "$stderr" "$output/machine${index}.${role}.stderr.log" 2>/dev/null || true
  done < <(jq -r '.nodes[] | [.index, .role, .stdoutLog, .stderrLog] | @tsv' "$manifest" 2>/dev/null)
}

remove_cluster() {
  local name=$1 log=$2
  if m "remove-$name" 180 "$log" removeCluster "$name"; then
    ok "$log" removeCluster
  else
    rg -q "removeCluster success=0 removed=0 identity=$name failure=record not found" "$log"
  fi
}

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  copy_cluster_logs first "$FIRST_MANIFEST" || status=1
  copy_cluster_logs second "$SECOND_MANIFEST" || status=1
  if (( FIRST_CREATED && !FIRST_REMOVED )); then
    remove_cluster "$FIRST" "$ROOT/remove-first-cleanup.log" || status=1
  fi
  if (( SECOND_CREATED && !SECOND_REMOVED )); then
    remove_cluster "$SECOND" "$ROOT/remove-second-cleanup.log" || status=1
  fi
  [[ ! -e "$FIRST_MANIFEST" && ! -e "$SECOND_MANIFEST" ]] || status=1
  jq -nc --argjson exitCode "$status" --arg operationUUID "$OPERATION" \
    '{exitCode:$exitCode,operationUUID:$operationUUID}' >"$ROOT/result.json"
  printf 'PAIR_ENROLLMENT_EVIDENCE=%s\n' "$ROOT"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

request() {
  local name=$1 workspace=$2
  jq -nc --arg name "$name" --arg workspace "$workspace" \
    '{name:$name,deploymentMode:"test",internalTransportProfile:"aegis-x25519-v1",nBrains:3,autoscaleIntervalSeconds:180,machineSchemas:[{schema:"pair-enrollment-machine",kind:"vm",vmImageURI:"test://virtual-datacenter"}],test:{workspaceRoot:$workspace,machineCount:3,machineLogicalCores:4,machineMemoryMB:8192,machineStorageMB:8192,brainBootstrapFamily:"ipv4",enableFakeIpv4Boundary:false,interContainerMTU:9000}}'
}

create_cluster() {
  local name=$1 workspace=$2 log=$3 request_json
  request_json=$(request "$name" "$workspace")
  printf '%s\n' "$request_json" >"$ROOT/$name-request.json"
  m "create-$name" 180 "$log" createCluster "$request_json"
  ok "$log" createCluster
}

ready() {
  local report=$1
  [[ $(rg -c '^[[:space:]]*Machine: state=healthy role=brain ' "$report" || true) = 3 &&
     $(rg -c '^[[:space:]]*lifecycle controlPlaneReachable=1 runtimeReady=1 ' "$report" || true) = 3 &&
     $(rg -c '^[[:space:]]*lifecycle .*currentMaster=1([[:space:]]|$)' "$report" || true) = 1 &&
     $(rg -c "approvedBundleSHA256=$EXPECTED_BUNDLE_SHA256 " "$report" || true) = 3 ]]
}

wait_ready() {
  local cluster=$1 label=$2
  local report="$ROOT/$label-cluster-report.log"
  local deadline=$(( $(date +%s%3N) + 120000 ))
  while (( $(date +%s%3N) < deadline )); do
    m "report-$label" 8 "$report" clusterReport "$cluster" && ready "$report" && return 0
    sleep .25
  done
  sed -n '1,220p' "$report" >&2
  return 1
}

enrollment_complete() {
  local log=$1
  ok "$log" enrollClusterPair &&
    rg -q 'firstQualified=1 firstProjection=1 secondQualified=1 secondProjection=1 pending=0' "$log"
}

master_identity() {
  python3 - "$1" "$FIRST_MANIFEST" <<'PY2'
import json,pathlib,re,sys
nodes={node['ipv4']:node['index'] for node in json.loads(pathlib.Path(sys.argv[2]).read_text())['nodes']}
for block in re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)', pathlib.Path(sys.argv[1]).read_text()):
    identity=re.search(r'(?m)^[ \t]*identity uuid=(\S+) .*sshAddress=(\S+)',block)
    master=re.search(r'\bcurrentMaster=1(?:\s|$)',block)
    boot=re.search(r'\bbootTimeMs=([0-9]+)',block)
    if identity and master and boot and identity.group(2) in nodes:
        print(nodes[identity.group(2)],identity.group(1),boot.group(1),sep='\t')
        raise SystemExit(0)
raise SystemExit('no exact current master identity')
PY2
}

sha256sum "$PRODIGY_BIN" "$MOTHERSHIP_BIN" "$BUNDLE" >"$ROOT/artifact-identities.sha256"
printf 'operationUUID=%s\nconflictingOperationUUID=%s\n' "$OPERATION" "$CONFLICT_OPERATION" >"$ROOT/scenario.txt"

FIRST_CREATED=1
create_cluster "$FIRST" "$FIRST_WORKSPACE" "$ROOT/create-first.log"
SECOND_CREATED=1
create_cluster "$SECOND" "$SECOND_WORKSPACE" "$ROOT/create-second.log"
wait_ready "$FIRST" first
wait_ready "$SECOND" second

m enroll 45 "$ROOT/enroll.log" enrollClusterPair "$FIRST" "$SECOND" "$OPERATION"
enrollment_complete "$ROOT/enroll.log"
m enroll-reversed-retry 45 "$ROOT/enroll-reversed-retry.log" enrollClusterPair "$SECOND" "$FIRST" "$OPERATION"
enrollment_complete "$ROOT/enroll-reversed-retry.log"
if m enroll-conflicting-operation 45 "$ROOT/enroll-conflicting-operation.log" \
  enrollClusterPair "$FIRST" "$SECOND" "$CONFLICT_OPERATION"; then
  echo 'FAIL: conflicting pair enrollment operation unexpectedly succeeded' >&2
  exit 1
fi
rg -q 'enrollClusterPair success=0 .*failure=cluster pair already has an immutable enrollment operation' "$ROOT/enroll-conflicting-operation.log"

# A provider-owned whole-machine crash must restore the committed operation
# under a different master without another enrollment root or endpoint roster.
m report-first-before-fault 8 "$ROOT/first-before-fault-report.log" clusterReport "$FIRST"
ready "$ROOT/first-before-fault-report.log"
IFS=$'\t' read -r OLD_MASTER_INDEX OLD_MASTER_UUID OLD_MASTER_BOOT < <(master_identity "$ROOT/first-before-fault-report.log")
[[ "$OLD_MASTER_INDEX" =~ ^[1-3]$ ]]
m first-master-fault 45 "$ROOT/first-master-fault.log" faultTestCluster "$FIRST" crash "$OLD_MASTER_INDEX" 12000 0 0 0
ok "$ROOT/first-master-fault.log" faultTestCluster
wait_ready "$FIRST" first-after-fault
IFS=$'\t' read -r NEW_MASTER_INDEX NEW_MASTER_UUID NEW_MASTER_BOOT < <(master_identity "$ROOT/first-after-fault-cluster-report.log")
[[ "$NEW_MASTER_UUID" != "$OLD_MASTER_UUID" ]]
python3 - "$ROOT/first-after-fault-cluster-report.log" "$OLD_MASTER_UUID" "$OLD_MASTER_BOOT" <<'PY2'
import pathlib,re,sys
for block in re.findall(r'(?ms)^[ \t]*Machine:.*?(?=^[ \t]*Machine:|\Z)',pathlib.Path(sys.argv[1]).read_text()):
    identity=re.search(r'(?m)^[ \t]*identity uuid=(\S+)',block)
    boot=re.search(r'\bbootTimeMs=([0-9]+)',block)
    if identity and identity.group(1)==sys.argv[2] and boot:
        assert boot.group(1)!=sys.argv[3], 'faulted master did not change incarnation'
        break
else: raise SystemExit('faulted master missing after recovery')
PY2
printf 'oldMasterUUID=%s newMasterUUID=%s oldMasterIndex=%s newMasterIndex=%s\n' \
  "$OLD_MASTER_UUID" "$NEW_MASTER_UUID" "$OLD_MASTER_INDEX" "$NEW_MASTER_INDEX" >>"$ROOT/scenario.txt"
m enroll-after-master-fault 45 "$ROOT/enroll-after-master-fault.log" enrollClusterPair "$FIRST" "$SECOND" "$OPERATION"
enrollment_complete "$ROOT/enroll-after-master-fault.log"

m report-first-final 8 "$ROOT/first-final-cluster-report.log" clusterReport "$FIRST"
ready "$ROOT/first-final-cluster-report.log"
m report-second-final 8 "$ROOT/second-final-cluster-report.log" clusterReport "$SECOND"
ready "$ROOT/second-final-cluster-report.log"
copy_cluster_logs first "$FIRST_MANIFEST"
copy_cluster_logs second "$SECOND_MANIFEST"

remove_cluster "$FIRST" "$ROOT/remove-first.log"
FIRST_REMOVED=1
remove_cluster "$SECOND" "$ROOT/remove-second.log"
SECOND_REMOVED=1
[[ ! -e "$FIRST_MANIFEST" && ! -e "$SECOND_MANIFEST" ]]
