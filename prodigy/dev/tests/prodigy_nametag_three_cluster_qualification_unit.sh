#!/usr/bin/env bash
set -Eeuo pipefail

readonly SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly DRIVER="$SELF_DIR/prodigy_nametag_three_cluster_qualification.sh"
readonly FIXTURE="$SELF_DIR/fixtures/nametag_three_cluster_qualification_manifest.json"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/prodigy-nametag-three-cluster-unit.XXXXXX")"
trap 'rm -rf "$ROOT"' EXIT

bash -n "$DRIVER"
jq -e . "$FIXTURE" >/dev/null
output="$ROOT/output"
bash "$DRIVER" --mothership /usr/bin/true --manifest "$FIXTURE" --run-dir "$ROOT/run" --dry-run >"$output"

# The fixture is the frozen matrix; dry-run must invoke both sides of all rows.
test "$(jq '.chaos | length' "$FIXTURE")" = 17
while IFS= read -r label; do grep -Fq "\"label\":\"$label\"" "$output"; done < <(jq -r '.chaos[] | .injection.label, .observation.label' "$FIXTURE")
test "$(find "$ROOT/run/receipts" -name 'chaos-*.json' -type f | wc -l | tr -d ' ')" = 17
test "$(jq -s '[.[] | select(.status == "dry-run" and .fixtureOnly == true)] | length' "$ROOT/run/receipts"/chaos-*.json)" = 17
test "$(jq -s '[.[] | select(.schema.version == 4)] | length' "$ROOT/run/receipts"/chaos-*.json)" = 17
test "$(jq -s '[.[] | select(has("canonicalFiveStoreReceipt") or has("healthyTopology"))] | length' "$ROOT/run/receipts"/chaos-*.json)" = 0
test "$(jq -s '[.[] | select(.kind == "cleanup" and .status == "success")] | length' "$ROOT/run/resource-ledger.jsonl")" = 25
test "$(jq '[.topology.gatewayMachines[]] | length' "$FIXTURE")" = 9
test "$(jq '[.topology.masque.paths[].authorities[]] | length' "$FIXTURE")" = 18
test "$(jq '[.commands[] | select(.operation == "crossClusterMasqueGateway" and .args == ["configure"])] | length' "$FIXTURE")" = 18
test "$(jq '[.cleanup[] | select(.operation == "crossClusterMasqueGateway" and .args == ["withdraw"])] | length' "$FIXTURE")" = 18
run_uuid="$(jq -r 'select(.kind == "header") | .campaignRunUUID' "$ROOT/run/resource-ledger.jsonl")"
[[ $run_uuid =~ ^[0-9a-f]{32}$ ]]
bash "$DRIVER" --mothership /usr/bin/true --manifest "$FIXTURE" --run-dir "$ROOT/run" --dry-run >/dev/null
test "$run_uuid" = "$(jq -r 'select(.kind == "header") | .campaignRunUUID' "$ROOT/run/resource-ledger.jsonl")"
grep -Fq '"label":"cleanup-pair-enroll"' "$output"
! grep -Fq 'prepareNametagStatefulPair' "$output"
! grep -Fq 'nametagStatefulPair' "$output"

# Reverse cleanup remains exact: deleting an inverse invalidates the manifest.
jq 'del(.cleanup[] | select(.resourceID == "pair-enroll"))' "$FIXTURE" >"$ROOT/missing-cleanup.json"
if bash "$DRIVER" --mothership /usr/bin/true --manifest "$ROOT/missing-cleanup.json" --run-dir "$ROOT/missing" --dry-run >"$ROOT/missing.out" 2>&1; then
  echo 'expected missing cleanup manifest to fail' >&2
  exit 1
fi
grep -Fq 'FAIL: manifest schema' "$ROOT/missing.out"

# A skipped/unowned row and topology drift are preflight failures.
jq '(.chaos[0].injection.owner) = "harness"' "$FIXTURE" >"$ROOT/unowned.json"
if bash "$DRIVER" --mothership /usr/bin/true --manifest "$ROOT/unowned.json" --run-dir "$ROOT/unowned" --dry-run >"$ROOT/unowned.out" 2>&1; then exit 1; fi
grep -Fq 'FAIL: manifest schema' "$ROOT/unowned.out"
jq '(.topology.masque.paths) |= .[0:8]' "$FIXTURE" >"$ROOT/topology-drift.json"
if bash "$DRIVER" --mothership /usr/bin/true --manifest "$ROOT/topology-drift.json" --run-dir "$ROOT/topology-drift" --dry-run >"$ROOT/topology-drift.out" 2>&1; then exit 1; fi
grep -Fq 'FAIL: manifest schema' "$ROOT/topology-drift.out"

# The corrected topology is exact: tags and /96s, three slots per pair, and
# both directional authorities must agree on the reverse endpoint and slot.
jq '(.topology.sites[1].datacenterTag) = 1' "$FIXTURE" >"$ROOT/duplicate-tag.json"
if bash "$DRIVER" --mothership /usr/bin/true --manifest "$ROOT/duplicate-tag.json" --run-dir "$ROOT/duplicate-tag" --dry-run >"$ROOT/duplicate-tag.out" 2>&1; then exit 1; fi
grep -Fq 'FAIL: manifest schema' "$ROOT/duplicate-tag.out"
jq '(.topology.sites[0].prefix) = "fd10:100::1/96" | (.topology.routeAdvertisements[0].prefix) = "fd10:100::1/96"' "$FIXTURE" >"$ROOT/noncanonical-prefix.json"
if bash "$DRIVER" --mothership /usr/bin/true --manifest "$ROOT/noncanonical-prefix.json" --run-dir "$ROOT/noncanonical-prefix" --dry-run >"$ROOT/noncanonical-prefix.out" 2>&1; then exit 1; fi
grep -Fq 'FAIL: manifest has a non-canonical IPv6 /96' "$ROOT/noncanonical-prefix.out"
jq '(.topology.masque.paths[0].authorities[1].peerMachineUUID) = "00000000-0000-4000-8000-000000000303"' "$FIXTURE" >"$ROOT/reverse-drift.json"
if bash "$DRIVER" --mothership /usr/bin/true --manifest "$ROOT/reverse-drift.json" --run-dir "$ROOT/reverse-drift" --dry-run >"$ROOT/reverse-drift.out" 2>&1; then exit 1; fi
grep -Fq 'FAIL: manifest schema' "$ROOT/reverse-drift.out"
jq '(.topology.gatewayMachines[] | select(.site == "ewr" and .slot == 0) | .machineUUID) = "00000000-0000-4000-8000-000000000999"' "$FIXTURE" >"$ROOT/gateway-machine-site-slot-mismatch.json"
if bash "$DRIVER" --mothership /usr/bin/true --manifest "$ROOT/gateway-machine-site-slot-mismatch.json" --run-dir "$ROOT/gateway-machine-site-slot-mismatch" --dry-run >"$ROOT/gateway-machine-site-slot-mismatch.out" 2>&1; then exit 1; fi
grep -Fq 'FAIL: manifest schema' "$ROOT/gateway-machine-site-slot-mismatch.out"
for mutation in \
  'del(.topology.gatewayMachines[] | select(.site == "ewr" and .slot == 2))' \
  'del(.topology.masque.paths[0].authorities[1])' \
  '(.topology.masque.paths[4].authorities[0].machineUUID) = .topology.masque.paths[0].authorities[0].machineUUID' \
  '(.topology.masque.paths[0].slot) = 1' \
  '(.topology.masque.paths[1].authorities[0].interface) = .topology.masque.paths[0].authorities[0].interface' \
  'del(.commands[] | select(.resourceID == "ewr-ord-0-ewr" and .operation == "crossClusterMasqueGateway"))' \
  'del(.cleanup[] | select(.resourceID == "ewr-ord-0-ewr" and .operation == "crossClusterMasqueGateway"))'; do
  candidate="$ROOT/topology-contract-$RANDOM.json"
  jq "$mutation" "$FIXTURE" >"$candidate"
  if bash "$DRIVER" --mothership /usr/bin/true --manifest "$candidate" --run-dir "$ROOT/topology-contract-$RANDOM" --dry-run >"$candidate.out" 2>&1; then
    echo "expected topology contract mutation to fail: $mutation" >&2
    exit 1
  fi
  grep -Fq 'FAIL: manifest schema' "$candidate.out"
done
jq '(.topology.stores.Radar.groups) = [0,1]' "$FIXTURE" >"$ROOT/store-drift.json"
if bash "$DRIVER" --mothership /usr/bin/true --manifest "$ROOT/store-drift.json" --run-dir "$ROOT/store-drift" --dry-run >"$ROOT/store-drift.out" 2>&1; then exit 1; fi
grep -Fq 'FAIL: manifest schema' "$ROOT/store-drift.out"

# A live-shaped manifest has empty qualification arguments. The test Mothership
# records the stable caller-provided identity tuple, while Mothership owns all
# receipt timestamps and returns only a complete typed v4 receipt.
live_manifest="$ROOT/live-manifest.json"
all_masters_preparation="$ROOT/all-masters.prepare.json"
all_masters_intent="$ROOT/all-masters.intent"
create_ewr_request="$ROOT/create-ewr.json"
create_ord_request="$ROOT/create-ord.json"
authority_request="$ROOT/authority-request.json"
printf 'test all-masters preparation\n' >"$all_masters_preparation"
printf '{"name":"task-ewr","deploymentMode":"production"}\n' >"$create_ewr_request"
printf '{"name":"task-ord","deploymentMode":"production"}\n' >"$create_ord_request"
# Paired bootstrap is a mutation too: the live ledger/cleanup assertions below
# must retain all eighteen directional records with this new CLI action.
printf '{"configureLiveArgs":["configurePair"],"withdrawLiveArgs":["withdraw"]}\n' >"$authority_request"
all_masters_preparation_sha256="$(sha256sum "$all_masters_preparation" | cut -d' ' -f1)"
create_ewr_sha256="$(sha256sum "$create_ewr_request" | cut -d' ' -f1)"
create_ord_sha256="$(sha256sum "$create_ord_request" | cut -d' ' -f1)"
authority_sha256="$(sha256sum "$authority_request" | cut -d' ' -f1)"
jq --arg all_masters_preparation "$all_masters_preparation" --arg all_masters_preparation_sha256 "$all_masters_preparation_sha256" --arg all_masters_intent "$all_masters_intent" \
  --arg create_ewr_request "$create_ewr_request" --arg create_ewr_sha256 "$create_ewr_sha256" \
  --arg create_ord_request "$create_ord_request" --arg create_ord_sha256 "$create_ord_sha256" \
  --arg authority_request "$authority_request" --arg authority_sha256 "$authority_sha256" '
  .execution.fixtureOnly = false |
  .execution.liveCommandArgumentsResolved = true |
  .qualification = {
    allMastersOperationUUID:"00000000000000000000000000000100",
    probeDeploymentIDs:{
      ewr:(11 * 281474976710656 + 1),
      ord:(11 * 281474976710656 + 2),
      lan:(11 * 281474976710656 + 3)
    }
  } |
  .materialization = {
    allMastersPreparation:{path:$all_masters_preparation,sha256:$all_masters_preparation_sha256},
    allMastersIntent:{path:$all_masters_intent},
    createRequests:{ewr:{path:$create_ewr_request,sha256:$create_ewr_sha256,name:"task-ewr"},ord:{path:$create_ord_request,sha256:$create_ord_sha256,name:"task-ord"}},
    authorityRequests:([.topology.masque.paths[].authorities[].id] | map({key:.,value:{path:$authority_request,sha256:$authority_sha256,configureLiveArgs:["configurePair"],withdrawLiveArgs:["withdraw"]}}) | from_entries)
  } |
  (.resources[] |= if .type == "cluster" and .id == "ewr" then .name = "task-ewr" elif .type == "cluster" and .id == "ord" then .name = "task-ord" else . end) |
  (.commands[] |= (if .operation == "createCluster" and .resourceID == "ewr" then .liveArgs = ["@" + $create_ewr_request]
                    elif .operation == "nametagAllMasters" then .liveArgs = [$all_masters_intent]
                    elif .operation == "crossClusterMasqueGateway" and .args == ["configure"] then .liveArgs = ["configurePair"]
                    else .liveArgs = [] end | .liveArgsResolved = true)) |
  (.cleanup[] |= (if .operation == "removeCluster" and .resourceID == "ewr" then .liveArgs = ["task-ewr"]
                   elif .operation == "crossClusterMasqueGateway" and .args == ["withdraw"] then .liveArgs = ["withdraw"]
                   else .liveArgs = [] end | .liveArgsResolved = true)) |
  (.chaos[] |= (.injection.liveArgs = [] | .injection.liveArgsResolved = true | .observation.liveArgs = [] | .observation.liveArgsResolved = true))' "$FIXTURE" >"$live_manifest"
fake_mothership="$ROOT/fake-mothership"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -Eeuo pipefail' \
  'if [[ ${1:-} == help ]]; then' \
  '  { jq -r '\''.commands[].operation,.cleanup[].operation,.chaos[].injection.operation,.chaos[].observation.operation'\'' "$QUALIFICATION_TEST_MANIFEST"; echo prepareNametagAllMasters; } | sort -u' \
  '  exit 0' \
  'fi' \
  'if [[ ${1:-} == nametagQualificationCapabilities ]]; then' \
  '  [[ ${QUALIFICATION_TEST_CAPABILITY_MODE:-valid} != command-error ]] || exit 1' \
  '  jq -nc --argjson adapters "$(jq -c '\''[.chaos[] | . as $row | ["injection","observation"][] as $direction | $row[$direction] | {rowID:$row.id,direction:$direction,operation:.operation,implemented:true}]'\'' "$QUALIFICATION_TEST_MANIFEST")" '\''{schema:"mothership.nametag-qualification-capabilities.v1",receiptProtocolVersion:4,adapters:$adapters} | if env.QUALIFICATION_TEST_CAPABILITY_MODE == "false" then .adapters[0].implemented=false | .adapters[0].reason="missing typed owner" elif env.QUALIFICATION_TEST_CAPABILITY_MODE == "missing" then del(.adapters[0]) elif env.QUALIFICATION_TEST_CAPABILITY_MODE == "duplicate" then .adapters[1]=.adapters[0] elif env.QUALIFICATION_TEST_CAPABILITY_MODE == "malformed" then .receiptProtocolVersion=3 else . end'\''' \
  '  exit 0' \
  'fi' \
  'if [[ ${1:-} == prepareNametagAllMasters ]]; then' \
  '  [[ $# == 3 && -r $2 ]] || exit 1' \
  '  printf '\''prepared all-masters intent\n'\'' >"$3"' \
  '  exit 0' \
  'fi' \
  'if [[ -n ${QUALIFICATION_TEST_COMMAND_LOG:-} ]]; then printf '\''%s\n'\'' "$1" >>"$QUALIFICATION_TEST_COMMAND_LOG"; fi' \
  'if [[ ${1:-} =~ ^nametag(Chaos|Observe)[A-Z][A-Za-z0-9]*$ ]]; then' \
  '  row_id="$(jq -r --arg operation "$1" '\''.chaos[] | select(.injection.operation == $operation or .observation.operation == $operation) | .id'\'' "$QUALIFICATION_TEST_MANIFEST")"' \
  '  direction=observation; [[ $1 == nametagChaos* ]] && direction=injection' \
  '  [[ ${PRODIGY_NAMETAG_QUALIFICATION_RUN_UUID:-} =~ ^0x[0-9a-f]{2,}$ && ${PRODIGY_NAMETAG_QUALIFICATION_ALL_MASTERS_OPERATION_UUID:-} =~ ^0x[0-9a-f]{2,}$ ]] || exit 1' \
  '  printf '\''%s\t%s\t%s\t%s\t%s\t%s\t%s\n'\'' "$1" "$#" "$PRODIGY_NAMETAG_QUALIFICATION_RUN_UUID" "$PRODIGY_NAMETAG_QUALIFICATION_ALL_MASTERS_OPERATION_UUID" "$PRODIGY_NAMETAG_QUALIFICATION_EWR_PROBE_DEPLOYMENT_ID" "$PRODIGY_NAMETAG_QUALIFICATION_ORD_PROBE_DEPLOYMENT_ID" "$PRODIGY_NAMETAG_QUALIFICATION_LAN_PROBE_DEPLOYMENT_ID" >>"$QUALIFICATION_TEST_ENV_LOG"' \
  '  receipt_run="${PRODIGY_NAMETAG_QUALIFICATION_RUN_UUID#0x}"; receipt_all_masters="${PRODIGY_NAMETAG_QUALIFICATION_ALL_MASTERS_OPERATION_UUID#0x}"; printf -v receipt_run "%032s" "$receipt_run"; printf -v receipt_all_masters "%032s" "$receipt_all_masters"; export PRODIGY_NAMETAG_QUALIFICATION_RUN_UUID="${receipt_run// /0}" PRODIGY_NAMETAG_QUALIFICATION_ALL_MASTERS_OPERATION_UUID="${receipt_all_masters// /0}"' \
  '  deadline="$(jq -r --arg row_id "$row_id" '\''.chaos[] | select(.id == $row_id) | .deadlineSeconds'\'' "$QUALIFICATION_TEST_MANIFEST")"' \
  '  convergence="$(jq -r --arg row_id "$row_id" '\''.chaos[] | select(.id == $row_id) | .convergenceSeconds'\'' "$QUALIFICATION_TEST_MANIFEST")"' \
  '  witnessed_result="$(jq -r --arg row_id "$row_id" '\''.chaos | to_entries[] | select(.value.id == $row_id) | (.key + 1)'\'' "$QUALIFICATION_TEST_MANIFEST")"' \
  '  started=1000000; deadline_at=$((started + deadline * 1000)); convergence_at=$((started + convergence * 1000))' \
  '  witness="nametag-qualification-v4:$row_id:fake-canonical-convergence"; witness_digest="$(printf %s "$witness" | sha256sum | cut -d '\'' '\'' -f1)"' \
  '  jq -nc --arg operation "$1" --arg row_id "$row_id" --arg direction "$direction" --arg run_uuid "$PRODIGY_NAMETAG_QUALIFICATION_RUN_UUID" --arg all_masters "$PRODIGY_NAMETAG_QUALIFICATION_ALL_MASTERS_OPERATION_UUID" --arg witness "$witness" --arg witness_digest "$witness_digest" --argjson ewr "$PRODIGY_NAMETAG_QUALIFICATION_EWR_PROBE_DEPLOYMENT_ID" --argjson ord "$PRODIGY_NAMETAG_QUALIFICATION_ORD_PROBE_DEPLOYMENT_ID" --argjson lan "$PRODIGY_NAMETAG_QUALIFICATION_LAN_PROBE_DEPLOYMENT_ID" --argjson started "$started" --argjson deadline_at "$deadline_at" --argjson convergence_at "$convergence_at" --argjson deadline "$deadline" --argjson convergence "$convergence" --argjson witnessed_result "$witnessed_result" '\''{success:true,operation:$operation,rowID:$row_id,completed:true,receipt:{protocolVersion:4,runUUID:$run_uuid,rowID:$row_id,direction:$direction,allMastersOperationUUID:$all_masters,applicationReceipts:[{clusterUUID:"00000000000000000000000000000001",deploymentID:$ewr,witnessDigest:("a" * 64)},{clusterUUID:"00000000000000000000000000000002",deploymentID:$ord,witnessDigest:("b" * 64)},{clusterUUID:"00000000000000000000000000000003",deploymentID:$lan,witnessDigest:("c" * 64)}],startedAtMilliseconds:$started,deadlineAtMilliseconds:$deadline_at,convergenceDeadlineAtMilliseconds:$convergence_at,observedAtMilliseconds:$convergence_at,deadlineSeconds:$deadline,convergenceSeconds:$convergence,witnessedResult:$witnessed_result,canonicalConvergenceWitness:$witness,witnessDigest:$witness_digest}}'\''' \
  'fi' >"$fake_mothership"
chmod +x "$fake_mothership"
missing_operation_mothership="$ROOT/missing-operation-mothership"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -Eeuo pipefail' \
  'if [[ ${1:-} == help ]]; then' \
  '  jq -r '\''.commands[].operation,.cleanup[].operation,.chaos[].injection.operation,.chaos[].observation.operation'\'' "$QUALIFICATION_TEST_MANIFEST" | sort -u | grep -Fvx -- authorizeBGPOriginPrefix' \
  '  exit 0' \
  'fi' \
  'exec "'$fake_mothership'" "$@"' >"$missing_operation_mothership"
chmod +x "$missing_operation_mothership"
if QUALIFICATION_TEST_MANIFEST="$live_manifest" QUALIFICATION_TEST_ENV_LOG="$ROOT/missing-operation-env" \
  PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
  bash "$DRIVER" --mothership "$missing_operation_mothership" --manifest "$live_manifest" --run-dir "$ROOT/missing-operation-run" --live >"$ROOT/missing-operation.out" 2>&1; then
  echo 'expected missing Mothership operation to fail' >&2
  exit 1
fi
grep -Fq 'Mothership lacks required operation authorizeBGPOriginPrefix' "$ROOT/missing-operation.out"

# Capability names alone are insufficient: every manifest adapter must have a
# real executor before createCluster can run. Cleanup stays usable if a later
# binary reports a missing owner.
for mode in false missing duplicate malformed command-error; do
  command_log="$ROOT/capability-$mode-commands"
  : >"$command_log"
  if QUALIFICATION_TEST_MANIFEST="$live_manifest" QUALIFICATION_TEST_ENV_LOG="$ROOT/capability-$mode-env" \
    QUALIFICATION_TEST_COMMAND_LOG="$command_log" QUALIFICATION_TEST_CAPABILITY_MODE="$mode" \
    PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
    bash "$DRIVER" --mothership "$fake_mothership" --manifest "$live_manifest" --run-dir "$ROOT/capability-$mode-run" --live >"$ROOT/capability-$mode.out" 2>&1; then
    echo "expected capability preflight mode $mode to fail" >&2
    exit 1
  fi
  grep -Fq 'qualification capability preflight' "$ROOT/capability-$mode.out"
  ! grep -Fqx createCluster "$command_log"
done
QUALIFICATION_TEST_MANIFEST="$live_manifest" QUALIFICATION_TEST_ENV_LOG="$ROOT/cleanup-env" \
  QUALIFICATION_TEST_CAPABILITY_MODE=false PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
  bash "$DRIVER" --mothership "$fake_mothership" --manifest "$live_manifest" --run-dir "$ROOT/cleanup-run" --live --cleanup >/dev/null
# Provision first through Mothership, then materialize observed IDs. Existing
# mode must run the same capability/native receipt gates without pretending to
# own resources created by the campaign provisioning ledger.
existing_run="$ROOT/existing-run"
existing_commands="$ROOT/existing-commands.log"
if QUALIFICATION_TEST_MANIFEST="$live_manifest" QUALIFICATION_TEST_ENV_LOG="$ROOT/existing-env" \
  QUALIFICATION_TEST_COMMAND_LOG="$existing_commands" \
  PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
  bash "$DRIVER" --mothership "$fake_mothership" --manifest "$live_manifest" \
    --run-dir "$existing_run" --live --qualify-existing >"$ROOT/existing.out" 2>&1; then
  echo 'fake Mothership unexpectedly passed existing-mode restart checkpoint' >&2; exit 1
fi
[[ ! -e "$existing_run/receipts/chaos-mothership-restart-resume.json" ]]
test "$(jq -s '[.[] | select(.kind=="resource" or .kind=="cleanup")] | length' "$existing_run/resource-ledger.jsonl")" = 0
test "$(jq -r 'select(.kind=="header") | .executionMode' "$existing_run/resource-ledger.jsonl")" = existing
! grep -Eq '^(createCluster|removeCluster|deploy|cancelDeployment|enrollClusterPair|crossClusterMasqueGateway)$' "$existing_commands"
grep -Fxq nametagAllMasters "$existing_commands"
test "$(wc -l <"$ROOT/existing-env" | tr -d ' ')" = 33
if QUALIFICATION_TEST_MANIFEST="$live_manifest" PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
  bash "$DRIVER" --mothership "$fake_mothership" --manifest "$live_manifest" \
    --run-dir "$existing_run" --live --cleanup >"$ROOT/existing-cleanup.out" 2>&1; then
  echo 'existing qualification ledger unexpectedly became provisioning ownership' >&2; exit 1
fi
grep -Fq 'ledger header fields' "$ROOT/existing-cleanup.out"
if QUALIFICATION_TEST_MANIFEST="$live_manifest" QUALIFICATION_TEST_CAPABILITY_MODE=false \
  PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
  bash "$DRIVER" --mothership "$fake_mothership" --manifest "$live_manifest" \
    --run-dir "$ROOT/existing-missing-capability" --live --qualify-existing >"$ROOT/existing-missing-capability.out" 2>&1; then
  echo 'existing mode skipped capability preflight' >&2; exit 1
fi
grep -Fq 'qualification capability preflight' "$ROOT/existing-missing-capability.out"

live_run="$ROOT/live-run"
env_log="$ROOT/qualification-environment.tsv"
# A fake cannot supply the kernel-pinned row 17 process checkpoint; its
# synthetic receipts must not be promoted to a completed restart witness.
if QUALIFICATION_TEST_MANIFEST="$live_manifest" QUALIFICATION_TEST_ENV_LOG="$env_log" \
  PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
  bash "$DRIVER" --mothership "$fake_mothership" --manifest "$live_manifest" --run-dir "$live_run" --live >/dev/null; then
  echo 'fake Mothership unexpectedly passed the real restart checkpoint' >&2; exit 1
fi
[[ ! -e "$live_run/receipts/chaos-mothership-restart-resume.json" ]]
live_uuid="$(jq -r 'select(.kind == "header") | .campaignRunUUID' "$live_run/resource-ledger.jsonl")"
[[ $live_uuid =~ ^[0-9a-f]{32}$ ]]
canonical_cli_uuid(){ local value=$1; [[ $value =~ ^[0-9a-f]{32}$ && $value != 00000000000000000000000000000000 ]] || return 1; while [[ ${#value} -gt 2 && ${value:0:2} == 00 ]]; do value=${value:2}; done; printf '0x%s' "$value"; }
expected_run_cli="$(canonical_cli_uuid "$live_uuid")"
expected_all_masters_cli="$(canonical_cli_uuid "$(jq -r '.qualification.allMastersOperationUUID' "$live_manifest")")"
[[ $expected_all_masters_cli == 0x0100 ]] || {
  echo "leading-zero all-masters UUID did not normalize to 0x0100" >&2
  exit 1
}
test "$(jq -s '[.[] | select(.kind == "resource" and ((.resourceName|type) == "string") and (.argumentsSHA256|test("^[0-9a-f]{64}$")))] | length' "$live_run/resource-ledger.jsonl")" = 25
test "$(wc -l <"$env_log" | tr -d ' ')" = 33
awk -F $'\t' -v run_uuid="$expected_run_cli" \
  -v all_masters="$expected_all_masters_cli" \
  -v ewr_probe="$(jq -r '.qualification.probeDeploymentIDs.ewr' "$live_manifest")" \
  -v ord_probe="$(jq -r '.qualification.probeDeploymentIDs.ord' "$live_manifest")" \
  -v lan_probe="$(jq -r '.qualification.probeDeploymentIDs.lan' "$live_manifest")" \
  'NF == 7 && $2 == 1 && $3 == run_uuid && $4 == all_masters && $5 == ewr_probe && $6 == ord_probe && $7 == lan_probe { valid += 1 } END { exit valid == 33 ? 0 : 1 }' "$env_log"
! rg -q 'PRODIGY_NAMETAG_QUALIFICATION_STARTED_AT_MS|qualificationCommand|qualification_started_at_ms' "$DRIVER"

jq '.qualification.allMastersOperationUUID = "00000000000000000000000000000000"' \
  "$live_manifest" >"$ROOT/zero-all-masters-manifest.json"
if QUALIFICATION_TEST_MANIFEST="$ROOT/zero-all-masters-manifest.json" \
  QUALIFICATION_TEST_ENV_LOG="$ROOT/zero-all-masters-env.log" \
  PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 \
  PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
  bash "$DRIVER" --mothership "$fake_mothership" \
    --manifest "$ROOT/zero-all-masters-manifest.json" \
    --run-dir "$ROOT/zero-all-masters-run" --live \
    >"$ROOT/zero-all-masters.out" 2>&1; then
  echo "zero all-masters UUID unexpectedly reached qualification dispatch" >&2
  exit 1
fi
grep -Fq "invalid all-masters UUID" "$ROOT/zero-all-masters.out"

jq -c 'select(.kind != "phase" or .phase != "chaos")' "$live_run/resource-ledger.jsonl" >"$live_run/resource-ledger.next"
mv "$live_run/resource-ledger.next" "$live_run/resource-ledger.jsonl"
: >"$env_log"
# A fake cannot supply the kernel-pinned row 17 process checkpoint; its
# synthetic receipts must not be promoted to a completed restart witness.
if QUALIFICATION_TEST_MANIFEST="$live_manifest" QUALIFICATION_TEST_ENV_LOG="$env_log" \
  PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
  bash "$DRIVER" --mothership "$fake_mothership" --manifest "$live_manifest" --run-dir "$live_run" --live >/dev/null; then
  echo 'fake Mothership unexpectedly passed the real restart checkpoint' >&2; exit 1
fi
[[ ! -e "$live_run/receipts/chaos-mothership-restart-resume.json" ]]
test "$live_uuid" = "$(jq -r 'select(.kind == "header") | .campaignRunUUID' "$live_run/resource-ledger.jsonl")"
test "$(wc -l <"$env_log" | tr -d ' ')" = 33

# A prepared intent is ledger-bound.  Replaying the all-masters phase after a
# post-preparation replacement must fail before it can dispatch that operation.
printf 'tampered all-masters intent\n' >"$all_masters_intent"
jq -c 'select(.kind != "phase" or .phase != "all-masters")' "$live_run/resource-ledger.jsonl" >"$live_run/resource-ledger.next"
mv "$live_run/resource-ledger.next" "$live_run/resource-ledger.jsonl"
if QUALIFICATION_TEST_MANIFEST="$live_manifest" QUALIFICATION_TEST_ENV_LOG="$ROOT/tampered-env" \
  PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
  bash "$DRIVER" --mothership "$fake_mothership" --manifest "$live_manifest" --run-dir "$live_run" --live >"$ROOT/tampered.out" 2>&1; then
  echo 'expected tampered materialized intent to fail' >&2
  exit 1
fi
grep -Fq 'all-masters intent is absent, tampered, or was not prepared for this ledger' "$ROOT/tampered.out"

mkdir "$ROOT/missing-ledger-field"
jq -c 'if .kind == "header" then del(.campaignRunUUID) else . end' "$live_run/resource-ledger.jsonl" >"$ROOT/missing-ledger-field/resource-ledger.jsonl"
if bash "$DRIVER" --mothership /usr/bin/true --manifest "$live_manifest" --run-dir "$ROOT/missing-ledger-field" --dry-run >"$ROOT/missing-ledger-field.out" 2>&1; then exit 1; fi
grep -Fq 'FAIL: ledger header fields' "$ROOT/missing-ledger-field.out"

# A broad or forged receipt cannot replace v4's row/direction, three-probe,
# timestamp, and canonical SHA-256 witness checks.
bad_mothership="$ROOT/bad-mothership"
sed 's/receipt:{protocolVersion:4/receipt:{protocolVersion:3/' "$fake_mothership" >"$bad_mothership"
chmod +x "$bad_mothership"
if QUALIFICATION_TEST_MANIFEST="$live_manifest" QUALIFICATION_TEST_ENV_LOG="$ROOT/bad-env" \
  PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
  bash "$DRIVER" --mothership "$bad_mothership" --manifest "$live_manifest" --run-dir "$ROOT/bad-run" --live >"$ROOT/bad.out" 2>&1; then
  echo 'expected non-v4 receipt to fail' >&2
  exit 1
fi
grep -Fq 'completed typed v4 Mothership receipt' "$ROOT/bad.out"

# The supplied fixture deliberately has no resolved live identities.  A live
# invocation must fail before Mothership help, deployment, or chaos can run.
if PRODIGY_NAMETAG_THREE_CLUSTER_LIVE=1 PRODIGY_MOTHERSHIP_TIDESDB_PATH=unit \
  bash "$DRIVER" --mothership /usr/bin/true --manifest "$FIXTURE" --run-dir "$ROOT/live-fixture" --live >"$ROOT/live-fixture.out" 2>&1; then
  echo 'expected fixture-only live invocation to fail' >&2
  exit 1
fi
grep -Fq 'fixture-only or has unresolved live command arguments' "$ROOT/live-fixture.out"
grep -Fq 'completed typed v4 Mothership receipt' "$DRIVER"

# Exercise the real driver pidfd helper only on Linux. This is an owned
# bounded test child, never a Mothership qualification result.
if [[ -r /proc/self/stat && -r /proc/sys/kernel/random/boot_id ]]; then
  sed -n '/^signal_checkpoint_child(){/,/^}/p' "$DRIVER" >"$ROOT/pidfd-helper.sh"
  # shellcheck source=/dev/null
  source "$ROOT/pidfd-helper.sh"
  /bin/sleep 20 & child=$!
  start="$(python3 - "$child" <<'PYPROC'
import sys
with open('/proc/' + sys.argv[1] + '/stat', encoding='ascii') as stat:
    print(stat.read().rsplit(')', 1)[1].split()[19])
PYPROC
)"
  boot="$(cat /proc/sys/kernel/random/boot_id)"
  digest="$(sha256sum /bin/sleep | cut -d' ' -f1)"
  for ((attempt=0; attempt<100; ++attempt)); do
    [[ $(sha256sum "/proc/$child/exe" 2>/dev/null | cut -d' ' -f1) == "$digest" ]] && break
    sleep 0.01
  done
  [[ $(sha256sum "/proc/$child/exe" | cut -d' ' -f1) == "$digest" ]]
  [[ $child != $$ && $start =~ ^[0-9]+$ && $start -gt 0 ]]
  ! signal_checkpoint_child "$child" "$((start + 1))" "$boot" "$digest"
  ! signal_checkpoint_child "$child" "$start" "$boot" "$(printf '%064d' 0)"
  ! signal_checkpoint_child "$$" "$start" "$boot" "$digest"
  kill -0 "$child"
  signal_checkpoint_child "$child" "$start" "$boot" "$digest"
  status=0; wait "$child" || status=$?
  [[ $status == 143 ]]
fi

echo 'PASS: nametag three-cluster frozen chaos matrix, topology, and cleanup contract'
