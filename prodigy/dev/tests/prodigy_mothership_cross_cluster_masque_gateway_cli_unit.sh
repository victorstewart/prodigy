#!/usr/bin/env bash
set -euo pipefail

# Exercises the compiled CLI parser only.  A valid slots suffix reaches the
# isolated registry's missing-pair lookup; an out-of-range suffix must fail
# before that lookup or any gateway authority can be persisted.
mothership_bin=${1:?usage: $0 MOTHERSHIP_BINARY TASK_RUN_DIRECTORY}
task_run_directory=${2:?usage: $0 MOTHERSHIP_BINARY TASK_RUN_DIRECTORY}
[[ -x $mothership_bin && -d $task_run_directory ]] || exit 2
rg_bin=${RG_BIN:-rg}
command -v "$rg_bin" >/dev/null

scratch=$(mktemp -d "$task_run_directory/mothership-masque-slots.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT

pair_operation=0x01
local_machine=0x02
peer_machine=0x03
artifact_sha=$(printf 'a%.0s' {1..64})
local_identity_sha=$(printf 'b%.0s' {1..64})
peer_identity_sha=$(printf 'c%.0s' {1..64})
peer_trust_sha=$(printf 'd%.0s' {1..64})
base=(configure "$pair_operation" "$local_machine" "$peer_machine" listener
      203.0.113.10 443 "$artifact_sha" 1 "$local_identity_sha"
      "$peer_identity_sha" "$peer_trust_sha" 1)
pair_base=(configurePair "${base[@]:1}")

expect_lookup() {
  local label=$1
  shift
  if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$scratch/$label.tidesdb" "$mothership_bin" \
      crossClusterMasqueGateway "${base[@]}" "$@" >"$scratch/$label.log" 2>&1; then
    echo "$label unexpectedly configured an absent pair" >&2
    exit 1
  fi
  "$rg_bin" -q 'crossClusterMasqueGateway success=0 .*failure=.*record not found' "$scratch/$label.log"
  ! "$rg_bin" -q 'usage: crossClusterMasqueGateway' "$scratch/$label.log"
}

expect_rejected_before_lookup() {
  local label=$1
  shift
  if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$scratch/$label.tidesdb" "$mothership_bin" \
      crossClusterMasqueGateway "${base[@]}" "$@" >"$scratch/$label.log" 2>&1; then
    echo "$label unexpectedly succeeded" >&2
    exit 1
  fi
  "$rg_bin" -q 'usage: crossClusterMasqueGateway' "$scratch/$label.log"
  ! "$rg_bin" -q 'record not found' "$scratch/$label.log"
  [[ ! -e $scratch/$label.tidesdb ]]
}

expect_pair_lookup() {
  local label=$1
  shift
  if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$scratch/$label.tidesdb" "$mothership_bin" \
      crossClusterMasqueGateway "${pair_base[@]}" "$@" >"$scratch/$label.log" 2>&1; then
    echo "$label unexpectedly configured an absent reciprocal pair" >&2
    exit 1
  fi
  "$rg_bin" -q 'crossClusterMasqueGateway success=0 .*failure=.*record not found' "$scratch/$label.log"
  ! "$rg_bin" -q 'usage: crossClusterMasqueGateway' "$scratch/$label.log"
}

expect_pair_rejected_before_lookup() {
  local label=$1
  shift
  if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$scratch/$label.tidesdb" "$mothership_bin" \
      crossClusterMasqueGateway "${pair_base[@]}" "$@" >"$scratch/$label.log" 2>&1; then
    echo "$label unexpectedly succeeded" >&2
    exit 1
  fi
  "$rg_bin" -q 'usage: crossClusterMasqueGateway' "$scratch/$label.log"
  ! "$rg_bin" -q 'record not found' "$scratch/$label.log"
  [[ ! -e $scratch/$label.tidesdb ]]
}

# Legacy no-suffix behavior stays valid with default slots. All three exact
# slot values, a distinct gateway/tunnel pair, and artifact forms must reach
# pair lookup.
expect_lookup legacy-default
for slot in 0 1 2; do
  expect_lookup "slot-$slot" --slots "$slot" "$slot"
done
: >"$scratch/artifact.blob"
expect_lookup legacy-artifact "$scratch/artifact.blob"
expect_lookup artifact-and-slots "$scratch/artifact.blob" --slots 1 2
expect_lookup distinct-slots --slots 0 2

# configurePair retains the exact configure input grammar and must reject bad
# syntax before it can open the pair registry.  A syntactically valid request
# reaches only the missing enrollment lookup, so it cannot create either half.
expect_pair_lookup pair-default
expect_pair_lookup pair-distinct-slots --slots 0 2
expect_pair_rejected_before_lookup pair-slot-too-large --slots 3 0
expect_pair_rejected_before_lookup pair-slot-missing --slots 1
expect_pair_rejected_before_lookup pair-wrong-flag --slot 1 0

expect_rejected_before_lookup slot-too-large --slots 3 0
expect_rejected_before_lookup slot-negative --slots -1 0
expect_rejected_before_lookup slot-plus --slots +1 0
expect_rejected_before_lookup slot-noncanonical --slots 01 0
expect_rejected_before_lookup slot-missing --slots 1
expect_rejected_before_lookup slot-wrong-flag --slot 1 0

# The one-shot remote-runtime repair refuses malformed target identity before
# resolving an artifact or opening its mutation registry. This shares the
# isolated CLI boundary without contacting a machine.
repair_label=repair-invalid-identity
if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="$scratch/$repair_label.tidesdb" "$mothership_bin" \
    repairRemoteCloudMachineRuntime cluster-report-test not-a-member 0x1 /nonexistent-bundle not-a-linux-machine-id --check \
    >"$scratch/$repair_label.log" 2>&1; then
  echo "$repair_label unexpectedly succeeded" >&2
  exit 1
fi
"$rg_bin" -q 'machine UUID, operation ID, or expected Linux machine ID is invalid' "$scratch/$repair_label.log"
[[ ! -e $scratch/$repair_label.tidesdb ]]

echo 'PASS: cross-cluster MASQUE gateway configure/configurePair CLI parsing and remote repair identity guard'
