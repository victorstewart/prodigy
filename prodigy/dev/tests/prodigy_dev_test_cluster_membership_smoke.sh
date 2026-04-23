#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
WORKSPACE_ROOT="${3:-}"
CLUSTER_NAME="${4:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership [workspace-root] [cluster-name]"
   exit 2
fi

if [[ ! -x "${PRODIGY_BIN}" || ! -x "${MOTHERSHIP_BIN}" ]]
then
   echo "FAIL: prodigy and mothership must both be executable"
   exit 2
fi

PRODIGY_REAL="$(realpath "${PRODIGY_BIN}")"
MOTHERSHIP_REAL="$(realpath "${MOTHERSHIP_BIN}")"
PRODIGY_DIR="$(dirname "${PRODIGY_REAL}")"
MOTHERSHIP_DIR="$(dirname "${MOTHERSHIP_REAL}")"

if [[ "${PRODIGY_DIR}" != "${MOTHERSHIP_DIR}" ]]
then
   echo "FAIL: test-cluster membership smoke expects prodigy and mothership from the same build/install directory"
   exit 2
fi

timestamp="$(date -u +%Y%m%d-%H%M%S)"
if [[ -z "${WORKSPACE_ROOT}" ]]
then
   WORKSPACE_ROOT="/tmp/nametag-test-membership-3brains-${timestamp}"
else
   WORKSPACE_ROOT="$(realpath -m "${WORKSPACE_ROOT}")"
fi

if [[ -z "${CLUSTER_NAME}" ]]
then
   CLUSTER_NAME="test-membership-3brains-${timestamp}"
fi

mothership_db_path="$(mktemp -u /tmp/nametag-mothership-test-membership-XXXXXX.db)"
manifest_path="${WORKSPACE_ROOT}/test-cluster-manifest.json"
cluster_removed=0

cleanup()
{
   set +e
   if [[ -x "${MOTHERSHIP_BIN}" && "${cluster_removed}" -eq 0 ]]
   then
      env \
         PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         PRODIGY_MOTHERSHIP_TEST_HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh" \
         "${MOTHERSHIP_BIN}" removeCluster "${CLUSTER_NAME}" >/dev/null 2>&1 || true
   fi
   rm -rf "${WORKSPACE_ROOT}" "${mothership_db_path}"
}
trap cleanup EXIT

run_mothership()
{
   env \
      PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      PRODIGY_MOTHERSHIP_TEST_HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh" \
      "${MOTHERSHIP_BIN}" "$@"
}

run_cluster_report()
{
   local expected_machines="$1"
   local report_output=""
   local report_rc=0

   set +e
   report_output="$(run_mothership clusterReport "${CLUSTER_NAME}" 2>&1)"
   report_rc=$?
   set -e
   echo "${report_output}"

   if [[ ${report_rc} -ne 0 ]]
   then
      echo "FAIL: clusterReport returned rc=${report_rc}"
      exit 1
   fi

   if ! grep -q "topologyMachines: ${expected_machines}" <<< "${report_output}"
   then
      echo "FAIL: clusterReport did not report topologyMachines=${expected_machines}"
      exit 1
   fi

   if ! grep -q "nMachines: ${expected_machines}" <<< "${report_output}"
   then
      echo "FAIL: clusterReport did not report nMachines=${expected_machines}"
      exit 1
   fi
}

remove_cluster_and_assert_cleanup()
{
   local remove_output=""
   local remove_rc=0

   set +e
   remove_output="$(run_mothership removeCluster "${CLUSTER_NAME}" 2>&1)"
   remove_rc=$?
   set -e
   echo "${remove_output}"

   if [[ ${remove_rc} -ne 0 ]]
   then
      echo "FAIL: removeCluster returned rc=${remove_rc}"
      exit 1
   fi

   if ! grep -q "removeCluster success=1" <<< "${remove_output}"
   then
      echo "FAIL: removeCluster did not report success"
      exit 1
   fi

   cluster_removed=1

   if [[ -e "${WORKSPACE_ROOT}" ]]
   then
      echo "FAIL: test cluster workspace still exists after removeCluster"
      exit 1
   fi
}

assert_manifest_shape()
{
   local expected_machines="$1"
   local expected_brains="$2"

   if [[ ! -f "${manifest_path}" ]]
   then
      echo "FAIL: manifest missing at ${manifest_path}"
      exit 1
   fi

   if ! python - "${manifest_path}" "${expected_machines}" "${expected_brains}" <<'PY'
import json
import sys

manifest_path = sys.argv[1]
expected_machines = int(sys.argv[2])
expected_brains = int(sys.argv[3])

with open(manifest_path, 'r', encoding='utf-8') as fh:
   manifest = json.load(fh)

node_count = len(manifest.get("nodes", []))
brain_count = sum(1 for node in manifest.get("nodes", []) if node.get("role") == "brain")

if not (
   manifest.get("machineCount") == expected_machines
   and manifest.get("brainCount") == expected_brains
   and node_count == expected_machines
   and brain_count == expected_brains
):
   raise SystemExit(1)
PY
   then
      echo "FAIL: manifest shape mismatch expected machines=${expected_machines} brains=${expected_brains}"
      cat "${manifest_path}"
      exit 1
   fi
}

read -r -d '' CREATE_JSON <<EOF || true
{
  "name": "${CLUSTER_NAME}",
  "deploymentMode": "test",
  "nBrains": 3,
  "machineSchemas": [
    {
      "schema": "test-brain",
      "kind": "vm",
      "vmImageURI": "test://netns-local"
    }
  ],
  "test": {
    "workspaceRoot": "${WORKSPACE_ROOT}",
    "machineCount": 3,
    "brainBootstrapFamily": "ipv4",
    "enableFakeIpv4Boundary": false,
    "host": {
      "mode": "local"
    }
  }
}
EOF

echo "creating test cluster via mothership createCluster"
set +e
create_output="$(run_mothership createCluster "${CREATE_JSON}" 2>&1)"
create_rc=$?
set -e
echo "${create_output}"

if [[ ${create_rc} -ne 0 ]]
then
   echo "FAIL: createCluster returned rc=${create_rc}"
   exit 1
fi

if ! grep -q "createCluster success=1" <<< "${create_output}"
then
   echo "FAIL: createCluster did not report success"
   exit 1
fi

assert_manifest_shape 3 3
echo "cluster report after create"
run_cluster_report 3

echo "updating test cluster to 4 machines"
set +e
update_add_output="$(run_mothership setTestClusterMachineCount "${CLUSTER_NAME}" '{"machineCount":4}' 2>&1)"
update_add_rc=$?
set -e
echo "${update_add_output}"

if [[ ${update_add_rc} -ne 0 ]]
then
   echo "FAIL: setTestClusterMachineCount add returned rc=${update_add_rc}"
   exit 1
fi

if ! grep -q "setTestClusterMachineCount success=1" <<< "${update_add_output}"
then
   echo "FAIL: setTestClusterMachineCount add did not report success"
   exit 1
fi

if ! grep -q "topologyMachines=4" <<< "${update_add_output}"
then
   echo "FAIL: setTestClusterMachineCount add did not report topologyMachines=4"
   exit 1
fi

assert_manifest_shape 4 3
echo "cluster report after grow"
run_cluster_report 4

echo "updating test cluster back to 3 machines"
set +e
update_remove_output="$(run_mothership setTestClusterMachineCount "${CLUSTER_NAME}" '{"machineCount":3}' 2>&1)"
update_remove_rc=$?
set -e
echo "${update_remove_output}"

if [[ ${update_remove_rc} -ne 0 ]]
then
   echo "FAIL: setTestClusterMachineCount remove returned rc=${update_remove_rc}"
   exit 1
fi

if ! grep -q "setTestClusterMachineCount success=1" <<< "${update_remove_output}"
then
   echo "FAIL: setTestClusterMachineCount remove did not report success"
   exit 1
fi

if ! grep -q "topologyMachines=3" <<< "${update_remove_output}"
then
   echo "FAIL: setTestClusterMachineCount remove did not report topologyMachines=3"
   exit 1
fi

assert_manifest_shape 3 3
echo "cluster report after shrink"
run_cluster_report 3

echo "attempting invalid shrink below nBrains"
if reject_output="$(run_mothership setTestClusterMachineCount "${CLUSTER_NAME}" '{"machineCount":2}' 2>&1)"
then
   echo "${reject_output}"
   echo "FAIL: setTestClusterMachineCount unexpectedly accepted machineCount=2 below nBrains=3"
   exit 1
fi

echo "${reject_output}"

if ! grep -q "test.machineCount is below nBrains" <<< "${reject_output}"
then
   echo "FAIL: invalid shrink did not report nBrains failure"
   exit 1
fi

assert_manifest_shape 3 3
echo "removing test cluster"
remove_cluster_and_assert_cleanup

echo "PASS: test cluster membership add/remove/reject smoke completed"
