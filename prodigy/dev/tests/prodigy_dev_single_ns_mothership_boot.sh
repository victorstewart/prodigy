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
   echo "FAIL: local test-cluster boot expects prodigy and mothership from the same build/install directory"
   exit 2
fi

timestamp="$(date -u +%Y%m%d-%H%M%S)"
if [[ -z "${WORKSPACE_ROOT}" ]]
then
   WORKSPACE_ROOT="/tmp/nametag-test-local-1brain-${timestamp}"
else
   WORKSPACE_ROOT="$(realpath -m "${WORKSPACE_ROOT}")"
fi

if [[ -z "${CLUSTER_NAME}" ]]
then
   CLUSTER_NAME="test-local-1brain-${timestamp}"
fi

mothership_db_path="$(mktemp -u /tmp/prodigy-mothership-test-local-1brain-XXXXXX.db)"
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

read -r -d '' REQUEST_JSON <<EOF || true
{
  "name": "${CLUSTER_NAME}",
  "deploymentMode": "test",
  "nBrains": 1,
  "machineSchemas": [
    {
      "schema": "test-brain",
      "kind": "vm",
      "vmImageURI": "test://netns-local"
    }
  ],
  "test": {
    "workspaceRoot": "${WORKSPACE_ROOT}",
    "machineCount": 1,
    "brainBootstrapFamily": "ipv4",
    "enableFakeIpv4Boundary": false,
    "host": {
      "mode": "local"
    }
  }
}
EOF

echo "creating test cluster via mothership createCluster"
echo "  clusterName=${CLUSTER_NAME}"
echo "  workspaceRoot=${WORKSPACE_ROOT}"

set +e
timeout --preserve-status -k 3s 90s \
   env \
      PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      PRODIGY_MOTHERSHIP_TEST_HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh" \
      "${MOTHERSHIP_BIN}" createCluster "${REQUEST_JSON}"
status="$?"
set -e

if [[ "${status}" -eq 0 ]]
then
   set +e
   remove_output="$(run_mothership removeCluster "${CLUSTER_NAME}" 2>&1)"
   remove_status="$?"
   set -e

   if [[ "${remove_status}" -ne 0 ]]
   then
      echo "${remove_output}"
      echo "FAIL: removeCluster exited with status ${remove_status} for local one-brain boot smoke"
      exit 1
   fi

   if ! grep -q "removeCluster success=1" <<< "${remove_output}"
   then
      echo "${remove_output}"
      echo "FAIL: removeCluster did not report success for local one-brain boot smoke"
      exit 1
   fi

   cluster_removed=1
   echo "PASS: local one-brain mothership boot smoke"
   exit 0
fi

if [[ -f "${WORKSPACE_ROOT}/test-cluster-runner.log" ]]
then
   echo "--- runner log ---"
   sed -n '1,160p' "${WORKSPACE_ROOT}/test-cluster-runner.log"
fi

if [[ -f "${WORKSPACE_ROOT}/brain1.start1.stdout.log" ]]
then
   echo "--- brain1 log ---"
   sed -n '1,200p' "${WORKSPACE_ROOT}/brain1.start1.stdout.log"
fi

if [[ "${status}" -eq 124 ]]
then
   echo "FAIL: mothership createCluster timed out for local one-brain boot smoke"
else
   echo "FAIL: mothership createCluster exited with status ${status} for local one-brain boot smoke"
fi
exit 1
