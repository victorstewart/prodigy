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
   WORKSPACE_ROOT="/tmp/nametag-test-local-3brain-${timestamp}"
else
   WORKSPACE_ROOT="$(realpath -m "${WORKSPACE_ROOT}")"
fi

if [[ -z "${CLUSTER_NAME}" ]]
then
   CLUSTER_NAME="test-local-3brain-${timestamp}"
fi

read -r -d '' REQUEST_JSON <<EOF || true
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
echo "  clusterName=${CLUSTER_NAME}"
echo "  workspaceRoot=${WORKSPACE_ROOT}"

exec env PRODIGY_MOTHERSHIP_TEST_HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh" \
   "${MOTHERSHIP_BIN}" createCluster "${REQUEST_JSON}"
