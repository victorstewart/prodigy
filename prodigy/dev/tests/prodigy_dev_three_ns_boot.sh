#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "${MOTHERSHIP_BIN}" ]]
then
   exec "${SCRIPT_DIR}/prodigy_dev_netns_harness.sh" \
      "${PRODIGY_BIN}" \
      --brains=3 \
      --duration=14 \
      --mothership-bin="${MOTHERSHIP_BIN}"
else
   exec "${SCRIPT_DIR}/prodigy_dev_netns_harness.sh" \
      "${PRODIGY_BIN}" \
      --brains=3 \
      --duration=14
fi
