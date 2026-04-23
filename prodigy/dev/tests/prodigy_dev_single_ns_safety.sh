#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "${SCRIPT_DIR}/prodigy_dev_netns_harness.sh" \
   "${PRODIGY_BIN}" \
   --machines=1 \
   --brains=1 \
   --duration=8
