#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "${SCRIPT_DIR}/prodigy_dev_netns_harness.sh" \
   "${PRODIGY_BIN}" \
   --brains=3 \
   --duration=14 \
   --brain-bootstrap-family=private6 \
   --enable-fake-ipv4-boundary=0 \
   --require-brain-log-substring='nRegistered=3 required=3' \
   --require-brain-log-substring='brain transport tls peer verified'
