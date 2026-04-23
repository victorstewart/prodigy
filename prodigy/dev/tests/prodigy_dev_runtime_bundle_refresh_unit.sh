#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"

if [[ ! -f "${HARNESS}" ]]
then
   echo "FAIL: missing harness: ${HARNESS}" >&2
   exit 1
fi

require_line()
{
   local pattern="$1"
   local label="$2"

   if ! rg -q --fixed-strings "${pattern}" "${HARNESS}"
   then
      echo "FAIL: missing ${label}" >&2
      exit 1
   fi
}

require_line 'prodigy_runtime_bundle_needs_refresh()' 'bundle refresh predicate'
require_line 'ensure_prodigy_runtime_bundle_artifact_for_input()' 'bundle refresh guard'
require_line 'cmake --build "${prodigy_dir}" -j"$(nproc)" --target prodigy_bundle prodigy_bundle_sha256 >/dev/null' 'bundle rebuild command'
require_line 'echo "FAIL: runtime bundle artifact is stale for ${input_path}: ${bundle_path}" >&2' 'stale bundle fail-closed message'
require_line 'ensure_prodigy_runtime_bundle_artifact_for_input "${PRODIGY_BIN}" "${prodigy_runtime_bundle_path}"' 'initial runtime bundle refresh call'
require_line 'ensure_prodigy_runtime_bundle_artifact_for_input "${input_path}" "${bundle_path}"' 'update runtime bundle refresh call'

echo "PASS: harness refreshes or rejects stale runtime bundles"
