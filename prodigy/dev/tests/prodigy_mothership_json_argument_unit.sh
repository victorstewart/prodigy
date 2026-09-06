#!/usr/bin/env bash
set -Eeuo pipefail

mothership_bin="${1:-}"
[[ -x "${mothership_bin}" ]] || {
   echo "usage: $0 /path/to/mothership" >&2
   exit 2
}

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

request='{"name":"json-argument-test","provider":"aws","mode":"awsImds","scope":"test/us-east-1","allowPropagateToProdigy":false}'
request_file="${workdir}/request.json"
printf '%s\n' "${request}" >"${request_file}"
invalid_file="${workdir}/invalid.json"
printf '{\n' >"${invalid_file}"

run_credential()
{
   local source="$1"
   local output="$2"
   local database="${workdir}/$3.tidesdb"
   PRODIGY_MOTHERSHIP_TIDESDB_PATH="${database}" "${mothership_bin}" createProviderCredential "${source}" >"${output}" 2>&1
}

run_credential "${request}" "${workdir}/inline.log" inline
printf '%s\n' "${request}" | PRODIGY_MOTHERSHIP_TIDESDB_PATH="${workdir}/stdin.tidesdb" \
   "${mothership_bin}" createProviderCredential - >"${workdir}/stdin.log" 2>&1
run_credential "@${request_file}" "${workdir}/file.log" file

for output in "${workdir}/inline.log" "${workdir}/stdin.log" "${workdir}/file.log"
do
   rg -qx 'createProviderCredential success=1 created=1' "${output}" || {
      echo "credential input source did not succeed: ${output}" >&2
      cat "${output}" >&2
      exit 1
   }
done
# Creation timestamps differ between independent stores; compare their actual profile fields.
for source in inline stdin file; do
   sed -E 's/createdAtMs=[0-9]+/createdAtMs=TIME/g; s/updatedAtMs=[0-9]+/updatedAtMs=TIME/g' \
      "${workdir}/${source}.log" > "${workdir}/${source}.normalized"
done
cmp "${workdir}/inline.normalized" "${workdir}/stdin.normalized"
cmp "${workdir}/inline.normalized" "${workdir}/file.normalized"

if PRODIGY_MOTHERSHIP_TIDESDB_PATH="${workdir}/invalid-json.tidesdb" \
   "${mothership_bin}" createProviderCredential "@${invalid_file}" >"${workdir}/invalid-json.log" 2>&1
then
   echo "invalid JSON argument file unexpectedly succeeded" >&2
   exit 1
fi
rg -qx 'invalid json for createProviderCredential' "${workdir}/invalid-json.log"

if PRODIGY_MOTHERSHIP_TIDESDB_PATH="${workdir}/missing.tidesdb" \
   "${mothership_bin}" reserveApplicationID local "@${workdir}/missing.json" >"${workdir}/missing.log" 2>&1
then
   echo "missing JSON argument file unexpectedly succeeded" >&2
   exit 1
fi
rg -qx 'reserveApplicationID failed to read json file' "${workdir}/missing.log"

if PRODIGY_MOTHERSHIP_TIDESDB_PATH="${workdir}/deploy-missing.tidesdb" \
   "${mothership_bin}" deploy local "@${workdir}/missing-deploy.json" "${workdir}/unused.blob" >"${workdir}/deploy-missing.log" 2>&1
then
   echo "missing deployment JSON argument file unexpectedly succeeded" >&2
   exit 1
fi
rg -qx 'deploy failed to read json file' "${workdir}/deploy-missing.log"

if PRODIGY_MOTHERSHIP_TIDESDB_PATH="${workdir}/invalid.tidesdb" \
   "${mothership_bin}" reserveServiceID local '@' >"${workdir}/empty-path.log" 2>&1
then
   echo "empty JSON argument path unexpectedly succeeded" >&2
   exit 1
fi
rg -qx 'reserveServiceID @path is empty' "${workdir}/empty-path.log"

help="$(${mothership_bin} help)"
[[ "${help}" == *'deploy [target: local|clusterName|clusterUUID] [json|-|@path] [path to container blob]'* ]]
[[ "${help}" == *'reserveApplicationID [target: local|clusterName|clusterUUID] [json|-|@path]'* ]]
[[ "${help}" == *'reserveServiceID [target: dev|prod|local|clusterName|clusterUUID] [json|-|@path]'* ]]

echo "PASS: mothership JSON arguments accept inline, stdin, and @file sources and reject invalid paths"
