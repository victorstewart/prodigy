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
[[ "${help}" == *'upsertApiCredentialSet [target: local|clusterName|clusterUUID] [json|-|@path]'* ]]

# This command validates its JSON before it opens a control socket.  The local
# target is intentionally unavailable in this input-contract test; each valid
# source must therefore reach the same non-secret control-target failure.
api_request='{"applicationID":15,"upsertCredentials":[{"name":"input-contract","provider":"test","material":"not-a-secret"}]}'
api_file="${workdir}/api-request.json"
printf '%s\n' "${api_request}" >"${api_file}"
index=0
for source in "${api_request}" - "@${api_file}"; do
   index=$((index + 1))
   output="${workdir}/api-${index}.log"
   if [[ "${source}" == - ]]; then
      printf '%s\n' "${api_request}" | PRODIGY_MOTHERSHIP_TIDESDB_PATH="${workdir}/api.tidesdb" \
         "${mothership_bin}" upsertApiCredentialSet local - >"${output}" 2>&1 && exit 1
   else
      PRODIGY_MOTHERSHIP_TIDESDB_PATH="${workdir}/api.tidesdb" \
         "${mothership_bin}" upsertApiCredentialSet local "${source}" >"${output}" 2>&1 && exit 1
   fi
   ! rg -q 'not-a-secret|invalid json for upsertApiCredentialSet|json input exceeds' "${output}"
   rg -q '^failed to configure local control target:' "${output}"
done

for source in - "@${invalid_file}"; do
   output="${workdir}/api-invalid-$(basename "${source}" | tr '@/' '__').log"
   if [[ "${source}" == - ]]; then
      printf '{\n' | PRODIGY_MOTHERSHIP_TIDESDB_PATH="${workdir}/api-invalid.tidesdb" \
         "${mothership_bin}" upsertApiCredentialSet local - >"${output}" 2>&1 && exit 1
   else
      PRODIGY_MOTHERSHIP_TIDESDB_PATH="${workdir}/api-invalid.tidesdb" \
         "${mothership_bin}" upsertApiCredentialSet local "${source}" >"${output}" 2>&1 && exit 1
   fi
   rg -qx 'invalid json for upsertApiCredentialSet' "${output}"
done

oversize_file="${workdir}/api-oversize.json"
truncate -s $((4 * 1024 * 1024 + 1)) "${oversize_file}"
if PRODIGY_MOTHERSHIP_TIDESDB_PATH="${workdir}/api-oversize.tidesdb" \
   "${mothership_bin}" upsertApiCredentialSet local "@${oversize_file}" >"${workdir}/api-oversize.log" 2>&1
then
   echo "oversize API credential JSON unexpectedly succeeded" >&2
   exit 1
fi
rg -qx 'upsertApiCredentialSet json input exceeds 4194304 bytes' "${workdir}/api-oversize.log"

echo "PASS: mothership JSON arguments accept inline, stdin, and @file sources and reject invalid paths"
