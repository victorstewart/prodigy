#!/usr/bin/env bash
set -Eeuo pipefail

source_harness="${1:-}"
[[ -r "${source_harness}" ]] || {
   echo "usage: $0 /path/to/prodigy_dev_netns_harness.sh" >&2
   exit 2
}

fail()
{
   echo "FAIL: $*" >&2
   exit 1
}

work_root="$(mktemp -d /tmp/prodigy-netns-harness-cleanup-unit.XXXXXX)"
cleanup()
{
   [[ "${work_root}" == /tmp/prodigy-netns-harness-cleanup-unit.* ]] || return
   rm -rf -- "${work_root}"
}
trap cleanup EXIT

fixture_repo="${work_root}/repo"
fixture_tests="${fixture_repo}/prodigy/dev/tests"
mock_bin="${work_root}/bin"
subject="${fixture_tests}/prodigy_dev_netns_harness.sh"
mkdir -p "${fixture_tests}" "${fixture_repo}/.run" "${fixture_repo}/build" "${mock_bin}"

# This is a source fixture: it suppresses the root preflight only.  The mocked
# Mothership never creates a provider or deployment artifact.
expected_preflight=$'[[ "${EUID}" -eq 0 ]] || {\n   echo "SKIP: Mothership test clusters require root" >&2\n   exit 77\n}'
actual_preflight="$(sed -n '19,22p' "${source_harness}")"
[[ "${actual_preflight}" == "${expected_preflight}" ]] ||
   fail "harness root preflight changed; update this source fixture deliberately"
sed '19,22c\
: # root preflight suppressed by the unprivileged cleanup fixture' "${source_harness}" > "${subject}"
chmod +x "${subject}"

cat > "${fixture_repo}/build/prodigy" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "${fixture_repo}/build/prodigy"

cat > "${fixture_repo}/build/mothership" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

operation="${1:-}"
echo "${operation}" >> "${MOCK_EVENTS}"
case "${operation}" in
   createCluster)
      create_name="$(jq -r .name <<< "${2:-}")"
      case "${MOCK_SCENARIO}" in
         partial-create)
            echo "createCluster success=0 created=1 name=${create_name} failure=mocked"
            exit 23
            ;;
         partial-other-name)
            echo "createCluster success=0 created=1 name=other-harness failure=mocked"
            exit 23
            ;;
         partial-not-created)
            echo "createCluster success=0 created=0 name=${create_name} failure=mocked"
            exit 23
            ;;
      esac
      mkdir -p "${MOCK_WORKSPACE}"
      for index in 1 2 3
      do
         echo fixture-ready > "${MOCK_WORKSPACE}/machine${index}.log"
      done
      cat > "${MOCK_WORKSPACE}/test-cluster-manifest.json" <<MANIFEST
{"nodes":[
 {"index":1,"role":"brain","stdoutLog":"${MOCK_WORKSPACE}/machine1.log"},
 {"index":2,"role":"brain","stdoutLog":"${MOCK_WORKSPACE}/machine2.log"},
 {"index":3,"role":"brain","stdoutLog":"${MOCK_WORKSPACE}/machine3.log"}
]}
MANIFEST
      ;;
   clusterReport)
      count_file="${MOCK_WORKSPACE}/cluster-report-count"
      count=0
      [[ -r "${count_file}" ]] && count="$(<"${count_file}")"
      count=$((count + 1))
      printf '%s\n' "${count}" > "${count_file}"
      if [[ "${MOCK_SCENARIO}" == signal && "${count}" -ge 2 ]]
      then
         echo second-cluster-report >> "${MOCK_EVENTS}"
         harness_pid="$(ps -o ppid= -p "${PPID}" | tr -d ' ')"
         [[ "${harness_pid}" =~ ^[0-9]+$ ]] || exit 65
         kill -TERM "${harness_pid}"
      fi
      for index in 1 2 3
      do
         echo "Machine: state=healthy role=brain address=10.0.0.$((9 + index))"
         if [[ "${MOCK_SCENARIO}" == original-failure ]]
         then
            echo ' lifecycle controlPlaneReachable=1 runtimeReady=1 currentMaster=0'
         elif [[ "${index}" == 1 ]]
         then
            echo ' lifecycle controlPlaneReachable=1 runtimeReady=1 currentMaster=1'
         else
            echo ' lifecycle controlPlaneReachable=1 runtimeReady=1 currentMaster=0'
         fi
      done
      ;;
   removeCluster)
      case "${MOCK_REMOVE}" in
         success) echo 'removeCluster success=1 removed=1' ;;
         missing-receipt) echo 'removeCluster success=10 removed=1' ;;
         command-failure) echo 'removeCluster success=0 failure=mocked' >&2; exit 42 ;;
         *) exit 64 ;;
      esac
      ;;
   *) exit 64 ;;
esac
EOF
chmod +x "${fixture_repo}/build/mothership"

# The production harness runs in Linux with GNU awk.  The fixture reaches only
# its report-to-master parser, so keep this portability shim narrow.
cat > "${mock_bin}/awk" <<'EOF'
#!/usr/bin/env bash
[[ "${MOCK_SCENARIO}" == original-failure ]] || echo 1
EOF
chmod +x "${mock_bin}/awk"

run_case()
{
   local name="$1"
   local scenario="$2"
   local removal="$3"
   local signal_mode="${4:-0}"
   local keep_tmp="${5:-0}"
   local workspace="${work_root}/${name}.workspace"
   local output="${work_root}/${name}.output"
   local events="${work_root}/${name}.events"
   local status=0
   : > "${events}"

   local -a environment=(
      "MOCK_EVENTS=${events}"
      "MOCK_WORKSPACE=${workspace}"
      "MOCK_SCENARIO=${scenario}"
      "MOCK_REMOVE=${removal}"
      "PRODIGY_DEV_KEEP_TMP=${keep_tmp}"
      "PATH=${mock_bin}:${PATH}"
   )
   [[ "${keep_tmp}" == 0 || "${keep_tmp}" == 1 ]] || fail "${name}: invalid keep-tmp fixture value"
   [[ "${signal_mode}" == 0 || "${signal_mode}" == 1 ]] || fail "${name}: invalid signal fixture value"
   set +e
   env "${environment[@]}" "${subject}" "${fixture_repo}/build/prodigy" \
      "--workspace-root=${workspace}" --require-brain-log-substring=fixture-ready > "${output}" 2>&1
   status="$?"
   set -e

   case_tmpdir="$(sed -n 's/^DEBUG: preserved tmpdir //p' "${output}" | tail -n 1)"
   [[ -n "${case_tmpdir}" && -d "${case_tmpdir}" ]] || {
      cat "${output}" >&2
      fail "${name}: cleanup did not preserve evidence"
   }
   [[ -r "${case_tmpdir}/create.log" ]] || fail "${name}: create evidence missing"
   printf '%s\t%s\t%s\n' "${status}" "${case_tmpdir}" "${output}"
}

expect_case()
{
   local name="$1"
   local expected_status="$2"
   local expected_text="$3"
   shift 3
   local result
   result="$(run_case "${name}" "$@")"
   IFS=$'\t' read -r status tmpdir output <<< "${result}"
   [[ "${status}" == "${expected_status}" ]] || {
      cat "${output}" >&2
      fail "${name}: expected status ${expected_status}, got ${status}"
   }
   grep -Fq "${expected_text}" "${output}" || {
      cat "${output}" >&2
      fail "${name}: missing '${expected_text}'"
   }
   [[ -s "${tmpdir}/remove.log" ]] || fail "${name}: removal receipt was not retained"
}

expect_case success 0 'PRODIGY_DEV_HARNESS_PASS' normal success 0 1
expect_case command_failure 1 'removeCluster exited with status 42' normal command-failure 0 0
expect_case missing_receipt 1 'removeCluster did not report exact success receipt' normal missing-receipt 0 0
expect_case original_failure 1 'cluster has no single reported master' original-failure command-failure 0 0
expect_case original_signal 143 'removeCluster exited with status 42' signal command-failure 1 0

expect_partial_create_case()
{
   local name="$1"
   local scenario="$2"
   local expect_remove="$3"
   local result status tmpdir output
   result="$(run_case "${name}" "${scenario}" success 0 0)"
   IFS=$'\t' read -r status tmpdir output <<< "${result}"
   [[ "${status}" == 1 ]] || {
      cat "${output}" >&2
      fail "${name}: expected original create failure status 1, got ${status}"
   }
   grep -Fq 'Mothership could not create the test cluster' "${output}" || fail "${name}: missing create failure"
   if [[ "${expect_remove}" == 1 ]]
   then
      [[ -s "${tmpdir}/remove.log" ]] || fail "${name}: partial create did not retain removal receipt"
      grep -Fxq removeCluster "${work_root}/${name}.events" || fail "${name}: partial create did not invoke removeCluster"
   else
      [[ ! -e "${tmpdir}/remove.log" ]] || fail "${name}: non-owned or uncreated receipt invoked removeCluster"
      ! grep -Fxq removeCluster "${work_root}/${name}.events" || fail "${name}: non-owned or uncreated receipt invoked removeCluster"
   fi
}

expect_partial_create_case partial_create partial-create 1
expect_partial_create_case partial_other_name partial-other-name 0
expect_partial_create_case partial_not_created partial-not-created 0

echo 'PASS: netns harness cleanup receipts preserve primary status and evidence'
