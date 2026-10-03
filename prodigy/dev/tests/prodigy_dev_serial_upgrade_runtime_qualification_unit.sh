#!/usr/bin/env bash
set -Eeuo pipefail

subject="${1:-}"
[[ -x "${subject}" ]] || { echo "usage: $0 /path/to/prodigy_dev_serial_upgrade_runtime_qualification.sh" >&2; exit 2; }
harness="$(dirname "${subject}")/prodigy_dev_netns_harness.sh"
[[ -r "${harness}" ]] || { echo "missing serial-upgrade harness: ${harness}" >&2; exit 2; }
work="$(mktemp -d /tmp/prodigy-serial-upgrade-driver-unit.XXXXXX)"
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/source"
for name in prodigy mothership
do
   cat > "${work}/source/${name}" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
   chmod +x "${work}/source/${name}"
done
for name in source.bundle target.bundle app.plan.json app.container.zst
do
   : > "${work}/${name}"
done
cat > "${work}/launcher" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$MOCK_ARGS"
EOF
chmod +x "${work}/launcher"
args="${work}/args"
env PRODIGY_DEV_SERIAL_UPGRADE_LAUNCHER="${work}/launcher" MOCK_ARGS="${args}" "${subject}" \
   "${work}/source/prodigy" "${work}/source/mothership" "${work}/target.bundle" "${work}/source.bundle" \
   "${work}/app.plan.json" "${work}/app.container.zst" 0x01 serial-normal
grep -Fx -- "--mothership-update-prodigy-input=${work}/target.bundle" "${args}"
grep -Fx -- "--mothership-plan-upgrade-source-bundle=${work}/source.bundle" "${args}"
grep -Fx -- '--mothership-plan-upgrade-operation-id=0x01' "${args}"
grep -Fx -- "--update-continuity-probe=1" "${args}"
grep -Fx -- "--update-continuity-max-failures=0" "${args}"
[[ "$(rg -F -c -- '"${mothership_bin}" updateProdigy "${cluster_name}" "${mothership_update_prodigy_input}" "${mothership_plan_upgrade_operation_id}"' "${harness}")" == 2 ]]
rg -Fq 'fail "updateProdigy requires a nonzero lower-case 0x hex operation ID"' "${harness}"
set +e
env PRODIGY_DEV_SERIAL_UPGRADE_LAUNCHER="${work}/launcher" MOCK_ARGS="${args}" "${subject}" \
   "${work}/source/prodigy" "${work}/source/mothership" "${work}/target.bundle" "${work}/source.bundle" \
   "${work}/app.plan.json" "${work}/app.container.zst" 0x01 follower-link-reconnect >"${work}/skip.log" 2>&1
status="$?"
set -e
[[ "${status}" == 77 ]]
grep -Fq 'typed per-member rollout receipt report' "${work}/skip.log"
echo 'PASS: serial upgrade driver preserves Mothership-only admission and fails closed for receipt-gated fault'
