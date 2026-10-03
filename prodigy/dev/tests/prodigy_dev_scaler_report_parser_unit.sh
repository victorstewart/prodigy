#!/usr/bin/env bash
set -euo pipefail

HARNESS="${1:-}"
if [[ -z "${HARNESS}" || ! -r "${HARNESS}" ]]
then
   echo "usage: $0 /path/to/prodigy_dev_netns_harness.sh" >&2
   exit 2
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
function_file="${tmpdir}/scaler_satisfied.sh"
sed -n '/^scaler_satisfied()/,/^}$/p' "${HARNESS}" >"${function_file}"
[[ -s "${function_file}" ]] || {
   echo "FAIL: scaler_satisfied was not extracted from ${HARNESS}" >&2
   exit 1
}
# Exercise the actual parser implementation rather than a copied expression.
source "${function_file}"

canonical="${tmpdir}/canonical.report"
legacy="${tmpdir}/legacy.report"
below="${tmpdir}/below.report"
wrong_name="${tmpdir}/wrong-name.report"
cat >"${canonical}" <<'EOF'
name: pingpong.requests
nvalue: 7
EOF
cat >"${legacy}" <<'EOF'
name: pingpong.requests
value: 8
EOF
cat >"${below}" <<'EOF'
name: pingpong.requests
nvalue: 6
EOF
cat >"${wrong_name}" <<'EOF'
name: pingpong.other
nvalue: 99
EOF

deploy_report_require_scaler="pingpong.requests"
deploy_report_require_scaler_value_min=7
scaler_satisfied "${canonical}" || {
   echo "FAIL: canonical nvalue did not satisfy the threshold" >&2
   exit 1
}
scaler_satisfied "${legacy}" || {
   echo "FAIL: legacy value did not satisfy the threshold" >&2
   exit 1
}
if scaler_satisfied "${below}"
then
   echo "FAIL: below-threshold nvalue was accepted" >&2
   exit 1
fi
if scaler_satisfied "${wrong_name}"
then
   echo "FAIL: nvalue from a different scaler was accepted" >&2
   exit 1
fi

echo "SCALER_REPORT_PARSER_UNIT_PASS"
