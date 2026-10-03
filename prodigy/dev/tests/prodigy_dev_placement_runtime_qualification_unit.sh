#!/usr/bin/env bash
set -Eeuo pipefail
subject="${1:-$(dirname "$0")/prodigy_dev_placement_runtime_qualification.sh}"
work="$(mktemp -d "${TMPDIR:-/tmp}/prodigy-placement-report-unit.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
# Load only the actual read-only parser; never run the scenario's lifecycle.
sed -n '/^machine_for_deployment()/,/^}$/p' "${subject}" >"${work}/parser.sh"
[[ -s "${work}/parser.sh" ]]
source "${work}/parser.sh"
cat >"${work}/report" <<'EOF'
Machine: state=healthy role=brain
  identity uuid=0x01 source=created
  placement containers= applications= deploymentIDs= shardGroups=
Machine: state=healthy role=brain
  identity uuid=0x02 source=created
  placement containers=0x03 applications=PlacementRuntime deploymentIDs=281474976710656002 shardGroups=
EOF
[[ -z "$(machine_for_deployment "${work}/report" 281474976710656001)" ]]
[[ "$(machine_for_deployment "${work}/report" 281474976710656002)" == 0x02 ]]
sed 's/281474976710656002/281474976710656001/' "${work}/report" >"${work}/source-report"
[[ "$(machine_for_deployment "${work}/source-report" 281474976710656001)" == 0x02 ]]
[[ -z "$(machine_for_deployment "${work}/source-report" 281474976710656002)" ]]
printf 'PASS: placement report parser distinguishes adjacent 64-bit deployment IDs\n'
