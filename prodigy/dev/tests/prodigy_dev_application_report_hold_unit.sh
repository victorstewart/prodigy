#!/usr/bin/env bash
set -euo pipefail

harness="${1:?harness path required}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
for function in block_scalar wait_application_report
do
   sed -n "/^${function}()/,/^}$/p" "${harness}" >>"${tmpdir}/functions.sh"
done
source "${tmpdir}/functions.sh"

# Drive the real observer with deterministic reports and a clock. No cluster,
# runtime artifact, network or privileged operation participates in this unit.
date() { cat "${tmpdir}/clock"; }
sleep() { echo "$(( $(cat "${tmpdir}/clock") + 1000 ))" >"${tmpdir}/clock"; }
select_deployment_block() { cp "$1" "$2"; }
runtime_resources_satisfied() { return 0; }
scaler_satisfied() { return 0; }
application_report()
{
   local value="${samples[${sample_index}]}"
   sample_index=$((sample_index + 1))
   [[ "${value}" != missing ]] || return 1
   if [[ "${value}" == failed ]]
   then
      echo 'state: DeploymentState::failed' >"$2"
      return 0
   fi
   local healthy=3 deployed=3
   [[ "${value}" != unhealthy ]] || healthy=0
   [[ "${value}" != peak ]] || deployed=6
   printf 'nHealthy: %s\nnTarget: 3\nnDeployed: %s\nnShardGroups: 1\nnCrashes: 0\n' "${healthy}" "${deployed}" >"$2"
}

deploy_report_application=test
deploy_report_min_healthy=3
deploy_report_min_target=3
deploy_report_min_deployed=3
deploy_report_min_shard_groups=1
deploy_report_max_healthy_min=3
deploy_report_max_target_min=3
deploy_report_max_deployed_min=6
deploy_report_max_shard_groups_min=1
deploy_report_final_healthy_min=3
deploy_report_final_healthy_max=3
deploy_report_final_target_max=3
deploy_report_final_deployed_max=3
deploy_report_final_shard_groups_max=1
deploy_report_max_crashes_max=0
deploy_report_floor_min_runtime_ms=0
deploy_report_success_hold_ms=2000
deploy_report_poll_interval_ms=1000
deploy_ping_port=0

reset_samples()
{
   samples=("$@")
   sample_index=0
   deploy_report_attempts="${#samples[@]}"
   echo 1000 >"${tmpdir}/clock"
}
reset_samples peak good good good
if ! wait_application_report
then
   echo 'FAIL: initial transition did not qualify' >&2
   exit 1
fi
reset_samples good good good
if ! wait_application_report post-fault
then
   echo 'FAIL: recovery discarded the already observed transition peak' >&2
   exit 1
fi
reset_samples failed
if wait_application_report post-fault
then
   echo 'FAIL: failed application qualified as recovered' >&2
   exit 1
fi

deploy_report_success_hold_ms=3000
for gap in missing unhealthy
do
   reset_samples good "${gap}" good good
   if wait_application_report post-fault
   then
      echo "FAIL: ${gap} observation did not break the healthy hold" >&2
      exit 1
   fi
done
reset_samples good good good good
if ! wait_application_report post-fault
then
   echo 'FAIL: a continuous healthy hold did not qualify' >&2
   exit 1
fi
echo APPLICATION_REPORT_HOLD_UNIT_PASS
