#!/usr/bin/env bash
set -Eeuo pipefail

prodigy_bin="${1:-}"
mothership_bin="${2:-}"
container_artifact="${3:-}"
mode="${4:-standard}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/../../.." && pwd -P)"
harness="${script_dir}/prodigy_dev_netns_harness.sh"

if [[ ! -x "${prodigy_bin}" || ! -x "${mothership_bin}" || ! -r "${container_artifact}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/pingpong.container.zst [standard|runtime-isolation]" >&2
   exit 2
fi

case "${mode}" in
   standard)
      storage_mb=64
      read_only_root=false
      run_as_id=0
      host_network=true
      skip_probe=0
      ;;
   runtime-isolation)
      storage_mb=0
      read_only_root=true
      run_as_id=65534
      host_network=false
      skip_probe=1
      ;;
   *)
      echo "error: unsupported ping-pong smoke mode: ${mode}" >&2
      exit 2
      ;;
esac

case "$(uname -m)" in
   aarch64|arm64) architecture=aarch64 ;;
   x86_64|amd64) architecture=x86_64 ;;
   riscv64|riscv) architecture=riscv64 ;;
   *) echo "SKIP: unsupported architecture" >&2; exit 77 ;;
esac

bundle_artifact="$(dirname "${prodigy_bin}")/prodigy.${architecture}.bundle.tar.zst"
bundle_sha256="${bundle_artifact}.sha256"
if [[ ! -r "${bundle_artifact}" || ! -r "${bundle_sha256}" ]]
then
   echo "error: current Prodigy bundle and checksum must be built beside ${prodigy_bin}" >&2
   exit 2
fi

mkdir -p "${repo_root}/.run"
work_root="$(mktemp -d "${repo_root}/.run/pingpong-deploy.XXXXXX")"
trap 'rm -rf "${work_root}"' EXIT
bundle_home="${work_root}/share/prodigy"
mkdir -p "${bundle_home}"
ln "${bundle_artifact}" "${bundle_home}/prodigy.${architecture}.bundle.tar.zst"
ln "${bundle_sha256}" "${bundle_home}/prodigy.${architecture}.bundle.tar.zst.sha256"
export XDG_DATA_HOME="${work_root}/share"
plan="${work_root}/pingpong.plan.json"
jq -n \
   --arg architecture "${architecture}" \
   --argjson storageMB "${storage_mb}" \
   --argjson rootFilesystemReadOnly "${read_only_root}" \
   --argjson runAsID "${run_as_id}" \
   --argjson useHostNetworkNamespace "${host_network}" '
   {
      config:{
         type:"ApplicationType::stateless",
         applicationID:"${application:PingPongSmoke}",
         versionID:1,
         architecture:$architecture,
         filesystemMB:64,
         storageMB:$storageMB,
         rootFilesystemReadOnly:$rootFilesystemReadOnly,
         runAsID:$runAsID,
         memoryMB:256,
         nLogicalCores:1,
         msTilHealthy:10000,
         sTilHealthcheck:15,
         sTilKillable:30
      },
      useHostNetworkNamespace:$useHostNetworkNamespace,
      minimumSubscriberCapacity:1024,
      isStateful:false,
      stateless:{
         nBase:1,
         maxPerRackRatio:1.0,
         maxPerMachineRatio:1.0,
         moveableDuringCompaction:true
      },
      advertisements:[{
         service:"${service:PingPongSmoke/server}",
         startAt:"ContainerState::scheduled",
         stopAt:"ContainerState::destroying",
         port:19090
      }],
      moveConstructively:true,
      requiresDatacenterUniqueTag:false
   }
' > "${plan}"

"${harness}" "${prodigy_bin}" \
   --mothership-bin="${mothership_bin}" \
   --machines=2 \
   --brains=1 \
   --test-machine-logical-cores=4 \
   --test-machine-memory-mb=8192 \
   --test-machine-storage-mb=8192 \
   --deploy-plan-json="${plan}" \
   --deploy-container-zstd="${container_artifact}" \
   --deploy-report-application=PingPongSmoke \
   --deploy-report-min-healthy=1 \
   --deploy-report-min-target=1 \
   --deploy-report-min-deployed=1 \
   --deploy-ping-port=19090 \
   --deploy-ping-payload=ping \
   --deploy-ping-expect=pong \
   --deploy-skip-probe="${skip_probe}"
