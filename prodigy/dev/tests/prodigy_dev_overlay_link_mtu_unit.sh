#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
EXPECTED_INTER_CONTAINER_MTU=9000
EXPECTED_UNDERLAY_MTU=$((EXPECTED_INTER_CONTAINER_MTU + 40))

if [[ -z "${PRODIGY_BIN}" || ! -x "${PRODIGY_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy"
   exit 2
fi

if [[ "${EUID}" -ne 0 ]]
then
   echo "SKIP: requires root for isolated netns harness"
   exit 77
fi

deps=(mktemp ps stat timeout ip nsenter grep cut awk)
for cmd in "${deps[@]}"
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}"
      exit 77
   fi
done

tmpdir="$(mktemp -d "${REPO_ROOT}/.run/prodigy-dev-overlay-link-mtu-unit.XXXXXX")"
workspace_root="${tmpdir}/workspace"
manifest_path="${workspace_root}/test-cluster-manifest.json"
harness_pid=""

cleanup()
{
   set +e

   if [[ -n "${harness_pid}" ]] && kill -0 "${harness_pid}" >/dev/null 2>&1
   then
      kill -TERM "${harness_pid}" >/dev/null 2>&1 || true
      timeout 10s bash -lc "while kill -0 ${harness_pid} >/dev/null 2>&1; do sleep 0.1; done" >/dev/null 2>&1 || true
      kill -KILL "${harness_pid}" >/dev/null 2>&1 || true
   fi

   rm -rf "${tmpdir}"
}
trap cleanup EXIT

extract_json_string()
{
   local key="$1"
   local file="$2"
   grep -o "\"${key}\":\"[^\"]*\"" "${file}" | head -n 1 | cut -d'"' -f4
}

extract_json_number()
{
   local key="$1"
   local file="$2"
   grep -o "\"${key}\":[0-9]*" "${file}" | head -n 1 | cut -d: -f2
}

extract_link_mtu()
{
   "$@" | awk '{for (i = 1; i <= NF; i += 1) if ($i == "mtu") { print $(i + 1); exit }}'
}

extract_link_detail_field()
{
   local field="$1"
   shift
   "$@" | awk -v want="${field}" '{for (i = 1; i <= NF; i += 1) if ($i == want) { print $(i + 1); exit }}'
}

assert_link_mtu()
{
   local observed_mtu="$1"
   local label="$2"

   if [[ "${observed_mtu}" != "${EXPECTED_UNDERLAY_MTU}" ]]
   then
      echo "FAIL: ${label} mtu=${observed_mtu} expected=${EXPECTED_UNDERLAY_MTU}"
      exit 1
   fi
}

assert_link_budget()
{
   local observed_value="$1"
   local field="$2"
   local label="$3"

   if [[ "${observed_value}" != "${EXPECTED_UNDERLAY_MTU}" ]]
   then
      echo "FAIL: ${label} ${field}=${observed_value} expected=${EXPECTED_UNDERLAY_MTU}"
      exit 1
   fi
}

export PRODIGY_DEV_ALLOW_BPF_ATTACH=1
"${SCRIPT_DIR}/prodigy_dev_netns_harness.sh" \
   "${PRODIGY_BIN}" \
   --runner-mode=persistent \
   --workspace-root="${workspace_root}" \
   --manifest-path="${manifest_path}" \
   --machines=3 \
   --brains=3 \
   --inter-container-mtu="${EXPECTED_INTER_CONTAINER_MTU}" \
   >/dev/null 2>&1 &
harness_pid="$!"

timeout 60s bash -lc '
   while [[ ! -s "'"${manifest_path}"'" ]]
   do
      sleep 0.1
   done
' >/dev/null

parent_ns="$(extract_json_string "parentNamespace" "${manifest_path}")"
if [[ -z "${parent_ns}" ]]
then
   echo "FAIL: unable to resolve parent namespace from manifest"
   exit 1
fi

manifest_inter_container_mtu="$(extract_json_number "interContainerMTU" "${manifest_path}")"
if [[ "${manifest_inter_container_mtu}" != "${EXPECTED_INTER_CONTAINER_MTU}" ]]
then
   echo "FAIL: manifest interContainerMTU=${manifest_inter_container_mtu} expected=${EXPECTED_INTER_CONTAINER_MTU}"
   exit 1
fi

mapfile -t brain_pids < <(grep -o '"pid":[0-9]*' "${manifest_path}" | cut -d: -f2)
if [[ "${#brain_pids[@]}" -ne 3 ]]
then
   echo "FAIL: expected 3 brain pids in manifest, saw ${#brain_pids[@]}"
   exit 1
fi

parent_bridge_mtu="$(extract_link_mtu ip netns exec "${parent_ns}" ip -o link show dev prodigy-br0)"
assert_link_mtu "${parent_bridge_mtu}" "parent_ns/prodigy-br0"

for idx in 1 2 3
do
   parent_if_mtu="$(extract_link_mtu ip netns exec "${parent_ns}" ip -o link show dev "bp${idx}")"
   assert_link_mtu "${parent_if_mtu}" "parent_ns/bp${idx}"
   parent_if_gso="$(extract_link_detail_field gso_max_size ip netns exec "${parent_ns}" ip -details link show dev "bp${idx}")"
   assert_link_budget "${parent_if_gso}" "gso_max_size" "parent_ns/bp${idx}"
   parent_if_gso_segs="$(extract_link_detail_field gso_max_segs ip netns exec "${parent_ns}" ip -details link show dev "bp${idx}")"
   if [[ "${parent_if_gso_segs}" != "1" ]]
   then
      echo "FAIL: parent_ns/bp${idx} gso_max_segs=${parent_if_gso_segs} expected=1"
      exit 1
   fi
   parent_if_gso_ipv4="$(extract_link_detail_field gso_ipv4_max_size ip netns exec "${parent_ns}" ip -details link show dev "bp${idx}")"
   assert_link_budget "${parent_if_gso_ipv4}" "gso_ipv4_max_size" "parent_ns/bp${idx}"
   parent_if_gro="$(extract_link_detail_field gro_max_size ip netns exec "${parent_ns}" ip -details link show dev "bp${idx}")"
   assert_link_budget "${parent_if_gro}" "gro_max_size" "parent_ns/bp${idx}"
   parent_if_gro_ipv4="$(extract_link_detail_field gro_ipv4_max_size ip netns exec "${parent_ns}" ip -details link show dev "bp${idx}")"
   assert_link_budget "${parent_if_gro_ipv4}" "gro_ipv4_max_size" "parent_ns/bp${idx}"
done

for idx in 0 1 2
do
   brain_pid="${brain_pids[$idx]}"
   timeout 30s bash -lc '
      while ! kill -0 "'"${brain_pid}"'" >/dev/null 2>&1
      do
         sleep 0.1
      done
   ' >/dev/null
   bond_mtu="$(extract_link_mtu nsenter -t "${brain_pid}" -n ip -o link show dev bond0)"
   assert_link_mtu "${bond_mtu}" "brain$((idx + 1))/bond0"
   bond_gso="$(extract_link_detail_field gso_max_size nsenter -t "${brain_pid}" -n ip -details link show dev bond0)"
   assert_link_budget "${bond_gso}" "gso_max_size" "brain$((idx + 1))/bond0"
   bond_gso_segs="$(extract_link_detail_field gso_max_segs nsenter -t "${brain_pid}" -n ip -details link show dev bond0)"
   if [[ "${bond_gso_segs}" != "1" ]]
   then
      echo "FAIL: brain$((idx + 1))/bond0 gso_max_segs=${bond_gso_segs} expected=1"
      exit 1
   fi
   bond_gso_ipv4="$(extract_link_detail_field gso_ipv4_max_size nsenter -t "${brain_pid}" -n ip -details link show dev bond0)"
   assert_link_budget "${bond_gso_ipv4}" "gso_ipv4_max_size" "brain$((idx + 1))/bond0"
   bond_gro="$(extract_link_detail_field gro_max_size nsenter -t "${brain_pid}" -n ip -details link show dev bond0)"
   assert_link_budget "${bond_gro}" "gro_max_size" "brain$((idx + 1))/bond0"
   bond_gro_ipv4="$(extract_link_detail_field gro_ipv4_max_size nsenter -t "${brain_pid}" -n ip -details link show dev bond0)"
   assert_link_budget "${bond_gro_ipv4}" "gro_ipv4_max_size" "brain$((idx + 1))/bond0"
done

echo "PASS: prodigy dev harness keeps interContainerMTU=${EXPECTED_INTER_CONTAINER_MTU} while pinning overlay underlay links to ${EXPECTED_UNDERLAY_MTU}"
