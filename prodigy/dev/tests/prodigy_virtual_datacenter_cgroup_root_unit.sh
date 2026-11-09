#!/usr/bin/env bash
set -euo pipefail

provider="${1:-}"
[[ -r "${provider}" ]] || {
   echo "usage: $0 /path/to/mothership.virtual.datacenter.provider.sh" >&2
   exit 2
}

# Load only the retained-cgroup validators, without entering the dispatcher.
tmpdir="$(mktemp -d)"
trap 'rm -rf -- "${tmpdir}"' EXIT
validator_source="${tmpdir}/provider-validators.sh"
awk '
   /^valid_retained_cgroup_root\(\)$/ { found++; copying=1 }
   /^restore_cgroup_scope_if_idle\(\)$/ { finished=1; exit }
   copying { print }
   END { exit(found == 1 && finished ? 0 : 1) }
' "${provider}" > "${validator_source}"
source "${validator_source}"

# macOS lacks GNU realpath -m. This lexical stand-in has the exact only form
# used by the provider validator and keeps the regression unprivileged.
if [[ "$(uname -s)" == Darwin ]]
then
   realpath()
   {
      [[ "$#" -eq 3 && "$1" == -m && "$2" == -- ]] || return 2
      python3 -c 'import os, sys; print(os.path.normpath(sys.argv[1]))' "$3"
   }
fi

affirm_valid()
{
   valid_retained_cgroup_root "$1" 65572 || {
      echo "valid retained cgroup root rejected: $1" >&2
      exit 1
   }
}

affirm_invalid()
{
   if valid_retained_cgroup_root "$1" 65572
   then
      echo "invalid retained cgroup root accepted: $1" >&2
      exit 1
   fi
}

affirm_valid /sys/fs/cgroup/prodigy-vdc-65572
affirm_valid /sys/fs/cgroup/delegated.slice/prodigy-vdc-65572
affirm_invalid /sys/fs/cgroup/prodigy-vdc-65573
affirm_invalid /sys/fs/cgroup/delegated.slice/prodigy-vdc-65573
affirm_invalid /sys/fs/cgroup/delegated.slice/../prodigy-vdc-65572
affirm_invalid /tmp/prodigy-vdc-65572

# A kernel fixture is deliberately opt-in.  The caller supplies an empty,
# delegated cgroup-v2 scope inside an isolated guest; this test never creates
# one in the host namespace.  The production helper itself still insists on
# cgroup2, an empty parent, enabled controllers, and exact retained ownership.
if [[ -n "${PRODIGY_VDC_CGROUP_KERNEL_SCOPE:-}" ]]
then
   scope="${PRODIGY_VDC_CGROUP_KERNEL_SCOPE}"
   runtime=65572
   root="${scope}/prodigy-vdc-${runtime}"
   control="${scope}/prodigy-vdc-control"
   [[ "${scope}" == /sys/fs/cgroup/* && -d "${scope}" &&
      "$(findmnt -n -o FSTYPE -T "${scope}")" == cgroup2 &&
      ! -e "${root}" && ! -e "${control}" && -z "$(cat -- "${scope}/cgroup.procs")" ]] || {
      echo "kernel cgroup fixture is not an empty delegated cgroup-v2 scope" >&2; exit 1;
   }
   enabled_before="$(<"${scope}/cgroup.subtree_control")"
   for controller in cpuset cpu memory pids
   do
      [[ " ${enabled_before} " == *" ${controller} "* ]] || {
         echo "kernel cgroup fixture lacks ${controller}" >&2; exit 1;
      }
   done
   cleanup_kernel_fixture() { rmdir "${control}" 2>/dev/null || true; rmdir "${root}/provider" 2>/dev/null || true; rmdir "${root}" 2>/dev/null || true; }
   trap 'cleanup_kernel_fixture; rm -rf -- "${tmpdir}"' EXIT
   mkdir "${root}" "${root}/provider"
   restore_retained_cgroup_control_if_absent "${scope}" "${root}" "${runtime}"
   [[ -d "${control}" && ! -L "${control}" && "$(<"${scope}/cgroup.subtree_control")" == "${enabled_before}" && -z "$(cat -- "${scope}/cgroup.procs")" ]] || {
      echo "kernel cgroup recovery changed controller or process inventory" >&2; exit 1;
   }
   # Existing control ownership is intentionally a no-op in adoption; only an
   # absent leaf is repaired.
   ! retained_cgroup_control_absent_recoverable "${scope}" "${root}" "${runtime}" || {
      echo "existing control leaf was mistaken for absent" >&2; exit 1;
   }
   rmdir "${control}"
   mkdir "${scope}/foreign"
   foreign_before="$(find "${scope}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)"
   ! restore_retained_cgroup_control_if_absent "${scope}" "${root}" "${runtime}" || {
      echo "foreign cgroup child was accepted" >&2; exit 1;
   }
   [[ "$(find "${scope}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)" == "${foreign_before}" &&
      "$(<"${scope}/cgroup.subtree_control")" == "${enabled_before}" && -z "$(cat -- "${scope}/cgroup.procs")" ]] || {
      echo "foreign rejection changed cgroup inventory" >&2; exit 1;
   }
   rmdir "${scope}/foreign"
   printf -- '-pids\n' > "${scope}/cgroup.subtree_control"
   controller_missing="$(<"${scope}/cgroup.subtree_control")"
   ! restore_retained_cgroup_control_if_absent "${scope}" "${root}" "${runtime}" || {
      echo "missing controller was accepted" >&2; exit 1;
   }
   [[ "$(<"${scope}/cgroup.subtree_control")" == "${controller_missing}" && -z "$(cat -- "${scope}/cgroup.procs")" ]] || {
      echo "controller rejection changed cgroup inventory" >&2; exit 1;
   }
   printf '+pids\n' > "${scope}/cgroup.subtree_control"
   [[ "$(<"${scope}/cgroup.subtree_control")" == "${enabled_before}" ]] || {
      echo "kernel cgroup fixture controller restoration failed" >&2; exit 1;
   }
   rmdir "${root}/provider"; rmdir "${root}"
   printf 'virtual datacenter retained cgroup control kernel unit passed\n'
fi

printf 'virtual datacenter retained cgroup root unit passed\n'
