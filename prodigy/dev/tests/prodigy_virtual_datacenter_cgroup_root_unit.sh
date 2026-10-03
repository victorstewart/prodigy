#!/usr/bin/env bash
set -euo pipefail

provider="${1:-}"
[[ -r "${provider}" ]] || {
   echo "usage: $0 /path/to/mothership.virtual.datacenter.provider.sh" >&2
   exit 2
}

# Load only the provider's pure validator, without entering its dispatcher.
tmpdir="$(mktemp -d)"
trap 'rm -rf -- "${tmpdir}"' EXIT
validator_source="${tmpdir}/provider-validators.sh"
awk '
   /^valid_retained_cgroup_root\(\)$/ { found++; copying=1 }
   copying { print }
   copying && /^}$/ { copying=0; finished=1 }
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

printf 'virtual datacenter retained cgroup root unit passed\n'
