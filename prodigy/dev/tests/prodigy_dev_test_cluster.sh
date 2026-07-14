#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
harness="${script_dir}/prodigy_dev_netns_harness.sh"

fail()
{
   echo "FAIL: $*" >&2
   exit 1
}

usage()
{
   echo "usage: $0 /path/to/prodigy [Mothership test-cluster options]" >&2
   exit 2
}

[[ $# -gt 0 ]] || usage

case "$(uname -s)" in
   Darwin)
      for command in container jq
      do
         command -v "${command}" >/dev/null || fail "required command is unavailable: ${command}"
      done
      container system status | grep -Eq '^status[[:space:]]+running$' || fail "Apple Containers is not running"

      container_name="${PRODIGY_APPLE_CONTAINER_NAME:-prodigy-work}"
      image="${PRODIGY_APPLE_CONTAINER_IMAGE:-nametag/archlinuxarm-cachy-prodigy-toolchain:20260624-cmake-4.4.0}"
      containers="$(container list --all --format json)"
      while IFS= read -r stale
      do
         [[ -n "${stale}" ]] || continue
         container delete --force "${stale}"
      done < <(jq -r --arg selected "${container_name}" '.[] | select(.id != $selected and (.id | test("^prodigy-(work|dev|test)(-|$)"))) | .id' <<< "${containers}")

      create_apple_container()
      {
         local kernel="${PRODIGY_APPLE_CONTAINER_KERNEL:-${repo_root}/.run/apple-container-kernel/containerization/bin/vmlinux-arm64}"
         local cache_root="${repo_root}/.run/apple-container-cache"
         local checkout_root
         local checkout
         local name
         local -a run

         [[ -s "${kernel}" ]] || fail "approved Prodigy kernel is unavailable: ${kernel}"
         container image inspect "${image}" >/dev/null 2>&1 || fail "Apple Container base image is unavailable: ${image}"
         mkdir -p "${cache_root}/cargo" "${cache_root}/cache"
         run=(
            container run
            --name "${container_name}"
            --detach
            --init
            --kernel "${kernel}"
            --cap-add ALL
            --cpus "${PRODIGY_APPLE_CONTAINER_CPUS:-16}"
            --memory "${PRODIGY_APPLE_CONTAINER_MEMORY:-24g}"
            --label dev.prodigy.test-boundary=true
            --volume "${cache_root}/cargo:/root/.cargo"
            --volume "${cache_root}/cache:/root/.cache"
         )
         checkout_root="$(dirname "${repo_root}")"
         for name in basics prodigy nametag oxide
         do
            checkout="${checkout_root}/${name}"
            [[ -d "${checkout}" ]] && run+=(--volume "${checkout}:/mnt/${name}")
         done
         run+=("${image}" /bin/bash -lc 'exec sleep infinity')
         "${run[@]}"
      }

      selected_count="$(jq -r --arg id "${container_name}" '[.[] | select(.id == $id)] | length' <<< "${containers}")"
      if [[ "${selected_count}" == 1 ]]
      then
         state="$(jq -r --arg id "${container_name}" '.[] | select(.id == $id) | .status.state' <<< "${containers}")"
         selected_image="$(jq -r --arg id "${container_name}" '.[] | select(.id == $id) | .configuration.image.reference' <<< "${containers}")"
         if [[ "${state}" != running || "${selected_image}" != "${image}" ]]
         then
            container delete --force "${container_name}"
            create_apple_container
         fi
      elif [[ "${selected_count}" == 0 ]]
      then
         create_apple_container
      else
         fail "multiple Apple Containers have identity ${container_name}"
      fi

      inspection="$(container inspect "${container_name}")"
      [[ "$(jq -r '.[0].configuration.platform.os' <<< "${inspection}")" == linux ]] || fail "selected Apple Container is not Linux"
      jq -e '.[0].configuration.capAdd | index("ALL") != null' <<< "${inspection}" >/dev/null ||
         fail "selected Apple Container lacks the capabilities required by the virtual-datacenter provider"

      translate_path()
      {
         jq -er --arg path "$1" '
            [.[0].configuration.mounts[]
               | select(.source as $source | $path == $source or ($path | startswith($source + "/")))]
            | sort_by(.source | length)
            | last as $mount
            | if $mount == null then empty else $mount.destination + $path[($mount.source | length):] end
         ' <<< "${inspection}"
      }

      guest_repo="$(translate_path "${repo_root}")" || fail "Prodigy repository is not mounted in ${container_name}"
      guest_harness="$(translate_path "${harness}")" || fail "test harness is not mounted in ${container_name}"
      prodigy_path="$1"
      shift
      if [[ "${prodigy_path}" != /* ]]
      then
         prodigy_path="$(cd "$(dirname "${prodigy_path}")" && pwd)/$(basename "${prodigy_path}")"
      fi
      guest_prodigy="$(translate_path "${prodigy_path}")" || fail "Prodigy binary is not mounted in ${container_name}"

      translated=()
      for argument in "$@"
      do
         if [[ "${argument}" == --*=/* ]]
         then
            option="${argument%%=*}"
            value="${argument#*=}"
            mapped="$(translate_path "${value}")" || mapped=
            [[ -z "${mapped}" ]] || argument="${option}=${mapped}"
         fi
         translated+=("${argument}")
      done

      command=(container exec --user 0 --workdir "${guest_repo}")
      while IFS='=' read -r name _
      do
         [[ "${name}" == PRODIGY_* ]] && command+=(--env "${name}")
      done < <(env)
      command+=(
         --env "PRODIGY_DEV_TEST_BOUNDARY=apple-container"
         --env "PRODIGY_DEV_APPLE_CONTAINER_ID=${container_name}"
         "${container_name}"
         "${guest_harness}"
         "${guest_prodigy}"
         "${translated[@]}"
      )
      cleanup_apple_container()
      {
         status=$?
         trap - EXIT HUP INT TERM
         if ! container stop "${container_name}"
         then
            [[ "${status}" -ne 0 ]] || status=1
         fi
         if ! container delete --force "${container_name}"
         then
            [[ "${status}" -ne 0 ]] || status=1
         fi
         exit "${status}"
      }
      trap cleanup_apple_container EXIT
      trap 'exit 129' HUP
      trap 'exit 130' INT
      trap 'exit 143' TERM
      "${command[@]}"
      ;;
   Linux)
      boundary="${PRODIGY_DEV_TEST_BOUNDARY:-}"
      if [[ "${boundary}" == apple-container ]]
      then
         [[ -n "${PRODIGY_DEV_APPLE_CONTAINER_ID:-}" ]] || fail "Apple Container boundary identity is missing"
         command -v systemd-detect-virt >/dev/null &&
            [[ "$(systemd-detect-virt --container 2>/dev/null || true)" != none ]] ||
            fail "Apple Container boundary was declared outside a Linux container"
      else
         marker="${PRODIGY_DEV_DISPOSABLE_LINUX_MARKER:-/run/prodigy-disposable-linux}"
         [[ -f "${marker}" && "$(cat "${marker}")" == prodigy-disposable-linux-v1 ]] ||
            fail "privileged test clusters require a disposable KVM guest or sacrificial-host marker: ${marker}"
         [[ "$(stat -c %u "${marker}")" == 0 ]] || fail "disposable Linux marker must be root-owned"
         mode="$(stat -c %a "${marker}")"
         (( (8#${mode} & 022) == 0 )) || fail "disposable Linux marker must not be group/other-writable"
      fi

      kernel_major="$(uname -r | sed 's/[^0-9].*//')"
      [[ "${kernel_major}" =~ ^[0-9]+$ && "${kernel_major}" -ge 7 ]] || fail "Prodigy test clusters require Linux 7.0 or newer"
      exec "${harness}" "$@"
      ;;
   *)
      fail "Prodigy test clusters require Linux, using Apple Containers when launched from macOS"
      ;;
esac
