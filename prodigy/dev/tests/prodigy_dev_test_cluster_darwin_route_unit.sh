#!/usr/bin/env bash
set -Eeuo pipefail

source_launcher="${1:-}"
[[ -r "${source_launcher}" ]] || {
   echo "usage: $0 /path/to/prodigy_dev_test_cluster.sh" >&2
   exit 2
}

fail()
{
   echo "FAIL: $*" >&2
   exit 1
}

work_root="$(mktemp -d /tmp/prodigy-darwin-route-unit.XXXXXX)"
cleanup()
{
   [[ "${work_root}" == /tmp/prodigy-darwin-route-unit.* ]] || return
   rm -rf -- "${work_root}"
}
trap cleanup EXIT

fixture_repo="${work_root}/repo"
mock_bin="${work_root}/bin"
subject="${fixture_repo}/prodigy/dev/tests/prodigy_dev_test_cluster.sh"
instance="${work_root}/instance.json"
inspection="${work_root}/inspection.json"
event_log="${work_root}/events"
route_state_file="${work_root}/route-state"
output="${work_root}/output"
mkdir -p "${mock_bin}" "$(dirname "${subject}")" "${fixture_repo}/build"

sed \
   -e "s#/usr/sbin/netstat#${mock_bin}/netstat#g" \
   -e "s#/usr/bin/sudo#${mock_bin}/sudo#g" \
   -e "s#/sbin/route#${mock_bin}/route#g" \
   "${source_launcher}" > "${subject}"

jq -n '{name:"nametag-prodigy",labels:{"dev.prodigy.bpf-authorized":"guest-only"},environment:{PRODIGY_DEV_ALLOW_BPF_ATTACH:"1",PRODIGY_BPF_AUTHORIZATION:"guest-only"}}' > "${instance}"
jq -n --arg source "${fixture_repo}" '[{configuration:{platform:{os:"linux"},capAdd:["ALL"],mounts:[{source:$source,destination:"/root/prodigy"}]},status:{networks:[{network:"default",ipv4Address:"192.168.64.4/24",mtu:1280}]}}]' > "${inspection}"

cat > "${mock_bin}/mock" <<'EOF'
#!/usr/bin/env bash
tool="${0##*/}"
exact_route()
{
   local mtu="${1:-1280}"
   printf '%s\n' \
      'destination: 198.18.0.0' \
      '       mask: 255.255.0.0' \
      '    gateway: 192.168.64.4' \
      ' recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire' \
      "        0         0         0         0         0         0     ${mtu}         0"
}

case "${tool}" in
   uname)
      [[ "${1:-}" == -s ]] || exit 64
      echo Darwin
      ;;
   container)
      case "${1:-}" in
         system) echo "status running" ;;
         inspect) cat "${INSPECTION_FILE}" ;;
         exec)
            echo "container exec" >> "${EVENT_LOG}"
            exit "${CONTAINER_EXEC_STATUS:-0}"
            ;;
         *) exit 64 ;;
      esac
      ;;
   launcher)
      echo "launcher ${1:-}" >> "${EVENT_LOG}"
      case "${1:-}" in
         ensure) exit 0 ;;
         stop) exit "${LAUNCHER_STOP_STATUS:-0}" ;;
         *) exit 64 ;;
      esac
      ;;
   sudo)
      exec "$@"
      ;;
   route)
      [[ "${1:-}" == -n ]] || exit 64
      operation="${2:-}"
      echo "route ${operation}" >> "${EVENT_LOG}"
      case "${operation}" in
         get)
            if [[ -e "${ROUTE_STATE_FILE}" ]]
            then
               if [[ "${ROUTE_SCENARIO}" == post-add-wrong-prefix ]]
               then
                  printf '%s\n' 'destination: 198.18.0.0' '       mask: 255.255.255.0' '    gateway: 192.168.64.4'
               else
                  exact_route
               fi
            elif [[ "${ROUTE_SCENARIO}" == exact ]]
            then
               exact_route
            elif [[ "${ROUTE_SCENARIO}" == exact-conflict ]]
            then
               printf '%s\n' 'destination: 198.18.0.0' '       mask: 255.255.0.0' '    gateway: 192.168.64.99'
            elif [[ "${ROUTE_SCENARIO}" == exact-mtu-conflict ]]
            then
               exact_route 1500
            else
               printf '%s\n' 'destination: default' '    gateway: 192.168.64.1'
            fi
            ;;
         add)
            [[ "$*" == "-n add -net 198.18.0.0/16 192.168.64.4 -mtu 1280" ]] || exit 65
            : > "${ROUTE_STATE_FILE}"
            ;;
         delete)
            [[ "$*" == "-n delete -net 198.18.0.0/16 192.168.64.4" ]] || exit 66
            rm -f "${ROUTE_STATE_FILE}"
            ;;
         *) exit 64 ;;
      esac
      ;;
   netstat)
      echo netstat >> "${EVENT_LOG}"
      case "${ROUTE_SCENARIO}" in
         exact) echo "198.18.0/16 192.168.64.4" ;;
         exact-conflict) echo "198.18.0/16 192.168.64.99" ;;
         exact-mtu-conflict) echo "198.18.0/16 192.168.64.4" ;;
         more-specific-host) echo "198.18.0.3 192.168.64.4" ;;
         more-specific-range) echo "198.18.128/17 192.168.64.4" ;;
         *) [[ ! -e "${ROUTE_STATE_FILE}" ]] || echo "198.18.0/16 192.168.64.4" ;;
      esac
      ;;
   *)
      exit 64
      ;;
esac
EOF
chmod +x "${subject}" "${mock_bin}/mock"
for tool in uname container launcher sudo route netstat
do
   ln -s mock "${mock_bin}/${tool}"
done

base_env=(
   "PATH=${mock_bin}:${PATH}"
   "APPLE_LINUX_DEV_LAUNCHER=${mock_bin}/launcher"
   "PRODIGY_APPLE_CONTAINER_INSTANCE=${instance}"
   "INSPECTION_FILE=${inspection}"
   "EVENT_LOG=${event_log}"
   "ROUTE_STATE_FILE=${route_state_file}"
)
status=0

run_case()
{
   local scenario="$1"
   local exec_status="${2:-0}"
   : > "${event_log}"
   rm -f "${route_state_file}"
   set +e
   env "${base_env[@]}" "ROUTE_SCENARIO=${scenario}" "CONTAINER_EXEC_STATUS=${exec_status}" \
      "${subject}" "${fixture_repo}/build/prodigy" > "${output}" 2>&1
   status=$?
   set -e
}

expect()
{
   local expected_status="$1"
   local expected_events="$2"
   local actual_events
   actual_events="$(paste -sd, "${event_log}")"
   [[ "${status}" -eq "${expected_status}" && "${actual_events}" == "${expected_events}" ]] || {
      cat "${output}" >&2
      fail "status/events: expected ${expected_status} [${expected_events}], got ${status} [${actual_events}]"
   }
}

run_case exact
expect 0 'launcher ensure,netstat,route get,netstat,container exec,launcher stop'

run_case default
expect 0 'launcher ensure,netstat,route get,route add,route get,netstat,container exec,route delete,launcher stop'
[[ ! -e "${route_state_file}" ]] || fail "owned route survived successful cleanup"

run_case default 37
expect 37 'launcher ensure,netstat,route get,route add,route get,netstat,container exec,route delete,launcher stop'

run_case exact-conflict
expect 1 'launcher ensure,netstat,route get,launcher stop'
grep -Fq 'already uses a different gateway: 192.168.64.99' "${output}" || fail "missing exact-route conflict diagnostic"

run_case exact-mtu-conflict
expect 1 'launcher ensure,netstat,route get,launcher stop'
grep -Fq 'already uses a different MTU: 1500' "${output}" || fail "missing exact-route MTU conflict diagnostic"

run_case more-specific-host
expect 1 'launcher ensure,netstat,launcher stop'
grep -Fq '198.18.0.3 via 192.168.64.4' "${output}" || fail "missing host-route conflict diagnostic"

run_case more-specific-range
expect 1 'launcher ensure,netstat,launcher stop'
grep -Fq '198.18.128/17 via 192.168.64.4' "${output}" || fail "missing subnet-route conflict diagnostic"

run_case post-add-wrong-prefix
expect 1 'launcher ensure,netstat,route get,route add,route get,route delete,launcher stop'
grep -Fq 'failed to verify the Apple Container host route' "${output}" || fail "missing post-add verification diagnostic"

: > "${event_log}"
rm -f "${route_state_file}"
env "${base_env[@]}" ROUTE_SCENARIO=default "${subject}" --hold-apple-route > "${output}" 2>&1 &
owner_pid=$!
for _ in $(seq 1 200)
do
   grep -q '^APPLE_ROUTE_OWNER:' "${output}" 2>/dev/null && break
   kill -0 "${owner_pid}" 2>/dev/null || break
   sleep 0.01
done
grep -q '^APPLE_ROUTE_OWNER:' "${output}" || {
   kill -TERM "${owner_pid}" 2>/dev/null || true
   wait "${owner_pid}" 2>/dev/null || true
   cat "${output}" >&2
   fail "route owner did not announce readiness"
}
kill -TERM "${owner_pid}"
set +e
wait "${owner_pid}"
status=$?
set -e
expect 143 'launcher ensure,netstat,route get,route add,route get,netstat,route delete,launcher stop'
[[ ! -e "${route_state_file}" ]] || fail "route owner did not remove its route"

echo "PASS: Darwin route ownership lifecycle"
