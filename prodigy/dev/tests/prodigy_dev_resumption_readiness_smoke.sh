#!/usr/bin/env bash
set -euo pipefail

PRODIGY_BIN="${1:-}"
MOTHERSHIP_BIN="${2:-}"
RESUMPTION_PROBE_BIN="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${SCRIPT_DIR}/prodigy_dev_netns_harness.sh"
source "${SCRIPT_DIR}/prodigy_dev_discombobulator_artifact_helpers.sh"
SCRIPT_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
prodigy_dev_reexec_in_private_mount_namespace_once PRODIGY_DEV_RESUMPTION_READINESS_SMOKE_MOUNT_NS_READY bash "${SCRIPT_SELF}" "$@"

if [[ -z "${PRODIGY_BIN}" || -z "${MOTHERSHIP_BIN}" || -z "${RESUMPTION_PROBE_BIN}" ]]
then
   echo "usage: $0 /path/to/prodigy /path/to/mothership /path/to/prodigy_resumption_readiness_probe_container"
   exit 2
fi

if [[ "$(id -u)" -ne 0 ]]
then
   echo "SKIP: requires root for isolated resumption readiness smoke"
   exit 77
fi

deps=(awk btrfs cargo mkfs.btrfs mount umount stat zstd timeout ip nsenter openssl python3 rg)
for cmd in "${deps[@]}"
do
   if ! command -v "${cmd}" >/dev/null 2>&1
   then
      echo "SKIP: missing required command: ${cmd}"
      exit 77
   fi
done

if [[ "${PRODIGY_DEV_ALLOW_BPF_ATTACH:-0}" != "1" ]]
then
   echo "SKIP: resumption readiness smoke requires fake boundary BPF attach; set PRODIGY_DEV_ALLOW_BPF_ATTACH=1 only inside an authorized isolated VM"
   exit 77
fi

PRODIGY_BIN="$(readlink -f "${PRODIGY_BIN}" 2>/dev/null || printf '%s' "${PRODIGY_BIN}")"
MOTHERSHIP_BIN="$(readlink -f "${MOTHERSHIP_BIN}" 2>/dev/null || printf '%s' "${MOTHERSHIP_BIN}")"
RESUMPTION_PROBE_BIN="$(readlink -f "${RESUMPTION_PROBE_BIN}" 2>/dev/null || printf '%s' "${RESUMPTION_PROBE_BIN}")"
target_arch="$(prodigy_dev_detect_target_arch)"

tmpdir="$(mktemp -d)"
workspace_root="${tmpdir}/workspace"
manifest_path="${workspace_root}/test-cluster-manifest.json"
cluster_name="resumption-readiness-$(date -u +%Y%m%d-%H%M%S)"
mothership_db_path="${tmpdir}/mothership-resumption-readiness.tidesdb"
keep_tmp="${PRODIGY_DEV_KEEP_TMP:-0}"
allow_containers_overmount="${PRODIGY_DEV_ALLOW_CONTAINERS_OVERMOUNT:-0}"
create_log="${tmpdir}/create_cluster.log"
register_log="${tmpdir}/register.log"
deploy_log="${tmpdir}/deploy.log"
application_log="${tmpdir}/application_report.log"
cluster_report_log="${tmpdir}/cluster_report.log"
combined_log="${tmpdir}/combined.log"
remove_log="${tmpdir}/remove_cluster.log"
tcp_tls_full_log="${tmpdir}/tcp_tls_full.log"
tcp_tls_resume_log="${tmpdir}/tcp_tls_resume.log"
tcp_tls_session="${tmpdir}/tcp_tls_session.pem"
picoquic_full_log="${tmpdir}/picoquic_full.log"
picoquic_resume_log="${tmpdir}/picoquic_resume.log"
picoquic_ticket_store="${tmpdir}/picoquic_tickets.bin"

containers_dir_created=0
containers_mount_created=0
containers_loop_image=""
cluster_created=0
archive_workspace=0

fail_with_log()
{
   archive_workspace=1
   echo "FAIL: $1"
   sed -n "1,${3:-180}p" "$2" || true
   exit 1
}

cleanup()
{
   set +e

   if [[ "${archive_workspace}" -eq 1 && -d "${workspace_root}" ]]
   then
      rm -rf "${tmpdir}/workspace-archive" >/dev/null 2>&1 || true
      cp -a "${workspace_root}" "${tmpdir}/workspace-archive" >/dev/null 2>&1 || true
   fi

   if [[ "${cluster_created}" -eq 1 ]]
   then
      env PRODIGY_MOTHERSHIP_TEST_HARNESS="${HARNESS}" \
         PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
         "${MOTHERSHIP_BIN}" removeCluster "${cluster_name}" \
         >"${remove_log}" 2>&1 || true
   fi

   if [[ "${containers_mount_created}" -eq 1 ]]
   then
      umount /containers >/dev/null 2>&1 || true
   fi

   if [[ "${containers_dir_created}" -eq 1 ]]
   then
      rmdir /containers >/dev/null 2>&1 || true
   fi

   if [[ "${keep_tmp}" -eq 1 ]]
   then
      echo "KEEP_TMP: ${tmpdir}"
   else
      rm -rf "${tmpdir}"
   fi
}
trap cleanup EXIT

if [[ ! -d /containers ]]
then
   mkdir -p /containers
   containers_dir_created=1
fi

containers_fs_type="$(stat -f -c '%T' /containers 2>/dev/null || echo unknown)"
if [[ "${containers_fs_type}" != "btrfs" ]]
then
   if awk '$2 == "/containers" { found = 1 } END { exit(found ? 0 : 1) }' /proc/self/mounts
   then
      if [[ "${allow_containers_overmount}" != "1" ]]
      then
         echo "FAIL: /containers is mounted but not btrfs (found ${containers_fs_type})"
         exit 1
      fi
   fi

   if ! prodigy_dev_containers_root_is_safely_overmountable /containers
   then
      echo "FAIL: /containers exists on non-btrfs fs and is not safely overmountable"
      exit 1
   fi

   containers_loop_image="${tmpdir}/containers.loop.img"
   truncate -s 2G "${containers_loop_image}"
   mkfs.btrfs -f "${containers_loop_image}" >/dev/null
   mount -o loop "${containers_loop_image}" /containers
   containers_mount_created=1
fi

mkdir -p /containers/store /containers/storage "${workspace_root}"

application_id=6
version_id=$(( ($(date +%s%N) & 281474976710655) ))
if [[ "${version_id}" -le 0 ]]
then
   version_id=1
fi
deployment_id=$(( (application_id << 48) | version_id ))
read -r -d '' CREATE_REQUEST <<EOF || true
{
  "name": "${cluster_name}",
  "deploymentMode": "test",
  "nBrains": 1,
  "machineSchemas": [
    {
      "schema": "bootstrap",
      "kind": "vm",
      "vmImageURI": "test://netns-local"
    }
  ],
  "test": {
    "workspaceRoot": "${workspace_root}",
    "machineCount": 1,
    "brainBootstrapFamily": "ipv4",
    "enableFakeIpv4Boundary": true,
    "host": {
      "mode": "local"
    }
  }
}
EOF

if ! env PRODIGY_MOTHERSHIP_TEST_HARNESS="${HARNESS}" \
   PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" createCluster "${CREATE_REQUEST}" \
   >"${create_log}" 2>&1
then
   fail_with_log "createCluster test cluster failed" "${create_log}" 200
fi
cluster_created=1

for _ in $(seq 1 300)
do
   if [[ -s "${manifest_path}" ]]
   then
      break
   fi
   sleep 0.2
done

if [[ ! -s "${manifest_path}" ]]
then
   fail_with_log "test cluster manifest did not become ready" "${create_log}" 200
fi

read -r parent_pid <<EOF
$(python3 - "${manifest_path}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
print(manifest["parentPid"])
PY
)
EOF

if [[ -z "${parent_pid}" || "${parent_pid}" == "0" ]]
then
   echo "FAIL: unable to parse persistent harness parent pid"
   exit 1
fi

register_request='{"name":"resumption-test-ipv4","kind":"BGP","prefix":"198.18.0.1/32","usage":"wormholes","ingressScope":"singleMachine"}'
if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" registerRoutableSubnet "${cluster_name}" "${register_request}" \
   >"${register_log}" 2>&1
then
   fail_with_log "registerRoutableSubnet failed" "${register_log}" 160
fi

read -r routable_uuid routable_address <<EOF
$(python3 - "${register_log}" <<'PY'
import re, sys
text = open(sys.argv[1], "r", encoding="utf-8").read()
uuid = re.search(r"\buuid=([0-9a-fA-Fx]+)", text)
prefix = re.search(r"\bprefix=([^\s]+)", text)
if not uuid or not prefix:
    raise SystemExit(1)
print(uuid.group(1), prefix.group(1).split("/", 1)[0])
PY
)
EOF

if [[ -z "${routable_uuid}" || -z "${routable_address}" ]]
then
   fail_with_log "unable to parse registered resumption routable prefix" "${register_log}" 120
fi

artifact_project_dir="${tmpdir}/resumption-readiness-artifact"
discombobulator_file="${artifact_project_dir}/ResumptionReadinessProbe.DiscombobuFile"
container_blob="${tmpdir}/resumption-readiness.container.zst"
mkdir -p "${artifact_project_dir}"
picoquic_cert="${artifact_project_dir}/resumption_quic.cert.pem"
picoquic_key="${artifact_project_dir}/resumption_quic.key.pem"
if ! openssl req \
   -x509 \
   -newkey rsa:2048 \
   -sha256 \
	   -days 1 \
	   -nodes \
	   -subj "/CN=quic.resumption.test" \
	   -addext "subjectAltName=DNS:quic.resumption.test" \
	   -addext "basicConstraints=critical,CA:TRUE" \
	   -addext "keyUsage=critical,keyCertSign,digitalSignature,keyEncipherment" \
	   -addext "extendedKeyUsage=serverAuth" \
	   -keyout "${picoquic_key}" \
	   -out "${picoquic_cert}" \
	   >/dev/null 2>&1
then
   archive_workspace=1
   echo "FAIL: unable to generate picoquic test certificate"
   exit 1
fi
chmod 0644 "${picoquic_cert}" "${picoquic_key}"
cat > "${discombobulator_file}" <<EOF
FROM scratch for ${target_arch}
COPY {bin} ./$(basename "${RESUMPTION_PROBE_BIN}") /root/resumption_readiness_probe_container
COPY {cert} ./$(basename "${picoquic_cert}") /root/resumption_quic.cert.pem
COPY {cert} ./$(basename "${picoquic_key}") /root/resumption_quic.key.pem
SURVIVE /root/resumption_readiness_probe_container
SURVIVE /root/resumption_quic.cert.pem
SURVIVE /root/resumption_quic.key.pem
EOF
prodigy_dev_write_common_prodigy_assets "${discombobulator_file}"
cat >> "${discombobulator_file}" <<'EOF'
EXECUTE ["/root/resumption_readiness_probe_container"]
EOF

if ! prodigy_dev_run_discombobulator_build \
   "${artifact_project_dir}" \
   "${discombobulator_file}" \
   "${container_blob}" \
   "bin=$(dirname "${RESUMPTION_PROBE_BIN}")" \
   "cert=${artifact_project_dir}" \
   "ebpf=$(dirname "${PRODIGY_BIN}")"
then
   archive_workspace=1
   echo "FAIL: unable to build resumption readiness artifact"
   exit 1
fi

plan_json="${tmpdir}/resumption-readiness.plan.json"
cat > "${plan_json}" <<EOF
{
  "config": {
    "type": "ApplicationType::stateless",
    "applicationID": ${application_id},
    "versionID": ${version_id},
    "architecture": "${target_arch}",
    "filesystemMB": 64,
    "storageMB": 64,
    "memoryMB": 256,
    "nLogicalCores": 1,
    "msTilHealthy": 5000,
    "sTilHealthcheck": 5,
    "sTilKillable": 30
  },
  "minimumSubscriberCapacity": 1024,
  "isStateful": false,
  "stateless": {
    "nBase": 2,
    "maxPerRackRatio": 1.0,
    "maxPerMachineRatio": 1.0,
    "moveableDuringCompaction": true
  },
  "wormholes": [
    {
      "name": "resumption-tcp",
      "source": "registeredRoutablePrefix",
      "routablePrefixUUID": "${routable_uuid}",
      "externalPort": 42501,
      "containerPort": 18501,
      "layer4": "TCP",
      "isQuic": false,
      "tlsResumption": {
        "sniNames": ["tcp.resumption.test"],
        "alpns": ["http/1.1"]
      }
    },
    {
      "name": "resumption-quic",
      "source": "registeredRoutablePrefix",
      "routablePrefixUUID": "${routable_uuid}",
      "externalPort": 42502,
      "containerPort": 18502,
      "layer4": "UDP",
      "isQuic": true,
      "quicCidKeyRotationHours": 24,
      "tlsResumption": {
        "sniNames": ["quic.resumption.test"],
        "alpns": ["h3"]
      }
    }
  ],
  "moveConstructively": true,
  "requiresDatacenterUniqueTag": false
}
EOF

if ! env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
   "${MOTHERSHIP_BIN}" deploy "${cluster_name}" "$(cat "${plan_json}")" "${container_blob}" \
   >"${deploy_log}" 2>&1
then
   fail_with_log "resumption readiness deployment failed" "${deploy_log}" 220
fi

healthy=0
for _ in $(seq 1 160)
do
   if env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" applicationReport "${cluster_name}" Nametag \
      >"${application_log}" 2>&1
   then
      if rg -q '^[[:space:]]*nHealthy:[[:space:]]*2$' "${application_log}"
      then
         healthy=1
         break
      fi
      if rg -q '^[[:space:]]*nCrashes:[[:space:]]*[1-9]' "${application_log}"
      then
         break
      fi
   fi

   sleep 0.5
done

if [[ "${healthy}" -ne 1 ]]
then
   archive_workspace=1
   echo "FAIL: resumption readiness deployment never reached 2 healthy containers"
   env PRODIGY_MOTHERSHIP_TIDESDB_PATH="${mothership_db_path}" \
      "${MOTHERSHIP_BIN}" clusterReport "${cluster_name}" \
      >"${cluster_report_log}" 2>&1 || true
   sed -n '1,240p' "${cluster_report_log}" || true
   sed -n '1,220p' "${application_log}" || true
   sed -n '1,220p' "${deploy_log}" || true
   exit 1
fi

collect_evidence()
{
   : >"${combined_log}"
   while IFS= read -r stdout_log
   do
      if [[ -f "${stdout_log}" ]]
      then
         cat "${stdout_log}" >>"${combined_log}" 2>/dev/null || true
         while IFS= read -r container_pid
         do
            if [[ -n "${container_pid}" ]] && kill -0 "${container_pid}" >/dev/null 2>&1
            then
               cat "/proc/${container_pid}/root/resumption_readiness_probe_evidence.log" >>"${combined_log}" 2>/dev/null || true
            fi
         done < <(
            rg -o 'spinContainer start ok deploymentID=[0-9]+ appID=6 .* pid=[0-9]+' "${stdout_log}" 2>/dev/null \
               | sed -E 's/.* pid=([0-9]+).*/\1/'
         )
      fi
   done < <(python3 - "${manifest_path}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
for node in manifest["nodes"]:
    print(node["stdoutLog"])
PY
   )
}

count_unique_trace_containers()
{
   local pattern="$1"
   { rg "${pattern}" "${combined_log}" 2>/dev/null || true; } \
      | awk '{
           for (i = 1; i <= NF; i++) {
              if ($i ~ /^containerUUID=[0-9]+$/) {
                 sub(/^containerUUID=/, "", $i)
                 seen[$i] = 1
              }
           }
        }
        END {
           count = 0
           for (pid in seen) {
              count++
           }
           print count
        }'
}

evidence_ok=0
for _ in $(seq 1 160)
do
   collect_evidence
   probe_ok_count="$(rg -c 'probe\.all_ok' "${combined_log}" 2>/dev/null || printf '0\n')"
   tcp_promotion_count="$(count_unique_trace_containers 'probe\.resumption_delta resumption-tcp .*reason=tls-resumption-issue-promotion .*applySuccess=1 issueReady=1')"
   quic_promotion_count="$(count_unique_trace_containers 'probe\.resumption_delta resumption-quic .*reason=tls-resumption-issue-promotion .*applySuccess=1 issueReady=1')"

   if [[ "${probe_ok_count}" -ge 2 && "${tcp_promotion_count}" -ge 2 && "${quic_promotion_count}" -ge 2 ]]
   then
      evidence_ok=1
      break
   fi

   sleep 0.5
done

if [[ "${evidence_ok}" -ne 1 ]]
then
   archive_workspace=1
   echo "FAIL: resumption readiness evidence did not converge"
   echo "---- combined evidence ----"
   sed -n '1,260p' "${combined_log}" || true
   echo "---- deploy log ----"
   sed -n '1,220p' "${deploy_log}" || true
   exit 1
fi

run_tcp_tls_client()
{
   local output_log="$1"
   local payload="$2"
   local expected_resumed="$3"
   local -a openssl_args=(
      s_client
      -connect "${routable_address}:42501"
      -tls1_3
      -servername tcp.resumption.test
      -alpn http/1.1
      -quiet
      -ign_eof
   )

   if [[ "${expected_resumed}" == full ]]
   then
      openssl_args+=(-sess_out "${tcp_tls_session}")
   else
      openssl_args+=(-sess_in "${tcp_tls_session}")
   fi

   if ! printf '%s' "${payload}" |
      timeout 30 nsenter -t "${parent_pid}" -n openssl "${openssl_args[@]}" >"${output_log}" 2>&1
   then
      archive_workspace=1
      echo "FAIL: TCP TLS client command failed"
      sed -n '1,180p' "${output_log}" || true
      collect_evidence
      echo "---- combined evidence ----"
      sed -n '1,360p' "${combined_log}" || true
      exit 1
   fi
}

run_tcp_tls_client "${tcp_tls_full_log}" "tcp-full" full

if [[ ! -s "${tcp_tls_session}" ]]
then
   fail_with_log "TCP TLS full handshake did not save a session" "${tcp_tls_full_log}" 180
fi

run_tcp_tls_client "${tcp_tls_resume_log}" "tcp-resume" resumed
collect_evidence

if ! rg -q 'tcp-tls-ok full' "${tcp_tls_full_log}" ||
   ! rg -q 'tcp-tls-ok resumed' "${tcp_tls_resume_log}" ||
   ! rg -q 'probe\.tcp_tls\.connection full' "${combined_log}" ||
   ! rg -q 'probe\.tcp_tls\.connection resumed' "${combined_log}"
then
   archive_workspace=1
   echo "FAIL: TCP TLS resumption evidence missing"
   echo "---- tcp full ----"
   sed -n '1,160p' "${tcp_tls_full_log}" || true
   echo "---- tcp resume ----"
   sed -n '1,160p' "${tcp_tls_resume_log}" || true
   echo "---- combined evidence ----"
   sed -n '1,320p' "${combined_log}" || true
   exit 1
fi

quic_listen_ok=0
for _ in $(seq 1 160)
do
   collect_evidence
   if rg -q 'probe\.quic\.listen resumption-quic' "${combined_log}"
   then
      quic_listen_ok=1
      break
   fi
   sleep 0.5
done

if [[ "${quic_listen_ok}" -ne 1 ]]
then
   fail_with_log "picoquic container listener did not become ready" "${combined_log}" 320
fi

picoquic_cid_candidates="$(rg -o 'probe\.quic\.cid [0-9a-fA-F]+' "${combined_log}" 2>/dev/null | awk '{ print tolower($2) }' | sort -u)"
if [[ -z "${picoquic_cid_candidates}" ]]
then
   fail_with_log "unable to parse picoquic routing CID" "${combined_log}" 320
fi

run_picoquic_client()
{
   local output_log="$1"
   local payload="$2"
   local mode="$3"

   timeout 45 nsenter -t "${parent_pid}" -n \
      "${RESUMPTION_PROBE_BIN}" \
         --picoquic-client \
         "${routable_address}" \
         42502 \
         "${picoquic_ticket_store}" \
         "${payload}" \
         "${mode}" \
         0 \
         "${picoquic_cid_hex}" \
         "${picoquic_cert}" \
         >"${output_log}" 2>&1
}

picoquic_cid_hex=""
while IFS= read -r candidate_cid
do
   if [[ ! "${candidate_cid}" =~ ^[0-9a-f]{32}$ ]]
   then
      continue
   fi

   picoquic_cid_hex="${candidate_cid}"
   : >"${picoquic_ticket_store}"
   if run_picoquic_client "${picoquic_full_log}" quic-full full
   then
      break
   fi
   picoquic_cid_hex=""
done <<<"${picoquic_cid_candidates}"

if [[ -z "${picoquic_cid_hex}" ]]
then
   fail_with_log "picoquic full client command failed" "${picoquic_full_log}" 180
fi

if [[ ! -s "${picoquic_ticket_store}" ]]
then
   fail_with_log "picoquic fresh handshake did not save a ticket" "${picoquic_full_log}" 180
fi

if ! run_picoquic_client "${picoquic_resume_log}" quic-resume resumed
then
   fail_with_log "picoquic resumed client command failed" "${picoquic_resume_log}" 180
fi

collect_evidence
if ! rg -q 'quic-client-ok quic-ok full' "${picoquic_full_log}" ||
   ! rg -q 'quic-client-ok quic-ok resumed' "${picoquic_resume_log}" ||
   ! rg -q 'probe\.quic\.connection full' "${combined_log}" ||
   ! rg -q 'probe\.quic\.connection resumed' "${combined_log}"
then
   archive_workspace=1
   echo "FAIL: picoquic resumption evidence missing"
   echo "---- picoquic full ----"
   sed -n '1,160p' "${picoquic_full_log}" || true
   echo "---- picoquic resume ----"
   sed -n '1,160p' "${picoquic_resume_log}" || true
   echo "---- combined evidence ----"
   sed -n '1,360p' "${combined_log}" || true
   exit 1
fi

echo "PASS: resumption readiness smoke address=${routable_address} deploymentID=${deployment_id} promotedTcp=${tcp_promotion_count} promotedQuic=${quic_promotion_count} tcpTls=full,resumed picoquic=full,resumed"
