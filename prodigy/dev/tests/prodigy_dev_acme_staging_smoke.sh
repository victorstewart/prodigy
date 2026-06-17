#!/usr/bin/env bash
set -euo pipefail

MOTHERSHIP_BIN="${1:-}"
SOURCE_ROOT="${2:-}"
CERTBOT_WHEELHOUSE="${3:-${PRODIGY_CERTBOT_WHEELHOUSE:-}}"

if [[ -z "${MOTHERSHIP_BIN}" || ! -x "${MOTHERSHIP_BIN}" || -z "${SOURCE_ROOT}" || ! -d "${SOURCE_ROOT}" ]]
then
   echo "usage: $0 /path/to/mothership /path/to/prodigy-root" >&2
   exit 2
fi

missing=()
for name in PRODIGY_ACME_STAGING_DOMAIN PRODIGY_ACME_ACCOUNT_EMAIL PRODIGY_CLUSTER_UUID PRODIGY_ACME_CERT_NAME PRODIGY_ACME_APPLICATION_ID PRODIGY_ACME_DEPLOYMENT_ID PRODIGY_ACME_WORMHOLE_NAME
do
   [[ -n "${!name:-}" ]] || missing+=("${name}")
done

if [[ -z "${PRODIGY_ACME_TARGET:-}" && -z "${PRODIGY_MOTHERSHIP_SOCKET:-}" && -z "${PRODIGY_CONTROL_SOCKET:-}" ]]
then
   missing+=("PRODIGY_ACME_TARGET or PRODIGY_MOTHERSHIP_SOCKET")
fi

if (( ${#missing[@]} ))
then
   printf 'SKIP: missing ACME staging inputs: %s\n' "${missing[*]}"
   exit 77
fi

RUN_ROOT="${PRODIGY_ACME_STAGING_RUN_ROOT:-${SOURCE_ROOT}/.run/acme-staging-smoke}"
CERTBOT_BIN="${PRODIGY_CERTBOT_BIN:-${RUN_ROOT}/certbot/bin/certbot}"
if [[ -z "${PRODIGY_CERTBOT_BIN:-}" ]]
then
   if [[ -z "${CERTBOT_WHEELHOUSE}" || ! -r "${CERTBOT_WHEELHOUSE}" ]]
   then
      echo "SKIP: managed Certbot wheelhouse is not available"
      exit 77
   fi
   rm -rf "${RUN_ROOT}/certbot.prev" "${RUN_ROOT}/certbot.wheels"
   mkdir -p "${RUN_ROOT}/certbot.wheels"
   tar --zstd -xf "${CERTBOT_WHEELHOUSE}" -C "${RUN_ROOT}/certbot.wheels"
   [[ ! -d "${RUN_ROOT}/certbot" ]] || mv "${RUN_ROOT}/certbot" "${RUN_ROOT}/certbot.prev"
   python3 -m venv "${RUN_ROOT}/certbot"
   "${RUN_ROOT}/certbot/bin/pip" install --no-index --no-cache-dir --disable-pip-version-check --find-links "${RUN_ROOT}/certbot.wheels" 'certbot==5.6.0'
   "${RUN_ROOT}/certbot/bin/certbot" --version | grep -F '5.6.0' >/dev/null
   rm -rf "${RUN_ROOT}/certbot.wheels"
fi
if [[ ! -x "${CERTBOT_BIN}" ]]
then
   echo "FAIL: managed Certbot binary is not executable: ${CERTBOT_BIN}" >&2
   exit 1
fi

HOOK_DIR="${PRODIGY_ACME_HOOK_DIR:-${SOURCE_ROOT}/prodigy/acme}"
for hook in acme-present-dns-01 acme-cleanup-dns-01 acme-import-lineage
do
   if [[ ! -x "${HOOK_DIR}/${hook}" ]]
   then
      echo "FAIL: missing executable ACME hook: ${HOOK_DIR}/${hook}" >&2
      exit 1
   fi
done

CONFIG_DIR="${RUN_ROOT}/config"
WORK_DIR="${RUN_ROOT}/work"
LOGS_DIR="${RUN_ROOT}/logs"
mkdir -p "${CONFIG_DIR}" "${WORK_DIR}" "${LOGS_DIR}"
umask 077

domains=(-d "${PRODIGY_ACME_STAGING_DOMAIN}")
if [[ -n "${PRODIGY_ACME_STAGING_EXTRA_DOMAINS:-}" ]]
then
   read -r -a extra_domains <<<"${PRODIGY_ACME_STAGING_EXTRA_DOMAINS}"
   for domain in "${extra_domains[@]}"
   do
      domains+=(-d "${domain}")
   done
fi

export PRODIGY_MOTHERSHIP="${MOTHERSHIP_BIN}"
if [[ -z "${PRODIGY_MOTHERSHIP_SOCKET:-}" && -n "${PRODIGY_CONTROL_SOCKET:-}" ]]
then
   export PRODIGY_MOTHERSHIP_SOCKET="${PRODIGY_CONTROL_SOCKET}"
fi

"${CERTBOT_BIN}" certonly \
   --force-renewal \
   --manual \
   --preferred-challenges dns \
   --manual-auth-hook "${HOOK_DIR}/acme-present-dns-01" \
   --manual-cleanup-hook "${HOOK_DIR}/acme-cleanup-dns-01" \
   --deploy-hook "${HOOK_DIR}/acme-import-lineage" \
   --no-directory-hooks \
   --cert-name "${PRODIGY_ACME_CERT_NAME}" \
   --key-type "${PRODIGY_ACME_KEY_TYPE:-ecdsa}" \
   --email "${PRODIGY_ACME_ACCOUNT_EMAIL}" \
   --non-interactive \
   --agree-tos \
   --test-cert \
   --config-dir "${CONFIG_DIR}" \
   --work-dir "${WORK_DIR}" \
   --logs-dir "${LOGS_DIR}" \
   "${domains[@]}"

if ! grep -F "importACMELineage success=1 certName=${PRODIGY_ACME_CERT_NAME}" "${LOGS_DIR}/letsencrypt.log" >/dev/null
then
   echo "FAIL: ACME issuance did not import lineage into Prodigy" >&2
   exit 1
fi

lineage="${CONFIG_DIR}/live/${PRODIGY_ACME_CERT_NAME}"
if [[ ! -s "${lineage}/fullchain.pem" || ! -s "${lineage}/privkey.pem" ]]
then
   echo "FAIL: certbot staging lineage missing fullchain.pem or privkey.pem: ${lineage}" >&2
   exit 1
fi

if [[ -n "${PRODIGY_ACME_STAGING_VERIFY_COMMAND:-}" ]]
then
   bash -lc "${PRODIGY_ACME_STAGING_VERIFY_COMMAND}"
fi

echo "PASS: ACME staging issuance completed for ${PRODIGY_ACME_CERT_NAME}"
