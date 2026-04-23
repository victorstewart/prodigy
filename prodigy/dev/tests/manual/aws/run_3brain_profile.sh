#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
RUN_STAMP="${RUN_STAMP:-$(date -u +%Y%m%d-%H%M%S)}"
RUN_NAME="${RUN_NAME:-aws-3brain-runtime-${RUN_STAMP}}"
WORK_ROOT="${NAMETAG_WORK_ROOT:-${ROOT_DIR}/.run}"
RUN_DIR="${RUN_DIR:-${WORK_ROOT}/mothership-live-${RUN_NAME}}"
MOTHERSHIP_BIN="${MOTHERSHIP_BIN:-${ROOT_DIR}/.run/build/preflight-aws-runtime-20260323/mothership-x86_64/mothership}"
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_INSTANCE_TYPE="${AWS_INSTANCE_TYPE:-t3.micro}"
AWS_PROVIDER_SCOPE="${AWS_PROVIDER_SCOPE:-acct-test/${AWS_REGION}}"
case "${AWS_INSTANCE_TYPE}" in
   t2.micro|t3.micro)
      ;;
   *)
      printf 'AWS_INSTANCE_TYPE must be t2.micro or t3.micro, got: %s\n' "${AWS_INSTANCE_TYPE}" >&2
      exit 1
      ;;
esac
SSH_PRIVATE_KEY_PATH_DEFAULT="/root/.ssh/prodigy_aws_test_ed25519"
if [[ -f "${SSH_PRIVATE_KEY_PATH_DEFAULT}" && -f "${SSH_PRIVATE_KEY_PATH_DEFAULT}.pub" ]]; then
   SSH_PRIVATE_KEY_PATH="${SSH_PRIVATE_KEY_PATH:-${SSH_PRIVATE_KEY_PATH_DEFAULT}}"
else
   SSH_PRIVATE_KEY_PATH="${SSH_PRIVATE_KEY_PATH:-/root/.ssh/id_rsa}"
fi
SSH_PUBLIC_KEY_PATH="${SSH_PUBLIC_KEY_PATH:-${SSH_PRIVATE_KEY_PATH}.pub}"
LOCAL_STATE_DB="${LOCAL_STATE_DB:-${RUN_DIR}/mothership-db}"
LOCAL_XDG_DATA_HOME="${LOCAL_XDG_DATA_HOME:-${RUN_DIR}/xdg-data}"
LOCAL_MOTHERSHIP_TIDESDB_PATH="${LOCAL_MOTHERSHIP_TIDESDB_PATH:-${RUN_DIR}/mothership-tidesdb}"
CLUSTER_CREATE_TIMEOUT_SECONDS="${CLUSTER_CREATE_TIMEOUT_SECONDS:-900}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-900}"
SSH_READY_TIMEOUT_SECONDS="${SSH_READY_TIMEOUT_SECONDS:-600}"
SECURITY_GROUP_ID=""
SECURITY_GROUP_NAME=""
INSTANCE_IDS=()
SSH_WAIT_PIDS=()
CLUSTER_CREATED=0

mkdir -p "${RUN_DIR}"

log()
{
   printf '%s %s\n' "$(python3 -c 'import time; print(f"{time.time():.6f}")')" "$*" | tee -a "${RUN_DIR}/harness.log"
}

require_file()
{
   local path="$1"
   if [[ ! -f "${path}" ]]; then
      printf 'required file missing: %s\n' "${path}" >&2
      exit 1
   fi
}

run_timed()
{
   local outfile="$1"
   shift
   "$@" 2>&1 | stdbuf -oL -eL perl -MTime::HiRes=time -ne 'printf("%.6f %s", time, $_)' | tee "${outfile}"
}

run_local()
{
   env \
      HOME=/root \
      XDG_DATA_HOME="${LOCAL_XDG_DATA_HOME}" \
      PRODIGY_STATE_DB="${LOCAL_STATE_DB}" \
      PRODIGY_MOTHERSHIP_TIDESDB_PATH="${LOCAL_MOTHERSHIP_TIDESDB_PATH}" \
      stdbuf -oL -eL "$@"
}

collect_journals()
{
   if [[ ! -f "${RUN_DIR}/instances.tsv" ]]; then
      return
   fi

   local ordinal=0
   while IFS=$'\t' read -r instance_id public_ip private_ip; do
      ordinal="$((ordinal + 1))"
      local label="brain-${ordinal}"
      if [[ "${ordinal}" -eq 1 ]]; then
         label="seed"
      fi
      if [[ -z "${public_ip}" ]]; then
         continue
      fi
      ssh -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null \
         -o BatchMode=yes \
         -o ConnectTimeout=5 \
         -i "${SSH_PRIVATE_KEY_PATH}" \
         "root@${public_ip}" \
         "journalctl -u prodigy --no-pager -o short-unix || true" \
         > "${RUN_DIR}/${label}.journal" 2> "${RUN_DIR}/${label}.journal.stderr" || true
      printf '%s\t%s\t%s\t%s\n' "${label}" "${instance_id}" "${public_ip}" "${private_ip}" >> "${RUN_DIR}/journals.tsv"
   done < "${RUN_DIR}/instances.tsv"
}

terminate_instances()
{
   if [[ ${#INSTANCE_IDS[@]} -eq 0 ]]; then
      return
   fi

   set -a
   # shellcheck disable=SC1091
   source "${ROOT_DIR}/.env.aws"
   set +a
   export RUN_DIR AWS_REGION SECURITY_GROUP_ID

   python3 - <<'PY'
import boto3
import json
import os
import time

run_dir = os.environ["RUN_DIR"]
region = os.environ["AWS_REGION"]
session = boto3.session.Session(
   aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
   aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
   region_name=region,
)
ec2 = session.client("ec2")

instances_path = os.path.join(run_dir, "instances.tsv")
instance_ids = []
with open(instances_path, "r", encoding="utf-8") as handle:
   for line in handle:
      line = line.strip()
      if not line:
         continue
      instance_ids.append(line.split("\t", 1)[0])

if instance_ids:
   ec2.terminate_instances(InstanceIds=instance_ids)
   waiter = ec2.get_waiter("instance_terminated")
   waiter.wait(InstanceIds=instance_ids)

reservation = ec2.describe_instances(InstanceIds=instance_ids) if instance_ids else {"Reservations": []}
instances = []
for reservation_item in reservation.get("Reservations", []):
   for instance in reservation_item.get("Instances", []):
      instances.append({
         "InstanceId": instance.get("InstanceId"),
         "State": instance.get("State", {}),
      })

with open(os.path.join(run_dir, "postCleanup.instances.json"), "w", encoding="utf-8") as handle:
   json.dump(instances, handle, indent=2)

security_group_id = os.environ.get("SECURITY_GROUP_ID", "")
if security_group_id:
   for _ in range(20):
      try:
         ec2.delete_security_group(GroupId=security_group_id)
         break
      except Exception:
         time.sleep(3)

   try:
      groups = ec2.describe_security_groups(GroupIds=[security_group_id])["SecurityGroups"] if security_group_id else []
   except Exception:
      groups = []
else:
   groups = []

with open(os.path.join(run_dir, "postCleanup.security-groups.json"), "w", encoding="utf-8") as handle:
   json.dump(groups, handle, indent=2)
PY
}

cleanup()
{
   local rc=$?
   set +e

   collect_journals

   if [[ "${CLUSTER_CREATED}" -eq 1 ]]; then
      run_timed "${RUN_DIR}/removeCluster.timed.out" run_local "${MOTHERSHIP_BIN}" removeCluster "${RUN_NAME}" >/dev/null 2>&1 || true
      run_local "${MOTHERSHIP_BIN}" removeProviderCredential "${RUN_NAME}-credential" > "${RUN_DIR}/removeProviderCredential.out" 2>&1 || true
   fi

   terminate_instances || true

   exit "${rc}"
}

trap cleanup EXIT

require_file "${ROOT_DIR}/.env.aws"
require_file "${MOTHERSHIP_BIN}"
require_file "${SSH_PRIVATE_KEY_PATH}"
require_file "${SSH_PUBLIC_KEY_PATH}"

set -a
# shellcheck disable=SC1091
source "${ROOT_DIR}/.env.aws"
set +a

CURRENT_PUBLIC_IP="${CURRENT_PUBLIC_IP:-$(curl -fsS https://checkip.amazonaws.com | tr -d '\n')}"
if [[ -z "${CURRENT_PUBLIC_IP}" ]]; then
   printf 'failed to resolve current public ip\n' >&2
   exit 1
fi
SSH_INGRESS_CIDR="${SSH_INGRESS_CIDR:-${CURRENT_PUBLIC_IP}/32}"

mkdir -p "${LOCAL_XDG_DATA_HOME}"
mkdir -p "${LOCAL_MOTHERSHIP_TIDESDB_PATH}"
printf 'RUN_NAME=%s\nRUN_DIR=%s\nAWS_REGION=%s\nAWS_INSTANCE_TYPE=%s\nMOTHERSHIP_BIN=%s\nSSH_PRIVATE_KEY_PATH=%s\nSSH_PUBLIC_KEY_PATH=%s\nLOCAL_STATE_DB=%s\nLOCAL_XDG_DATA_HOME=%s\nLOCAL_MOTHERSHIP_TIDESDB_PATH=%s\nSSH_INGRESS_CIDR=%s\n' \
   "${RUN_NAME}" \
   "${RUN_DIR}" \
   "${AWS_REGION}" \
   "${AWS_INSTANCE_TYPE}" \
   "${MOTHERSHIP_BIN}" \
   "${SSH_PRIVATE_KEY_PATH}" \
   "${SSH_PUBLIC_KEY_PATH}" \
   "${LOCAL_STATE_DB}" \
   "${LOCAL_XDG_DATA_HOME}" \
   "${LOCAL_MOTHERSHIP_TIDESDB_PATH}" \
   "${SSH_INGRESS_CIDR}" > "${RUN_DIR}/meta.env"

log "runner hostns ready"

export RUN_DIR RUN_NAME AWS_REGION AWS_INSTANCE_TYPE SSH_PUBLIC_KEY_PATH SSH_INGRESS_CIDR
python3 - <<'PY' > "${RUN_DIR}/launch.ids.out"
import boto3
import json
import os
import time
from datetime import datetime, timezone
from botocore.exceptions import ClientError

run_dir = os.environ["RUN_DIR"]
run_name = os.environ["RUN_NAME"]
region = os.environ["AWS_REGION"]
instance_type = os.environ["AWS_INSTANCE_TYPE"]
public_key_path = os.environ["SSH_PUBLIC_KEY_PATH"]
ssh_ingress_cidr = os.environ["SSH_INGRESS_CIDR"]

with open(public_key_path, "r", encoding="utf-8") as handle:
   public_key = handle.read().strip()

session = boto3.session.Session(
   aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
   aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
   region_name=region,
)
ec2 = session.client("ec2")

images = ec2.describe_images(
   Owners=["099720109477"],
   Filters=[
      {"Name": "name", "Values": ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]},
      {"Name": "architecture", "Values": ["x86_64"]},
      {"Name": "state", "Values": ["available"]},
   ],
)["Images"]
images.sort(key=lambda image: image["CreationDate"])
selected_image = None
for image in reversed(images):
   if image.get("FreeTierEligible", False):
      selected_image = image
      break
if selected_image is None:
   selected_image = images[-1]

subnets = ec2.describe_subnets(Filters=[{"Name": "default-for-az", "Values": ["true"]}])["Subnets"]
subnets.sort(key=lambda subnet: subnet["AvailabilityZone"])
subnet = subnets[0]
vpc_id = subnet["VpcId"]

security_group_name = f"prodigy-aws-runtime-ssh-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
create_group = ec2.create_security_group(
   GroupName=security_group_name,
   Description=f"Prodigy AWS runtime profile {run_name}",
   VpcId=vpc_id,
)
security_group_id = create_group["GroupId"]
ec2.authorize_security_group_ingress(
   GroupId=security_group_id,
   IpPermissions=[
      {
         "IpProtocol": "tcp",
         "FromPort": 22,
         "ToPort": 22,
         "IpRanges": [{"CidrIp": ssh_ingress_cidr, "Description": "Prodigy live runner"}],
      }
      ,
      {
         "IpProtocol": "-1",
         "UserIdGroupPairs": [{"GroupId": security_group_id, "Description": "Prodigy cluster internal"}],
      }
   ],
)

user_data = f"""#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - default
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - {public_key}
write_files:
  - path: /etc/ssh/sshd_config.d/99-prodigy-bootstrap.conf
    owner: root:root
    permissions: '0644'
    content: |
      PermitRootLogin prohibit-password
      PasswordAuthentication no
      PubkeyAuthentication yes
runcmd:
  - mkdir -p /root/.ssh
  - chmod 700 /root/.ssh
  - chmod 600 /root/.ssh/authorized_keys || true
  - systemctl restart sshd || systemctl restart ssh || service sshd restart || service ssh restart
"""

response = ec2.run_instances(
   ImageId=selected_image["ImageId"],
   InstanceType=instance_type,
   MinCount=3,
   MaxCount=3,
   UserData=user_data,
   NetworkInterfaces=[
      {
         "DeviceIndex": 0,
         "AssociatePublicIpAddress": True,
         "SubnetId": subnet["SubnetId"],
         "Groups": [security_group_id],
      }
   ],
   TagSpecifications=[
      {
         "ResourceType": "instance",
         "Tags": [
            {"Key": "Name", "Value": f"ntg-{run_name}"},
            {"Key": "app", "Value": "prodigy"},
            {"Key": "run", "Value": run_name},
         ],
      },
      {
         "ResourceType": "volume",
         "Tags": [
            {"Key": "Name", "Value": f"ntg-{run_name}"},
            {"Key": "app", "Value": "prodigy"},
            {"Key": "run", "Value": run_name},
         ],
      },
   ],
)

instance_ids = [instance["InstanceId"] for instance in response["Instances"]]
instances_by_id = {}
deadline = time.time() + 180
while time.time() < deadline:
   try:
      reservations = ec2.describe_instances(InstanceIds=instance_ids)["Reservations"]
   except ClientError as exc:
      error_code = exc.response.get("Error", {}).get("Code", "")
      if error_code == "InvalidInstanceID.NotFound":
         time.sleep(1)
         continue
      raise

   instances_by_id.clear()
   for reservation in reservations:
      for instance in reservation["Instances"]:
         instances_by_id[instance["InstanceId"]] = {
            "InstanceId": instance["InstanceId"],
            "PublicIpAddress": instance.get("PublicIpAddress", ""),
            "PrivateIpAddress": instance.get("PrivateIpAddress", ""),
            "SubnetId": instance.get("SubnetId", ""),
            "VpcId": instance.get("VpcId", ""),
            "ImageId": instance.get("ImageId", ""),
            "InstanceType": instance.get("InstanceType", ""),
            "AvailabilityZone": instance.get("Placement", {}).get("AvailabilityZone", ""),
            "State": instance.get("State", {}).get("Name", ""),
         }

   if len(instances_by_id) == len(instance_ids):
      launch_ready = True
      for instance_id in instance_ids:
         instance = instances_by_id[instance_id]
         if instance["State"] not in ("pending", "running"):
            raise RuntimeError(f"instance entered unexpected state {instance['State']}: {instance_id}")
         if not instance["PublicIpAddress"] or not instance["PrivateIpAddress"]:
            launch_ready = False
            break
      if launch_ready:
         break

   time.sleep(1)

if len(instances_by_id) != len(instance_ids):
   raise RuntimeError("timed out waiting for launched instance records")

instances = [instances_by_id[instance_id] for instance_id in instance_ids]

with open(os.path.join(run_dir, "launch.resources.json"), "w", encoding="utf-8") as handle:
   json.dump(
      {
         "image": {
            "ImageId": selected_image["ImageId"],
            "Name": selected_image.get("Name", ""),
            "CreationDate": selected_image.get("CreationDate", ""),
            "FreeTierEligible": selected_image.get("FreeTierEligible", False),
         },
         "securityGroup": {
            "GroupId": security_group_id,
            "GroupName": security_group_name,
            "IngressCIDR": ssh_ingress_cidr,
         },
         "subnet": {
            "SubnetId": subnet["SubnetId"],
            "VpcId": subnet["VpcId"],
            "AvailabilityZone": subnet["AvailabilityZone"],
            "CidrBlock": subnet["CidrBlock"],
         },
         "instances": instances,
      },
      handle,
      indent=2,
   )

with open(os.path.join(run_dir, "instances.tsv"), "w", encoding="utf-8") as handle:
   for instance in instances:
      handle.write(
         f"{instance['InstanceId']}\t{instance['PublicIpAddress']}\t{instance['PrivateIpAddress']}\n"
      )

print(security_group_id)
print(security_group_name)
for instance in instances:
   print(instance["InstanceId"])
PY

SECURITY_GROUP_ID="$(sed -n '1p' "${RUN_DIR}/launch.ids.out")"
SECURITY_GROUP_NAME="$(sed -n '2p' "${RUN_DIR}/launch.ids.out")"
mapfile -t INSTANCE_IDS < <(sed -n '3,$p' "${RUN_DIR}/launch.ids.out")
printf 'SECURITY_GROUP_ID=%s\nSECURITY_GROUP_NAME=%s\n' "${SECURITY_GROUP_ID}" "${SECURITY_GROUP_NAME}" >> "${RUN_DIR}/meta.env"
for instance_id in "${INSTANCE_IDS[@]}"; do
   printf 'INSTANCE_ID=%s\n' "${instance_id}" >> "${RUN_DIR}/meta.env"
done
log "aws launch submitted instances=${#INSTANCE_IDS[@]} securityGroup=${SECURITY_GROUP_ID}"

wait_for_ssh()
{
   local instance_id="$1"
   local public_ip="$2"
   local private_ip="$3"
   local deadline=$((SECONDS + SSH_READY_TIMEOUT_SECONDS))
   while (( SECONDS < deadline )); do
      if ssh -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null \
         -o BatchMode=yes \
         -o ConnectTimeout=5 \
         -i "${SSH_PRIVATE_KEY_PATH}" \
         "root@${public_ip}" true >/dev/null 2>&1; then
         local ts
         ts="$(python3 -c 'import time; print(f"{time.time():.6f}")')"
         printf '%s\t%s\t%s\t%s\n' "${ts}" "${instance_id}" "${public_ip}" "${private_ip}" > "${RUN_DIR}/ssh-ready.${instance_id}.tsv"
         printf '%s ssh-ready instance=%s public=%s private=%s\n' "${ts}" "${instance_id}" "${public_ip}" "${private_ip}" | tee -a "${RUN_DIR}/ssh-ready.log"
         return 0
      fi
      sleep 1
   done
   printf 'timed out waiting for ssh on %s (%s)\n' "${instance_id}" "${public_ip}" >&2
   return 1
}

while IFS=$'\t' read -r instance_id public_ip private_ip; do
   wait_for_ssh "${instance_id}" "${public_ip}" "${private_ip}" &
   SSH_WAIT_PIDS+=("$!")
done < "${RUN_DIR}/instances.tsv"
for pid in "${SSH_WAIT_PIDS[@]}"; do
   wait "${pid}"
done

cat "${RUN_DIR}"/ssh-ready.*.tsv | sort -n > "${RUN_DIR}/ssh-ready.all.tsv"
ALL_SSH_READY_AT="$(tail -n 1 "${RUN_DIR}/ssh-ready.all.tsv" | cut -f1)"
printf 'ALL_SSH_READY_AT=%s\n' "${ALL_SSH_READY_AT}" >> "${RUN_DIR}/meta.env"
log "all ssh ready timestamp=${ALL_SSH_READY_AT}"

export ALL_SSH_READY_AT AWS_PROVIDER_SCOPE SSH_PRIVATE_KEY_PATH
python3 - <<'PY'
import json
import os

run_dir = os.environ["RUN_DIR"]
run_name = os.environ["RUN_NAME"]
region = os.environ["AWS_REGION"]
instance_type = os.environ["AWS_INSTANCE_TYPE"]
provider_scope = os.environ["AWS_PROVIDER_SCOPE"]
ssh_private_key_path = os.environ["SSH_PRIVATE_KEY_PATH"]
material = f"{os.environ['AWS_ACCESS_KEY_ID']}:{os.environ['AWS_SECRET_ACCESS_KEY']}"

with open(os.path.join(run_dir, "launch.resources.json"), "r", encoding="utf-8") as handle:
   launch = json.load(handle)

subnet_cidr = launch["subnet"]["CidrBlock"]
private_gateway = subnet_cidr.split("/")[0]
private_gateway = private_gateway.rsplit(".", 1)[0] + ".1"

machines = []
for index, instance in enumerate(launch["instances"]):
   ssh_address = instance["PublicIpAddress"]
   if index > 0 and instance["PrivateIpAddress"]:
      ssh_address = instance["PrivateIpAddress"]
   machines.append(
      {
         "source": "adopted",
         "backing": "cloud",
         "kind": "vm",
         "lifetime": "ondemand",
         "isBrain": True,
         "cloud": {
            "schema": instance_type,
            "providerMachineType": instance_type,
            "cloudID": instance["InstanceId"],
         },
         "ssh": {
            "address": ssh_address,
            "port": 22,
            "user": "root",
            "privateKeyPath": ssh_private_key_path,
         },
         "addresses": {
            "private": [
               {
                  "address": instance["PrivateIpAddress"],
                  "cidr": int(subnet_cidr.split("/")[1]),
                  "gateway": private_gateway,
               }
            ],
            "public": [
               {
                  "address": instance["PublicIpAddress"],
                  "cidr": 32,
               }
            ],
         },
         "ownership": {
            "mode": "wholeMachine",
         },
      }
   )

payload = {
   "name": run_name,
   "deploymentMode": "remote",
   "provider": "aws",
   "providerScope": provider_scope,
   "providerCredentialName": f"{run_name}-credential",
   "providerCredentialOverride": {
      "name": f"{run_name}-credential",
      "provider": "aws",
      "mode": "staticMaterial",
      "material": material,
      "scope": provider_scope,
      "allowPropagateToProdigy": False,
   },
   "controls": [
      {
         "kind": "unixSocket",
         "path": "/run/prodigy/control.sock",
      }
   ],
   "architecture": "x86_64",
   "nBrains": 3,
   "machineSchemas": [
      {
         "schema": instance_type,
         "kind": "vm",
         "lifetime": "ondemand",
         "vmImageURI": launch["image"]["ImageId"],
         "providerMachineType": instance_type,
      }
   ],
   "machines": machines,
   "bootstrapSshUser": "root",
   "bootstrapSshPrivateKeyPath": ssh_private_key_path,
   "remoteProdigyPath": "/root/prodigy",
   "desiredEnvironment": "aws",
}

with open(os.path.join(run_dir, "createCluster.json"), "w", encoding="utf-8") as handle:
   json.dump(payload, handle, indent=2)
PY

CREATE_CLUSTER_PAYLOAD="$(cat "${RUN_DIR}/createCluster.json")"
run_timed "${RUN_DIR}/createCluster.timed.out" run_local "${MOTHERSHIP_BIN}" createCluster "${CREATE_CLUSTER_PAYLOAD}" > /dev/null
CLUSTER_CREATED=1
run_local "${MOTHERSHIP_BIN}" printClusters > "${RUN_DIR}/printClusters.out" 2>&1 || true

deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))
attempt=0
while (( SECONDS < deadline )); do
   attempt="$((attempt + 1))"
   {
      printf -- '--- clusterReport attempt=%u cluster=%s ---\n' "${attempt}" "${RUN_NAME}"
      run_local "${MOTHERSHIP_BIN}" clusterReport "${RUN_NAME}"
   } 2>&1 | stdbuf -oL -eL perl -MTime::HiRes=time -ne 'printf("%.6f %s", time, $_)' | tee -a "${RUN_DIR}/health.timed.out" >/dev/null

   run_local "${MOTHERSHIP_BIN}" clusterReport "${RUN_NAME}" > "${RUN_DIR}/clusterReport.last.out" 2>&1 || true
   if grep -q '^topologyMachines: 3$' "${RUN_DIR}/clusterReport.last.out" \
      && [[ "$(grep -c $'^\tMachine: state=healthy role=brain' "${RUN_DIR}/clusterReport.last.out")" -eq 3 ]]; then
      cp "${RUN_DIR}/clusterReport.last.out" "${RUN_DIR}/clusterReport.final.out"
      log "cluster healthy attempt=${attempt}"
      break
   fi
   sleep 1
done

if [[ ! -f "${RUN_DIR}/clusterReport.final.out" ]]; then
   printf 'cluster did not reach healthy state before timeout\n' >&2
   exit 1
fi

collect_journals
log "baseline profile complete runDir=${RUN_DIR}"
