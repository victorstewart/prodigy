# AWS cheap 3-brain cluster runbook

This runbook creates a cheap 3-machine / 3-brain Prodigy cluster on AWS, polls it, and removes it.

Validated cheap shape: `t3.micro`
Alternate shape: `t2.micro`
Validated auth mode: local AWS CLI v2 / IAM Identity Center, then EC2 instance-profile / IMDS for created AWS brains

Keep early test runs short. Public IPv4 addresses, disks, launch templates, and stopped instances can continue to bill depending on provider behavior.

## Requirements

- Built `mothership` and `prodigy` from this repository.
- Local AWS CLI v2.
- Authenticated AWS profile.
- Bootstrap SSH private key.
- Ubuntu 24.04 AMI ID for the target region.
- TCP Fast Open enabled on target hosts.

## Required AWS permissions

The controller identity needs enough EC2 and IAM access to create bootstrap capacity, launch templates, and pass the runtime role. The validated runbook uses a controller role/profile named:

```text
prodigy-controller-role
prodigy-controller-profile
```

Minimum practical action set for the validated runbook:

```text
ec2:Describe*
ec2:RunInstances
ec2:TerminateInstances
ec2:CreateLaunchTemplate
ec2:CreateLaunchTemplateVersion
ec2:ModifyLaunchTemplate
ec2:DeleteLaunchTemplate
ec2:CreateSecurityGroup
ec2:AuthorizeSecurityGroupIngress
iam:GetInstanceProfile
iam:PassRole
```

A read-only EC2 role is not sufficient. `iam:GetInstanceProfile` lets Mothership reject a missing runtime profile before it creates resources. `iam:PassRole` is required because every created AWS brain must boot with an EC2 instance profile; local AWS CLI credentials are only the bootstrap identity, not the long-lived runtime identity.

Before cluster creation is admitted, Mothership preflights the configured AWS credential by resolving the instance profile, describing the target EC2 environment, and issuing EC2 dry-run checks for the create/launch/terminate/template/security-group actions above. Failure here rejects `createCluster` before the cluster record is persisted or any VM is created. After prerequisite discovery succeeds, failed dry-run actions are reported together in one error.

## Authenticate locally

```bash
export MOTHERSHIP="${MOTHERSHIP:-./mothership}"
export RUN_ID="${RUN_ID:-$(date -u +%Y%m%d-%H%M%S)}"
export AWS_PROFILE="${AWS_PROFILE:-prodigy}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_ACCOUNT_ID="REPLACE_AWS_ACCOUNT_ID"
export AWS_AMI_ID="REPLACE_UBUNTU_24_04_AMI_ID"
export BOOTSTRAP_SSH_KEY="REPLACE_PATH_TO_BOOTSTRAP_PRIVATE_KEY"

aws configure sso --profile "${AWS_PROFILE}"
aws sso login --profile "${AWS_PROFILE}"
aws sts get-caller-identity --profile "${AWS_PROFILE}"
```

To re-resolve the Ubuntu 24.04 AMI used by the runbook:

```bash
python - <<'PY_AWS_AMI'
import boto3
session = boto3.Session(region_name='us-east-1')
ec2 = session.client('ec2')
images = ec2.describe_images(
    Owners=['099720109477'],
    Filters=[
        {'Name': 'name', 'Values': ['ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*']},
        {'Name': 'architecture', 'Values': ['x86_64']},
        {'Name': 'state', 'Values': ['available']},
    ],
)['Images']
images.sort(key=lambda x: x['CreationDate'])
print(images[-1]['ImageId'])
PY_AWS_AMI
```

## Create provider credential

```bash
cat > aws.credential.json <<JSON
{
  "name": "aws-3brain-${RUN_ID}-credential",
  "provider": "aws",
  "mode": "awsCli",
  "scope": "${AWS_ACCOUNT_ID}/${AWS_REGION}",
  "metadata": {
    "profile": "${AWS_PROFILE}"
  },
  "allowPropagateToProdigy": false
}
JSON

"${MOTHERSHIP}" createProviderCredential "$(cat aws.credential.json)"
```

## Create cluster

```bash
cat > aws.cluster.json <<JSON
{
  "name": "aws-3brain-${RUN_ID}",
  "deploymentMode": "remote",
  "provider": "aws",
  "providerScope": "${AWS_ACCOUNT_ID}/${AWS_REGION}",
  "providerCredentialName": "aws-3brain-${RUN_ID}-credential",
  "aws": {
    "instanceProfileName": "prodigy-controller-profile"
  },
  "controls": [
    {
      "kind": "unixSocket",
      "path": "/run/prodigy/control.sock"
    }
  ],
  "architecture": "x86_64",
  "nBrains": 3,
  "machineSchemas": [
    {
      "schema": "t3.micro",
      "kind": "vm",
      "lifetime": "ondemand",
      "vmImageURI": "${AWS_AMI_ID}",
      "providerMachineType": "t3.micro",
      "budget": 3
    }
  ],
  "bootstrapSshUser": "root",
  "bootstrapSshPrivateKeyPath": "${BOOTSTRAP_SSH_KEY}",
  "remoteProdigyPath": "/root/prodigy",
  "desiredEnvironment": "aws"
}
JSON

time "${MOTHERSHIP}" createCluster "$(cat aws.cluster.json)"
"${MOTHERSHIP}" clusterReport "aws-3brain-${RUN_ID}"
```

## Remove cluster

```bash
time "${MOTHERSHIP}" removeCluster "aws-3brain-${RUN_ID}"
"${MOTHERSHIP}" removeProviderCredential "aws-3brain-${RUN_ID}-credential"
```

## Cleanup verification

Check for tagged residual instances and volumes after removal:

```bash
aws ec2 describe-instances \
  --profile "${AWS_PROFILE}" \
  --region "${AWS_REGION}" \
  --filters "Name=tag:prodigyCluster,Values=aws-3brain-${RUN_ID}" \
  --output json

aws ec2 describe-volumes \
  --profile "${AWS_PROFILE}" \
  --region "${AWS_REGION}" \
  --filters "Name=tag:prodigyCluster,Values=aws-3brain-${RUN_ID}" \
  --output json
```
