AWS Cheap 3-Brain Runbook

Scope

- Bring up a fresh remote `3`-machine `3`-brain Prodigy cluster on AWS.
- Keep cost pinned to the repo-approved low-cost x86 shapes only.
- Keep the created AWS brains on EC2 instance-profile / IMDS auth only.

Cheapest Allowed Shape

- Preferred: `t3.micro`
- Allowed alternate: `t2.micro`
- Do not use any larger AWS instance type unless explicitly approved.

Current Auth Contract

- The created AWS brains stay on EC2 instance-profile / IMDS auth.
- A local workstation may run `mothership createCluster` directly with provider credential mode `awsCli`, backed by a short-lived local AWS CLI v2 / SSO session.
- An EC2 controller host may run the same flow with provider credential mode `awsImds`.
- Do not inject long-lived static AWS secrets into Prodigy runtime state.

Validated Cheap Path

- Validated on `2026-03-26`:
  - local Mothership on this workstation
  - provider credential mode `awsCli`
  - remote EC2 instance profile `prodigy-controller-profile`
  - `t3.micro`
  - Ubuntu 24.04 x86_64 AMI `ami-04eaa218f1349d88b`
  - healthy `3`-brain run artifact:
    - [/root/nametag/.mothership-live-aws-3brain-matrix-20260326-053725/createCluster.timed.out](/root/nametag/.mothership-live-aws-3brain-matrix-20260326-053725/createCluster.timed.out)

Current Required IAM/Profile State

- Known controller instance profile:
  - `prodigy-controller-profile`
- Known controller role:
  - `prodigy-controller-role`
- The controller/seed role must allow:
  - `ec2:RunInstances`
  - `ec2:TerminateInstances`
  - `ec2:CreateLaunchTemplate`
  - `ec2:CreateLaunchTemplateVersion`
  - `ec2:DeleteLaunchTemplate`
  - `ec2:Describe*`
  - `iam:PassRole` for the instance profile role attached to created Prodigy VMs
- A read-only EC2 role is not sufficient.

Known Working Machine Image

- Current Ubuntu 24.04 x86_64 AMI in `us-east-1` as of `2026-03-24`:
  - `ami-04eaa218f1349d88b`
- Re-resolve before a new wave if you want the latest:

```bash
python - <<'PY'
import boto3, json
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
PY
```

Cluster JSON Shape For Local Mothership

Create a short-lived local bootstrap credential first:

```json
{
  "name": "aws-3brain-run-credential",
  "provider": "aws",
  "mode": "awsCli",
  "scope": "062397142164/us-east-1",
  "allowPropagateToProdigy": false
}
```

Then create the cluster with that named credential:

```json
{
  "name": "aws-3brain-run",
  "deploymentMode": "remote",
  "provider": "aws",
  "providerScope": "062397142164/us-east-1",
  "providerCredentialName": "aws-3brain-run-credential",
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
      "vmImageURI": "ami-04eaa218f1349d88b",
      "providerMachineType": "t3.micro",
      "budget": 3
    }
  ],
  "bootstrapSshUser": "root",
  "bootstrapSshPrivateKeyPath": "/root/.ssh/prodigy_aws_test_ed25519",
  "remoteProdigyPath": "/root/prodigy",
  "desiredEnvironment": "aws"
}
```

How To Run From A Local Workstation

1. Refresh local AWS CLI auth with `aws sso login`.
2. Create the bootstrap provider credential with mode `awsCli`.
3. Run `mothership createCluster` locally with the cluster JSON above.
4. Poll `clusterReport` until `topologyMachines: 3` and all `3` brains report healthy.
5. Run `removeCluster`.
6. Run `removeProviderCredential`.
7. Verify no tagged test instances or volumes remain.

Alternate Controller-Host Path

- If you deliberately run `mothership createCluster` on an EC2 controller host that already has `prodigy-controller-profile`, switch the bootstrap provider credential mode to `awsImds`.

Timing Artifacts To Capture

- `createCluster.timed.out`
- `health.timed.out`
- `clusterReport.final.out`
- `seed.journal`
- follower journals if the run stalls

Cleanup Checks

```bash
python - <<'PY'
import boto3, json
session = boto3.Session(region_name='us-east-1')
ec2 = session.client('ec2')
resp = ec2.describe_instances(Filters=[{'Name': 'tag:app', 'Values': ['prodigy', 'prodigy-controller']}])
instances = []
for r in resp.get('Reservations', []):
   for i in r.get('Instances', []):
      if i['State']['Name'] != 'terminated':
         instances.append({'InstanceId': i['InstanceId'], 'State': i['State']['Name']})
print(json.dumps(instances, indent=2))
PY
```

Cost Notes

- Even on `t2.micro` or `t3.micro`, public IPv4 is billed separately on AWS.
- Keep runs short, tear down immediately, and verify cleanup every time.
- Do not leave controller hosts running after the measurement wave.

Current Caveats

- The managed AWS path depends on the controller/seed instance profile having real EC2 create/terminate and `iam:PassRole` permissions.
- If the controller role still simulates as implicit deny for those actions, fix IAM first and do not launch.
