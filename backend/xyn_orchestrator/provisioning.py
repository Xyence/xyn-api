import datetime as dt
import os
import time
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .models import Environment, ProvisionedInstance


DEFAULT_ALLOWED_CIDR = os.environ.get("XYENCE_PROVISION_ALLOW_CIDR", "0.0.0.0/0")
DEFAULT_SG_NAME = os.environ.get("XYENCE_PROVISION_SG_NAME", "xyn-seed-sg")
DEFAULT_AMI = os.environ.get("XYENCE_PROVISION_AMI", "").strip()
DEFAULT_INSTANCE_TYPE = os.environ.get("XYENCE_PROVISION_INSTANCE_TYPE", "t3.small")
DEFAULT_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
DEFAULT_REPO_URL = os.environ.get("XYNSEED_REPO_URL", "https://github.com/Xyence/xyn-seed.git")
DEFAULT_INSTANCE_PROFILE_ARN = os.environ.get("XYENCE_PROVISION_INSTANCE_PROFILE_ARN", "").strip()


def _ec2(region: str):
    return boto3.client("ec2", region_name=region)


def _ssm(region: str):
    return boto3.client("ssm", region_name=region)


def _build_user_data(repo_url: str) -> str:
    script = f"""#!/bin/bash
set -euo pipefail

LOG_FILE=/var/log/xyn-bootstrap.log
exec > >(tee -a $LOG_FILE) 2>&1

mkdir -p /var/lib/xyn

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y docker.io git curl
  systemctl enable docker
  systemctl start docker
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y docker git amazon-ssm-agent
  if ! command -v curl >/dev/null 2>&1; then
    dnf install -y curl --allowerasing || dnf install -y curl-minimal
  fi
  systemctl enable docker
  systemctl start docker
elif command -v yum >/dev/null 2>&1; then
  yum install -y docker git amazon-ssm-agent
  if ! command -v curl >/dev/null 2>&1; then
    yum install -y curl
  fi
  systemctl enable docker
  systemctl start docker
fi

# Ensure docker compose plugin is available for `docker compose` usage.
if ! docker compose version >/dev/null 2>&1; then
  ARCH=$(uname -m)
  if [ "$ARCH" = "x86_64" ]; then
    ARCH="x86_64"
  elif [ "$ARCH" = "aarch64" ]; then
    ARCH="aarch64"
  fi
  mkdir -p /usr/local/libexec/docker/cli-plugins
  curl -fsSL "https://github.com/docker/compose/releases/download/v2.27.0/docker-compose-linux-$ARCH" \
    -o /usr/local/libexec/docker/cli-plugins/docker-compose
  chmod +x /usr/local/libexec/docker/cli-plugins/docker-compose
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl enable amazon-ssm-agent || true
  systemctl start amazon-ssm-agent || true
fi

if [ ! -d /opt/xyn-seed ]; then
  git clone {repo_url} /opt/xyn-seed
fi
cd /opt/xyn-seed

./xynctl start --non-interactive --skip-ai-keys

for i in $(seq 1 90); do
  if curl -fsS http://localhost:8001/api/v1/health >/dev/null 2>&1; then
    touch /var/lib/xyn/READY
    exit 0
  fi
  sleep 10
done

exit 1
"""
    return script


def _ensure_security_group(region: str, vpc_id: Optional[str]) -> str:
    client = _ec2(region)
    filters = [{"Name": "group-name", "Values": [DEFAULT_SG_NAME]}]
    if vpc_id:
        filters.append({"Name": "vpc-id", "Values": [vpc_id]})
    resp = client.describe_security_groups(Filters=filters)
    groups = resp.get("SecurityGroups", [])
    if groups:
        return groups[0]["GroupId"]

    create_params = {"GroupName": DEFAULT_SG_NAME, "Description": "Xyn Seed SG"}
    if vpc_id:
        create_params["VpcId"] = vpc_id
    sg = client.create_security_group(**create_params)
    sg_id = sg["GroupId"]

    ingress_rules = [
        {"IpProtocol": "tcp", "FromPort": 8001, "ToPort": 8001, "IpRanges": [{"CidrIp": DEFAULT_ALLOWED_CIDR}]},
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": DEFAULT_ALLOWED_CIDR}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": DEFAULT_ALLOWED_CIDR}]},
    ]
    try:
        client.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ingress_rules)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidPermission.Duplicate":
            raise
    return sg_id


def provision_instance(payload: Dict[str, Any], user) -> ProvisionedInstance:
    environment = None
    if payload.get("environment_id"):
        environment = Environment.objects.filter(id=payload["environment_id"]).first()
    region = payload.get("region") or (environment.aws_region if environment else None) or DEFAULT_REGION
    if not region:
        raise ValueError("AWS region required (AWS_REGION or payload.region)")
    ami_id = payload.get("ami_id") or DEFAULT_AMI
    if not ami_id:
        raise ValueError("AMI ID required (XYENCE_PROVISION_AMI or payload.ami_id)")
    instance_type = payload.get("instance_type") or DEFAULT_INSTANCE_TYPE
    name = payload.get("name") or f"xyn-seed-{dt.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    subnet_id = payload.get("subnet_id")
    vpc_id = payload.get("vpc_id")
    key_name = payload.get("key_name")
    repo_url = payload.get("repo_url") or DEFAULT_REPO_URL
    instance_profile_arn = payload.get("iam_instance_profile_arn") or DEFAULT_INSTANCE_PROFILE_ARN
    instance_profile_name = payload.get("iam_instance_profile_name")

    sg_id = _ensure_security_group(region, vpc_id)
    user_data = _build_user_data(repo_url)

    instance = ProvisionedInstance.objects.create(
        name=name,
        environment=environment,
        aws_region=region,
        instance_type=instance_type,
        ami_id=ami_id,
        runtime_substrate="ec2",
        security_group_id=sg_id,
        subnet_id=subnet_id or "",
        vpc_id=vpc_id or "",
        status="provisioning",
        created_by=user,
        updated_by=user,
        tags_json={"Name": name, "xyn-instance": name},
    )

    try:
        client = _ec2(region)
        params: Dict[str, Any] = {
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "MinCount": 1,
            "MaxCount": 1,
            "SecurityGroupIds": [sg_id],
            "UserData": user_data,
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": name},
                        {"Key": "xyn-instance", "Value": name},
                    ],
                }
            ],
        }
        if subnet_id:
            params["SubnetId"] = subnet_id
        if key_name:
            params["KeyName"] = key_name
        if instance_profile_arn:
            params["IamInstanceProfile"] = {"Arn": instance_profile_arn}
        elif instance_profile_name:
            params["IamInstanceProfile"] = {"Name": instance_profile_name}

        resp = client.run_instances(**params)
        instance_id = resp.get("Instances", [{}])[0].get("InstanceId")
        if not instance_id:
            raise ValueError("EC2 did not return an InstanceId.")
        instance.instance_id = instance_id
        instance.save(update_fields=["instance_id", "updated_at"])
    except (ClientError, BotoCoreError, ValueError) as exc:
        instance.status = "error"
        instance.last_error = str(exc)
        instance.save(update_fields=["status", "last_error", "updated_at"])
        raise

    return instance


def retry_provision_instance(instance: ProvisionedInstance, user) -> ProvisionedInstance:
    region = instance.aws_region or DEFAULT_REGION
    if not region:
        raise ValueError("AWS region required (AWS_REGION or instance.aws_region)")
    ami_id = instance.ami_id or DEFAULT_AMI
    if not ami_id:
        raise ValueError("AMI ID required (XYENCE_PROVISION_AMI or instance.ami_id)")
    instance_type = instance.instance_type or DEFAULT_INSTANCE_TYPE
    name = instance.name or f"xyn-seed-{dt.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    subnet_id = instance.subnet_id or ""
    vpc_id = instance.vpc_id or ""
    key_name = None
    repo_url = DEFAULT_REPO_URL
    instance_profile_arn = DEFAULT_INSTANCE_PROFILE_ARN
    instance_profile_name = None

    sg_id = instance.security_group_id or _ensure_security_group(region, vpc_id or None)
    user_data = _build_user_data(repo_url)

    instance.aws_region = region
    instance.ami_id = ami_id
    instance.instance_type = instance_type
    instance.security_group_id = sg_id
    instance.status = "provisioning"
    instance.last_error = ""
    instance.updated_by = user
    instance.save(
        update_fields=[
            "aws_region",
            "ami_id",
            "instance_type",
            "security_group_id",
            "status",
            "last_error",
            "updated_by",
            "updated_at",
        ]
    )

    try:
        client = _ec2(region)
        params: Dict[str, Any] = {
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "MinCount": 1,
            "MaxCount": 1,
            "SecurityGroupIds": [sg_id],
            "UserData": user_data,
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": name},
                        {"Key": "xyn-instance", "Value": name},
                    ],
                }
            ],
        }
        if subnet_id:
            params["SubnetId"] = subnet_id
        if key_name:
            params["KeyName"] = key_name
        if instance_profile_arn:
            params["IamInstanceProfile"] = {"Arn": instance_profile_arn}
        elif instance_profile_name:
            params["IamInstanceProfile"] = {"Name": instance_profile_name}

        resp = client.run_instances(**params)
        instance_id = resp.get("Instances", [{}])[0].get("InstanceId")
        if not instance_id:
            raise ValueError("EC2 did not return an InstanceId.")
        instance.instance_id = instance_id
        instance.save(update_fields=["instance_id", "updated_at"])
    except (ClientError, BotoCoreError, ValueError) as exc:
        instance.status = "error"
        instance.last_error = str(exc)
        instance.save(update_fields=["status", "last_error", "updated_at"])
        raise

    return instance


def refresh_instance(instance: ProvisionedInstance) -> ProvisionedInstance:
    if not instance.instance_id:
        instance.status = "error"
        instance.last_error = "InstanceId missing; instance was not provisioned."
        instance.save(update_fields=["status", "last_error", "updated_at"])
        return instance
    client = _ec2(instance.aws_region)
    try:
        resp = client.describe_instances(InstanceIds=[instance.instance_id])
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code")
        if error_code == "InvalidInstanceID.NotFound":
            instance.status = "terminated"
            instance.last_error = ""
            instance.save(update_fields=["status", "last_error", "updated_at"])
            return instance
        instance.last_error = str(exc)
        instance.save(update_fields=["last_error", "updated_at"])
        return instance
    except BotoCoreError as exc:
        instance.last_error = str(exc)
        instance.save(update_fields=["last_error", "updated_at"])
        return instance
    reservations = resp.get("Reservations", [])
    if not reservations or not reservations[0].get("Instances"):
        instance.status = "terminated"
        instance.save(update_fields=["status", "updated_at"])
        return instance
    info = reservations[0]["Instances"][0]
    state = info.get("State", {}).get("Name", "unknown")
    instance.public_ip = info.get("PublicIpAddress")
    instance.private_ip = info.get("PrivateIpAddress")
    instance.status = "running" if state == "running" else state

    try:
        ssm = _ssm(instance.aws_region)
        inv = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance.instance_id]}]
        )
        if inv.get("InstanceInformationList"):
            instance.ssm_status = inv["InstanceInformationList"][0].get("PingStatus", "unknown")
    except (ClientError, BotoCoreError) as exc:
        instance.last_error = str(exc)

    # READY marker check via SSM
    if instance.ssm_status == "Online":
        try:
            cmd = _ssm(instance.aws_region).send_command(
                InstanceIds=[instance.instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": ["test -f /var/lib/xyn/READY"]},
            )
            command_id = cmd["Command"]["CommandId"]
            for _ in range(6):
                try:
                    out = _ssm(instance.aws_region).get_command_invocation(
                        CommandId=command_id,
                        InstanceId=instance.instance_id,
                    )
                except ClientError:
                    time.sleep(1)
                    continue
                if out.get("Status") == "Success":
                    instance.status = "ready"
                break
        except (ClientError, BotoCoreError):
            pass

    update_fields = ["public_ip", "private_ip", "status", "ssm_status", "last_error", "updated_at"]
    if instance.instance_id and instance.instance_id.startswith("i-"):
        if not instance.runtime_substrate or instance.runtime_substrate == "local":
            instance.runtime_substrate = "ec2"
            update_fields.append("runtime_substrate")
    instance.save(update_fields=update_fields)
    return instance


def destroy_instance(instance: ProvisionedInstance) -> ProvisionedInstance:
    client = _ec2(instance.aws_region)
    instance.status = "terminating"
    instance.save(update_fields=["status", "updated_at"])
    try:
        client.terminate_instances(InstanceIds=[instance.instance_id])
    except (ClientError, BotoCoreError) as exc:
        instance.status = "error"
        instance.last_error = str(exc)
        instance.save(update_fields=["status", "last_error", "updated_at"])
        return instance
    return instance


def fetch_bootstrap_log(instance: ProvisionedInstance, tail: int = 200) -> Dict[str, Any]:
    ssm = _ssm(instance.aws_region)
    cmd = ssm.send_command(
        InstanceIds=[instance.instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [f"tail -n {tail} /var/log/xyn-bootstrap.log || true"]},
    )
    command_id = cmd["Command"]["CommandId"]
    out = None
    last_error: Optional[Exception] = None
    for _ in range(10):
        try:
            out = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance.instance_id)
            break
        except ClientError as exc:
            last_error = exc
            time.sleep(1)
    if out is None:
        raise last_error or RuntimeError("SSM command invocation not found yet")
    return {
        "status": out.get("Status"),
        "stdout": out.get("StandardOutputContent", ""),
        "stderr": out.get("StandardErrorContent", ""),
    }
