import json
import time
from typing import Any, Dict, List, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

from .models import ProvisionedInstance
from .provisioning import (
    provision_instance,
    retry_provision_instance,
    refresh_instance,
    destroy_instance,
    fetch_bootstrap_log,
)
from .blueprints import _require_staff


def _instance_payload(instance: ProvisionedInstance) -> dict:
    return {
        "id": str(instance.id),
        "name": instance.name,
        "environment_id": str(instance.environment_id) if instance.environment_id else None,
        "aws_region": instance.aws_region,
        "instance_id": instance.instance_id,
        "instance_type": instance.instance_type,
        "ami_id": instance.ami_id,
        "security_group_id": instance.security_group_id,
        "subnet_id": instance.subnet_id,
        "vpc_id": instance.vpc_id,
        "public_ip": instance.public_ip,
        "private_ip": instance.private_ip,
        "ssm_status": instance.ssm_status,
        "status": instance.status,
        "last_error": instance.last_error,
        "desired_release_id": str(instance.desired_release_id) if instance.desired_release_id else None,
        "observed_release_id": str(instance.observed_release_id) if instance.observed_release_id else None,
        "observed_at": instance.observed_at,
        "last_deploy_run_id": str(instance.last_deploy_run_id) if instance.last_deploy_run_id else None,
        "health_status": instance.health_status,
        "tags": instance.tags_json or {},
        "created_at": instance.created_at,
        "updated_at": instance.updated_at,
    }


@csrf_exempt
@login_required
def list_instances(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
        try:
            instance = provision_instance(payload, request.user)
        except Exception as exc:
            return JsonResponse({"error": str(exc)}, status=400)
        return JsonResponse(_instance_payload(instance), status=201)

    instances = ProvisionedInstance.objects.all().order_by("-created_at")
    if env_id := request.GET.get("environment_id"):
        instances = instances.filter(environment_id=env_id)
    status = request.GET.get("status")
    if status and status != "all":
        instances = instances.filter(status=status)
    elif not status:
        instances = instances.exclude(status__in=["terminated", "error"])
    data = [_instance_payload(inst) for inst in instances]
    return JsonResponse({"instances": data})


@login_required
def get_instance(request: HttpRequest, instance_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    instance = get_object_or_404(ProvisionedInstance, id=instance_id)
    if request.method == "GET" and request.GET.get("refresh") == "true":
        instance = refresh_instance(instance)
    return JsonResponse(_instance_payload(instance))


@csrf_exempt
@login_required
def destroy_instance_view(request: HttpRequest, instance_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    instance = get_object_or_404(ProvisionedInstance, id=instance_id)
    instance = destroy_instance(instance)
    return JsonResponse(_instance_payload(instance))


@csrf_exempt
@login_required
def retry_instance_view(request: HttpRequest, instance_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    instance = get_object_or_404(ProvisionedInstance, id=instance_id)
    try:
        instance = retry_provision_instance(instance, request.user)
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return JsonResponse(_instance_payload(instance))


@login_required
def bootstrap_log_view(request: HttpRequest, instance_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    instance = get_object_or_404(ProvisionedInstance, id=instance_id)
    tail = int(request.GET.get("tail", "200"))
    try:
        log = fetch_bootstrap_log(instance, tail=tail)
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return JsonResponse({"instance_id": str(instance.id), **log})


def _run_ssm_commands(instance: ProvisionedInstance, commands: List[str]) -> Dict[str, Any]:
    if not instance.instance_id:
        raise RuntimeError("Instance has no AWS instance_id")
    if not instance.aws_region:
        raise RuntimeError("Instance has no aws_region")
    ssm = boto3.client("ssm", region_name=instance.aws_region)
    try:
        cmd = ssm.send_command(
            InstanceIds=[instance.instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": commands},
            TimeoutSeconds=600,
        )
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"SSM send_command failed: {exc}") from exc
    command_id = cmd["Command"]["CommandId"]
    last_error = None
    for _ in range(40):
        time.sleep(2)
        try:
            out = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance.instance_id)
        except (BotoCoreError, ClientError) as exc:
            last_error = exc
            continue
        status = out.get("Status")
        if status in {"Success", "Failed", "Cancelled", "TimedOut"}:
            return {
                "ssm_command_id": command_id,
                "status": status,
                "stdout": out.get("StandardOutputContent", ""),
                "stderr": out.get("StandardErrorContent", ""),
            }
    raise RuntimeError(f"SSM command invocation not found yet: {last_error}")


@login_required
def instance_containers_view(request: HttpRequest, instance_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    instance = get_object_or_404(ProvisionedInstance, id=instance_id)
    try:
        result = _run_ssm_commands(
            instance,
            [
                "command -v docker >/dev/null 2>&1 || { echo 'missing_docker'; exit 10; }",
                "docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}'",
            ],
        )
        status = result.get("status")
        if status != "Success":
            return JsonResponse(
                {
                    "instance_id": str(instance.id),
                    "status": status,
                    "ssm_command_id": result.get("ssm_command_id"),
                    "error": result.get("stderr") or result.get("stdout") or "SSM failed",
                    "containers": [],
                },
                status=500,
            )
        containers = []
        for line in (result.get("stdout") or "").splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) < 5:
                continue
            containers.append(
                {
                    "id": parts[0],
                    "name": parts[1],
                    "image": parts[2],
                    "status": parts[3],
                    "ports": parts[4],
                }
            )
        return JsonResponse(
            {
                "instance_id": str(instance.id),
                "status": "ok",
                "ssm_command_id": result.get("ssm_command_id"),
                "containers": containers,
            }
        )
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=400)
