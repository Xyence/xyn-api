import json
import time
from typing import Any, Dict, List, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

from .models import AuditLog, Deployment, Environment, ProvisionedInstance
from .provisioning import (
    provision_instance,
    retry_provision_instance,
    refresh_instance,
    destroy_instance,
    fetch_bootstrap_log,
)
from .blueprints import _require_staff
from .instances.bootstrap import get_instance_metadata


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
        "runtime_substrate": instance.runtime_substrate,
        "last_error": instance.last_error,
        "desired_release_id": str(instance.desired_release_id) if instance.desired_release_id else None,
        "observed_release_id": str(instance.observed_release_id) if instance.observed_release_id else None,
        "observed_at": instance.observed_at,
        "last_deploy_run_id": str(instance.last_deploy_run_id) if instance.last_deploy_run_id else None,
        "health_status": instance.health_status,
        "tags": instance.tags_json or {},
        "last_seen_at": instance.last_seen_at,
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


@csrf_exempt
@login_required
def get_instance(request: HttpRequest, instance_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    instance = get_object_or_404(ProvisionedInstance, id=instance_id)
    if request.method == "PATCH":
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
        if "environment_id" not in payload:
            return JsonResponse({"error": "environment_id required"}, status=400)
        new_env_id = payload.get("environment_id")
        if not new_env_id:
            return JsonResponse({"error": "environment_id required"}, status=400)
        force = bool(payload.get("force"))
        if not force and Deployment.objects.filter(
            instance=instance, status__in=["queued", "running"]
        ).exists():
            return JsonResponse(
                {"error": "instance has active deployments; use force to override"},
                status=409,
            )
        new_env = get_object_or_404(Environment, id=new_env_id)
        old_env = instance.environment
        if old_env != new_env:
            instance.environment = new_env
            instance.updated_by = request.user
            instance.save(update_fields=["environment", "updated_by", "updated_at"])
            old_label = old_env.slug if old_env else "none"
            new_label = new_env.slug if new_env else "none"
            AuditLog.objects.create(
                message=f"Instance {instance.id} environment changed {old_label} -> {new_label}",
                created_by=request.user,
                metadata_json={"instance_id": str(instance.id), "old": old_label, "new": new_label},
            )
        return JsonResponse(_instance_payload(instance))
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
        message = f"SSM send_command failed: {exc}"
        if "InvalidInstanceId" in str(exc):
            try:
                instance = refresh_instance(instance)
            except Exception:
                pass
            instance.status = "error"
            instance.ssm_status = "Offline"
            instance.last_error = "SSM InvalidInstanceId"
            instance.save(update_fields=["status", "ssm_status", "last_error", "updated_at"])
            message = (
                f"{message}. Instance record={instance.id} "
                f"ec2_instance_id={instance.instance_id or 'n/a'} region={instance.aws_region or 'n/a'} "
                f"status={instance.status or 'unknown'} ssm_status={instance.ssm_status or 'unknown'}"
            )
        raise RuntimeError(message) from exc
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
    if _is_local_instance(instance):
        try:
            containers = _list_local_containers()
            return JsonResponse(
                {
                    "instance_id": str(instance.id),
                    "status": "ok",
                    "containers": containers,
                }
            )
        except Exception as exc:
            return JsonResponse(
                {
                    "error": str(exc),
                    "hint": "Ensure /var/run/docker.sock is mounted and the Docker SDK is installed.",
                },
                status=400,
            )
    try:
        instance = refresh_instance(instance)
    except Exception:
        # Best-effort refresh; if it fails we'll still attempt SSM below.
        pass
    non_runnable_statuses = {"terminated", "terminating", "error"}
    ssm_state = (instance.ssm_status or "").lower()
    if (instance.status or "").lower() in non_runnable_statuses or ssm_state in {"offline", "connectionlost", "inactive"}:
        return JsonResponse(
            {
                "instance_id": str(instance.id),
                "name": instance.name,
                "aws_instance_id": instance.instance_id,
                "status": instance.status,
                "ssm_status": instance.ssm_status,
                "error": "Instance is not in a runnable state for SSM container inspection.",
            },
            status=409,
        )
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
        return JsonResponse(
            {
                "instance_id": str(instance.id),
                "name": instance.name,
                "aws_instance_id": instance.instance_id,
                "error": str(exc),
            },
            status=400,
        )


def _is_local_instance(instance: ProvisionedInstance) -> bool:
    # Treat EC2-style identifiers as remote even if legacy rows have stale substrate flags.
    if instance.instance_id and instance.instance_id.startswith("i-"):
        return False
    if instance.runtime_substrate in {"local", "docker"}:
        return True
    if instance.instance_id and instance.instance_id.startswith(("local:", "docker:")):
        return True
    try:
        metadata = get_instance_metadata()
    except Exception:
        return False
    return bool(instance.instance_id and metadata.instance_id == instance.instance_id)


def _list_local_containers() -> List[Dict[str, str]]:
    try:
        import docker
    except Exception as exc:
        raise RuntimeError(f"Docker SDK unavailable: {exc}") from exc
    try:
        client = docker.from_env()
        containers = client.containers.list()
    except Exception as exc:
        raise RuntimeError(f"Docker client error: {exc}") from exc
    payload = []
    for container in containers:
        attrs = container.attrs or {}
        payload.append(
            {
                "id": container.short_id,
                "name": container.name or "",
                "image": (attrs.get("Config") or {}).get("Image") or "",
                "status": container.status or "",
                "ports": _format_ports(attrs.get("NetworkSettings") or {}),
            }
        )
    return payload


def _format_ports(network_settings: Dict[str, Any]) -> str:
    ports = network_settings.get("Ports") or {}
    formatted = []
    for container_port, bindings in ports.items():
        if not bindings:
            formatted.append(container_port)
            continue
        for binding in bindings:
            host_ip = binding.get("HostIp", "")
            host_port = binding.get("HostPort", "")
            formatted.append(f"{host_ip}:{host_port}->{container_port}")
    return ", ".join(formatted)
