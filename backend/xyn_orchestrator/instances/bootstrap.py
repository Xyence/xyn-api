import logging
import os
import socket
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


logger = logging.getLogger(__name__)

IMDS_BASE = "http://169.254.169.254/latest"
IMDS_TOKEN_URL = f"{IMDS_BASE}/api/token"
IMDS_IDENTITY_URL = f"{IMDS_BASE}/dynamic/instance-identity/document"
IMDS_META_URL = f"{IMDS_BASE}/meta-data"

ECS_METADATA_ENV_V4 = "ECS_CONTAINER_METADATA_URI_V4"
ECS_METADATA_ENV_V3 = "ECS_CONTAINER_METADATA_URI"

K8S_NAMESPACE_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

_BOOTSTRAP_LOCK = threading.Lock()
_BOOTSTRAP_DONE = False


@dataclass
class InstanceMetadata:
    substrate: str
    instance_id: str
    name: str
    region: str
    instance_type: str
    ami_id: str
    status: str
    environment_id: Optional[str] = None
    tags: Optional[Dict[str, Any]] = None


def detect_runtime_substrate() -> str:
    configured = os.environ.get("XYENCE_RUNTIME_SUBSTRATE", "auto").strip().lower() or "auto"
    if configured != "auto":
        return configured
    if discover_ec2_identity():
        return "ec2"
    if discover_fargate_identity():
        return "fargate"
    if discover_k8s_identity():
        return "k8s"
    if discover_docker_identity():
        return "docker"
    return "local"


def discover_ec2_identity() -> Optional[InstanceMetadata]:
    token = _imds_token()
    if not token:
        return None
    headers = {"X-aws-ec2-metadata-token": token}
    try:
        doc = requests.get(IMDS_IDENTITY_URL, headers=headers, timeout=0.5)
        doc.raise_for_status()
        payload = doc.json()
    except Exception:
        return None
    instance_id = payload.get("instanceId", "")
    region = payload.get("region", "")
    ami_id = payload.get("imageId", "") or _imds_meta("ami-id", headers)
    instance_type = payload.get("instanceType", "") or _imds_meta("instance-type", headers)
    hostname = _imds_meta("hostname", headers)
    name = _aws_instance_name(instance_id, region) or hostname or instance_id
    if not instance_id:
        return None
    return InstanceMetadata(
        substrate="ec2",
        instance_id=instance_id,
        name=name or instance_id,
        region=region or "unknown",
        instance_type=instance_type or "unknown",
        ami_id=ami_id or "unknown",
        status="running",
        tags={"source": "imds"},
    )


def discover_fargate_identity() -> Optional[InstanceMetadata]:
    metadata_url = os.environ.get(ECS_METADATA_ENV_V4, "").strip() or os.environ.get(ECS_METADATA_ENV_V3, "").strip()
    if not metadata_url:
        return None
    try:
        task_url = metadata_url.rstrip("/") + "/task"
        response = requests.get(task_url, timeout=0.5)
        response.raise_for_status()
        task = response.json()
    except Exception:
        return None
    task_arn = task.get("TaskARN", "") or task.get("TaskArn", "")
    if not task_arn:
        return None
    region = _region_from_arn(task_arn) or os.environ.get("AWS_REGION", "unknown")
    family = task.get("Family") or "ecs-task"
    revision = task.get("Revision")
    name = f"{family}:{revision}" if revision is not None else family
    launch_type = (task.get("LaunchType") or "fargate").lower()
    return InstanceMetadata(
        substrate="fargate",
        instance_id=task_arn,
        name=name,
        region=region,
        instance_type=launch_type,
        ami_id="fargate",
        status="running",
        tags={"cluster": task.get("Cluster"), "source": "ecs-metadata"},
    )


def discover_k8s_identity() -> Optional[InstanceMetadata]:
    if not os.environ.get("KUBERNETES_SERVICE_HOST"):
        return None
    namespace = _read_file(K8S_NAMESPACE_PATH).strip() or "default"
    pod_name = os.environ.get("HOSTNAME", "").strip() or "pod"
    cluster = os.environ.get("KUBERNETES_CLUSTER_NAME", "").strip()
    instance_id = f"k8s:{namespace}:{pod_name}"
    if cluster:
        instance_id = f"k8s:{cluster}:{namespace}:{pod_name}"
    region = os.environ.get("AWS_REGION", "").strip() or "unknown"
    return InstanceMetadata(
        substrate="k8s",
        instance_id=instance_id,
        name=pod_name,
        region=region,
        instance_type="k8s",
        ami_id="k8s",
        status="running",
        tags={"namespace": namespace, "cluster": cluster, "source": "k8s-env"},
    )


def discover_docker_identity() -> Optional[InstanceMetadata]:
    container_id = _detect_container_id()
    if not container_id:
        return None
    hostname = os.environ.get("HOSTNAME", "").strip() or container_id[:12]
    instance_id = f"docker:{container_id}"
    region = os.environ.get("AWS_REGION", "").strip() or "unknown"
    return InstanceMetadata(
        substrate="docker",
        instance_id=instance_id,
        name=hostname,
        region=region,
        instance_type="docker",
        ami_id="docker",
        status="running",
        tags={"container_id": container_id, "source": "cgroup"},
    )


def discover_local_identity() -> InstanceMetadata:
    hostname = socket.gethostname()
    instance_id = f"local:{hostname}"
    region = os.environ.get("AWS_REGION", "").strip() or "local"
    return InstanceMetadata(
        substrate="local",
        instance_id=instance_id,
        name=hostname,
        region=region,
        instance_type="local",
        ami_id="local",
        status="running",
        tags={"source": "local"},
    )


def get_instance_metadata(subtype: Optional[str] = None) -> InstanceMetadata:
    substrate = (subtype or os.environ.get("XYENCE_RUNTIME_SUBSTRATE", "auto")).strip().lower()
    if not substrate or substrate == "auto":
        substrate = detect_runtime_substrate()
    if substrate == "ec2":
        metadata = discover_ec2_identity()
    elif substrate == "fargate":
        metadata = discover_fargate_identity()
    elif substrate == "k8s":
        metadata = discover_k8s_identity()
    elif substrate == "docker":
        metadata = discover_docker_identity()
    else:
        metadata = discover_local_identity()
    if not metadata:
        metadata = discover_local_identity()
    return _apply_overrides(metadata)


def upsert_local_instance_record(subtype: Optional[str] = None) -> Optional[str]:
    metadata = get_instance_metadata(subtype)
    from django.utils import timezone
    from django.utils.text import slugify
    from xyn_orchestrator.models import Environment, ProvisionedInstance

    env_id = metadata.environment_id
    environment = None
    if env_id:
        environment = Environment.objects.filter(id=env_id).first()
    if not environment:
        slug = "local"
        environment, _ = Environment.objects.get_or_create(
            slug=slug, defaults={"name": "Local", "base_domain": "", "aws_region": metadata.region or ""}
        )
    instance_id = metadata.instance_id
    if not instance_id:
        return None
    instance = ProvisionedInstance.objects.filter(instance_id=instance_id).first()
    if not instance:
        instance = ProvisionedInstance(instance_id=instance_id, name=metadata.name)
    instance.runtime_substrate = metadata.substrate
    instance.name = metadata.name or instance.name or instance_id
    instance.aws_region = metadata.region or instance.aws_region or "unknown"
    instance.instance_type = metadata.instance_type or instance.instance_type or "unknown"
    instance.ami_id = metadata.ami_id or instance.ami_id or "unknown"
    instance.status = metadata.status or instance.status or "running"
    if environment:
        instance.environment = environment
    tags = instance.tags_json or {}
    tags.update(metadata.tags or {})
    tags.setdefault("runtime_substrate", metadata.substrate)
    instance.tags_json = tags
    instance.last_seen_at = timezone.now()
    instance.save()
    return str(instance.id)


def bootstrap_instance_registration() -> None:
    global _BOOTSTRAP_DONE
    if _BOOTSTRAP_DONE:
        return
    with _BOOTSTRAP_LOCK:
        if _BOOTSTRAP_DONE:
            return
        _BOOTSTRAP_DONE = True
    try:
        from django.core.cache import cache
        lock_key = "xyn:instance-bootstrap"
        if cache and not cache.add(lock_key, "1", timeout=120):
            logger.info("Instance bootstrap already handled by another worker.")
            return
    except Exception:
        pass
    try:
        metadata = get_instance_metadata()
        logger.info(
            "Detected runtime substrate=%s instance_id=%s region=%s type=%s",
            metadata.substrate,
            metadata.instance_id,
            metadata.region,
            metadata.instance_type,
        )
        instance_id = upsert_local_instance_record(metadata.substrate)
        logger.info("Instance registration completed id=%s", instance_id)
    except Exception as exc:
        logger.warning("Instance bootstrap failed: %s", exc)


def _apply_overrides(metadata: InstanceMetadata) -> InstanceMetadata:
    overrides = {
        "instance_id": os.environ.get("XYENCE_LOCAL_INSTANCE_ID", "").strip(),
        "name": os.environ.get("XYENCE_LOCAL_INSTANCE_NAME", "").strip(),
        "region": os.environ.get("XYENCE_LOCAL_AWS_REGION", "").strip(),
        "instance_type": os.environ.get("XYENCE_LOCAL_INSTANCE_TYPE", "").strip(),
        "ami_id": os.environ.get("XYENCE_LOCAL_AMI_ID", "").strip(),
        "status": os.environ.get("XYENCE_LOCAL_STATUS", "").strip(),
        "environment_id": os.environ.get("XYENCE_LOCAL_ENVIRONMENT_ID", "").strip()
        or os.environ.get("XYENCE_ENVIRONMENT_ID", "").strip(),
    }
    applied = False
    for key, value in overrides.items():
        if value:
            setattr(metadata, key, value)
            applied = True
    if applied:
        logger.info("Applied local instance overrides for substrate detection.")
    if not metadata.instance_id:
        metadata.instance_id = f"{metadata.substrate}:{metadata.name}"
    return metadata


def _imds_token() -> Optional[str]:
    try:
        response = requests.put(
            IMDS_TOKEN_URL,
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            timeout=0.3,
        )
        response.raise_for_status()
        return response.text
    except Exception:
        return None


def _imds_meta(path: str, headers: Dict[str, str]) -> str:
    try:
        response = requests.get(f"{IMDS_META_URL}/{path}", headers=headers, timeout=0.3)
        response.raise_for_status()
        return response.text.strip()
    except Exception:
        return ""


def _aws_instance_name(instance_id: str, region: str) -> str:
    if not instance_id or not region:
        return ""
    try:
        import boto3

        ec2 = boto3.client("ec2", region_name=region)
        resp = ec2.describe_tags(
            Filters=[
                {"Name": "resource-id", "Values": [instance_id]},
                {"Name": "key", "Values": ["Name"]},
            ]
        )
        for tag in resp.get("Tags", []):
            if tag.get("Key") == "Name":
                return tag.get("Value", "") or ""
    except Exception:
        return ""
    return ""


def _region_from_arn(arn: str) -> str:
    try:
        parts = arn.split(":")
        return parts[3] if len(parts) > 3 else ""
    except Exception:
        return ""


def _detect_container_id() -> str:
    for path in ("/proc/1/cgroup", "/proc/self/cgroup"):
        content = _read_file(path)
        if not content:
            continue
        for line in content.splitlines():
            parts = line.split("/")
            if not parts:
                continue
            candidate = parts[-1].strip()
            if len(candidate) >= 12 and all(ch in "0123456789abcdef" for ch in candidate[:12].lower()):
                return candidate
            if "docker-" in candidate:
                candidate = candidate.replace("docker-", "").replace(".scope", "")
                if candidate:
                    return candidate
    return ""


def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except Exception:
        return ""
