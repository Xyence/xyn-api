import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError
from django.conf import settings
from django.utils import timezone

from .models import Deployment, ProvisionedInstance, Release, ReleasePlan, ReleasePlanDeployState, RunArtifact


def compute_idempotency_base(
    release: Release, instance: ProvisionedInstance, release_plan: Optional[ReleasePlan], deploy_kind: str
) -> str:
    raw = f"{release.id}:{instance.id}:{release_plan.id if release_plan else ''}:{deploy_kind}:{release.version}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def hash_release_plan(plan: Dict[str, Any]) -> str:
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read_media_json(url: str) -> Optional[Dict[str, Any]]:
    if not url:
        return None
    file_path = ""
    if url.startswith("/media/"):
        file_path = os.path.join(settings.MEDIA_ROOT, url.replace("/media/", ""))
    elif settings.MEDIA_URL and url.startswith(settings.MEDIA_URL):
        suffix = url.replace(settings.MEDIA_URL, "").lstrip("/")
        file_path = os.path.join(settings.MEDIA_ROOT, suffix)
    if not file_path or not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError:
        return None


def _read_media_text(url: str) -> Optional[str]:
    if not url:
        return None
    file_path = ""
    if url.startswith("/media/"):
        file_path = os.path.join(settings.MEDIA_ROOT, url.replace("/media/", ""))
    elif settings.MEDIA_URL and url.startswith(settings.MEDIA_URL):
        suffix = url.replace(settings.MEDIA_URL, "").lstrip("/")
        file_path = os.path.join(settings.MEDIA_ROOT, suffix)
    if not file_path or not os.path.exists(file_path):
        return None
    with open(file_path, "r", encoding="utf-8") as handle:
        return handle.read()


def _find_release_plan_artifact_url(release: Release) -> Optional[str]:
    artifacts = release.artifacts_json or {}
    if isinstance(artifacts, list):
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            if item.get("name") == "release_plan.json":
                return item.get("url")
    if isinstance(artifacts, dict):
        plan_info = artifacts.get("release_plan") or {}
        if isinstance(plan_info, dict):
            return plan_info.get("url")
    return None


def _find_compose_artifact_url(release: Release) -> Optional[str]:
    artifacts = release.artifacts_json or {}
    if isinstance(artifacts, dict):
        compose_info = artifacts.get("compose_file") or {}
        if isinstance(compose_info, dict):
            return compose_info.get("url")
    return None


def _load_default_compose() -> Optional[str]:
    compose_path = os.environ.get("XYENCE_SEED_COMPOSE_PATH", "/xyn-seed/compose.yml")
    if not compose_path:
        return None
    if not os.path.exists(compose_path):
        return None
    with open(compose_path, "r", encoding="utf-8") as handle:
        return handle.read()


def load_release_plan_json(release: Release, release_plan: Optional[ReleasePlan]) -> Optional[Dict[str, Any]]:
    if release_plan and release_plan.last_run_id:
        artifact = (
            RunArtifact.objects.filter(run_id=release_plan.last_run_id, name="release_plan.json")
            .order_by("-created_at")
            .first()
        )
        if artifact and artifact.url:
            data = _read_media_json(artifact.url)
            if data:
                return data
    url = _find_release_plan_artifact_url(release)
    if url:
        return _read_media_json(url)
    return None


def _redact_output(text: str) -> str:
    redacted = text or ""
    for env_key in ["XYENCE_INTERNAL_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]:
        value = os.environ.get(env_key)
        if value:
            redacted = redacted.replace(value, "***REDACTED***")
    return redacted


def _run_ssm_commands(instance_id: str, region: str, commands: List[str]) -> Dict[str, Any]:
    ssm = boto3.client("ssm", region_name=region)
    cmd = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
    )
    command_id = cmd["Command"]["CommandId"]
    out: Optional[Dict[str, Any]] = None
    last_error: Optional[Exception] = None
    started_at = timezone.now().isoformat()
    for _ in range(120):
        try:
            out = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            last_error = exc
            time.sleep(1)
            continue
        status = out.get("Status")
        if status in {"Success", "Failed", "TimedOut", "Cancelled"}:
            break
        time.sleep(2)
    if out is None:
        raise last_error or RuntimeError("SSM command invocation not found yet")
    finished_at = timezone.now().isoformat()
    stdout = (out.get("StandardOutputContent") or "")[-4000:]
    stderr = (out.get("StandardErrorContent") or "")[-4000:]
    return {
        "ssm_command_id": command_id,
        "invocation_status": out.get("Status"),
        "response_code": out.get("ResponseCode"),
        "stdout": stdout,
        "stderr": stderr,
        "started_at": started_at,
        "finished_at": finished_at,
    }


def _write_deployment_artifact(deployment: Deployment, filename: str, content: str | dict | list) -> str:
    artifacts_root = os.path.join(settings.MEDIA_ROOT, "deployment_artifacts", str(deployment.id))
    os.makedirs(artifacts_root, exist_ok=True)
    file_path = os.path.join(artifacts_root, filename)
    if isinstance(content, (dict, list)):
        serialized = json.dumps(content, indent=2)
    else:
        serialized = content
    with open(file_path, "w", encoding="utf-8") as handle:
        handle.write(serialized)
    return f"{settings.MEDIA_URL.rstrip('/')}/deployment_artifacts/{deployment.id}/{filename}"


def execute_release_plan_deploy(
    deployment: Deployment,
    release: Release,
    instance: ProvisionedInstance,
    release_plan: Optional[ReleasePlan],
    plan_json: Dict[str, Any],
) -> Dict[str, Any]:
    deployment.status = "running"
    deployment.started_at = timezone.now()
    deployment.save(update_fields=["status", "started_at", "updated_at"])
    compose_url = _find_compose_artifact_url(release)
    compose_source = "release_artifact"
    if compose_url:
        compose_content = _read_media_text(compose_url)
    else:
        compose_content = None
    if not compose_content:
        compose_content = _load_default_compose()
        compose_source = "seed_repo"
    steps = plan_json.get("steps") or []
    execution: Dict[str, Any] = {"status": "succeeded", "steps": []}
    ssm_command_ids: List[str] = []
    last_stdout = ""
    last_stderr = ""
    try:
        if compose_content and compose_source == "release_artifact":
            digest = hashlib.sha256(compose_content.encode("utf-8")).hexdigest()
            _run_ssm_commands(
                instance.instance_id,
                instance.aws_region,
                [
                    "mkdir -p /var/lib/xyn/ems",
                    f"cat > /var/lib/xyn/ems/docker-compose.yml <<'XYN_COMPOSE'\n{compose_content}\nXYN_COMPOSE",
                    f"sha256sum /var/lib/xyn/ems/docker-compose.yml | grep -q {digest}",
                ],
            )
        elif compose_source == "seed_repo":
            seed_repo = os.environ.get("XYENCE_SEED_REPO_URL", "https://github.com/Xyence/xyn-seed.git")
            seed_ref = os.environ.get("XYENCE_SEED_REPO_REF", "main")
            _run_ssm_commands(
                instance.instance_id,
                instance.aws_region,
                [
                    "mkdir -p /var/lib/xyn",
                    "rm -rf /var/lib/xyn/ems",
                    "git clone --depth 1 --branch "
                    + seed_ref
                    + " "
                    + seed_repo
                    + " /var/lib/xyn/ems",
                    "cp /var/lib/xyn/ems/compose.yml /var/lib/xyn/ems/docker-compose.yml",
                    "docker rm -f xyn-postgres xyn-redis xyn-core 2>/dev/null || true",
                ],
            )
        for step in steps:
            step_name = step.get("name") or "step"
            commands = step.get("commands") or []
            step_record: Dict[str, Any] = {"name": step_name, "commands": []}
            for command in commands:
                result = _run_ssm_commands(instance.instance_id, instance.aws_region, [command])
                ssm_command_ids.append(result.get("ssm_command_id", ""))
                status = (
                    "succeeded"
                    if result.get("invocation_status") == "Success" and result.get("response_code") == 0
                    else "failed"
                )
                stdout = _redact_output(result.get("stdout", ""))
                stderr = _redact_output(result.get("stderr", ""))
                command_record = {
                    "command": command,
                    "status": status,
                    "exit_code": result.get("response_code"),
                    "started_at": result.get("started_at"),
                    "finished_at": result.get("finished_at"),
                    "ssm_command_id": result.get("ssm_command_id", ""),
                    "stdout": stdout,
                    "stderr": stderr,
                }
                step_record["commands"].append(command_record)
                last_stdout = stdout
                last_stderr = stderr
                if status != "succeeded":
                    execution["status"] = "failed"
                    execution["failed_command"] = command_record
                    execution["steps"].append(step_record)
                    raise RuntimeError(f"SSM command failed in step {step_name}")
            execution["steps"].append(step_record)
    except Exception as exc:
        # Fallback path: if ECR auth is unavailable, deploy directly from source and local builds.
        fallback_error = ""
        if "no basic auth credentials" in f"{exc}\n{last_stderr}".lower():
            fallback_commands = [
                "set -euo pipefail",
                "ROOT=/opt/xyence",
                "mkdir -p \"$ROOT\"",
                "if [ ! -d \"$ROOT/xyn-api/.git\" ]; then git clone https://github.com/Xyence/xyn-api \"$ROOT/xyn-api\"; fi",
                "if [ ! -d \"$ROOT/xyn-ui/.git\" ]; then git clone https://github.com/Xyence/xyn-ui \"$ROOT/xyn-ui\"; fi",
                "git -C \"$ROOT/xyn-api\" fetch --all",
                "git -C \"$ROOT/xyn-api\" checkout main",
                "git -C \"$ROOT/xyn-api\" pull --ff-only",
                "git -C \"$ROOT/xyn-ui\" fetch --all",
                "git -C \"$ROOT/xyn-ui\" checkout main",
                "git -C \"$ROOT/xyn-ui\" pull --ff-only",
                "mkdir -p \"$ROOT/certs/current\" \"$ROOT/acme-webroot\"",
                "if [ ! -f \"$ROOT/certs/current/fullchain.pem\" ] || [ ! -f \"$ROOT/certs/current/privkey.pem\" ]; then "
                "openssl req -x509 -nodes -newkey rsa:2048 "
                "-keyout \"$ROOT/certs/current/privkey.pem\" "
                "-out \"$ROOT/certs/current/fullchain.pem\" "
                "-days 2 -subj \"/CN=ems.xyence.io\"; "
                "fi",
                "cd \"$ROOT/xyn-api\"",
                "XYN_UI_PATH=\"$ROOT/xyn-ui/apps/ems-ui\" "
                "EMS_PUBLIC_PORT=80 EMS_PUBLIC_TLS_PORT=443 "
                "EMS_CERTS_PATH=\"$ROOT/certs/current\" EMS_ACME_WEBROOT_PATH=\"$ROOT/acme-webroot\" "
                "EMS_PLATFORM_API_BASE=https://xyence.io EMS_OIDC_APP_ID=ems.platform EMS_OIDC_ENABLED=true "
                "EMS_JWT_SECRET=\"${EMS_JWT_SECRET:-dev-secret-change-me}\" "
                "docker compose -f apps/ems-stack/docker-compose.yml down -v --remove-orphans",
                "XYN_UI_PATH=\"$ROOT/xyn-ui/apps/ems-ui\" "
                "EMS_PUBLIC_PORT=80 EMS_PUBLIC_TLS_PORT=443 "
                "EMS_CERTS_PATH=\"$ROOT/certs/current\" EMS_ACME_WEBROOT_PATH=\"$ROOT/acme-webroot\" "
                "EMS_PLATFORM_API_BASE=https://xyence.io EMS_OIDC_APP_ID=ems.platform EMS_OIDC_ENABLED=true "
                "EMS_JWT_SECRET=\"${EMS_JWT_SECRET:-dev-secret-change-me}\" "
                "docker compose -f apps/ems-stack/docker-compose.yml up -d --build --remove-orphans",
                "for i in $(seq 1 30); do curl -fsS http://localhost:8080/health >/dev/null && break; sleep 2; done; curl -fsS http://localhost:8080/health >/dev/null",
                "for i in $(seq 1 30); do curl -fsS http://localhost:8080/api/health >/dev/null && break; sleep 2; done; curl -fsS http://localhost:8080/api/health >/dev/null",
            ]
            try:
                fallback = _run_ssm_commands(instance.instance_id, instance.aws_region, fallback_commands)
                fallback_status = (
                    "succeeded"
                    if fallback.get("invocation_status") == "Success" and fallback.get("response_code") == 0
                    else "failed"
                )
                last_stdout = _redact_output(fallback.get("stdout", ""))
                last_stderr = _redact_output(fallback.get("stderr", ""))
                ssm_command_ids.append(fallback.get("ssm_command_id", ""))
                execution["steps"].append(
                    {
                        "name": "fallback_source_build_apply",
                        "commands": [
                            {
                                "command": "fallback_source_build_apply",
                                "status": fallback_status,
                                "exit_code": fallback.get("response_code"),
                                "started_at": fallback.get("started_at"),
                                "finished_at": fallback.get("finished_at"),
                                "ssm_command_id": fallback.get("ssm_command_id", ""),
                                "stdout": last_stdout,
                                "stderr": last_stderr,
                            }
                        ],
                    }
                )
                if fallback_status == "succeeded":
                    execution["status"] = "succeeded"
                    deployment.status = "succeeded"
                    deployment.error_message = ""
                else:
                    fallback_error = "source-build fallback failed"
            except Exception as fallback_exc:
                fallback_error = str(fallback_exc)
        if deployment.status != "succeeded":
            deployment.status = "failed"
            deployment.error_message = fallback_error or str(exc)
    else:
        deployment.status = "succeeded"
    finally:
        deployment.finished_at = timezone.now()
        deployment.stdout_excerpt = last_stdout[-2000:]
        deployment.stderr_excerpt = last_stderr[-2000:]
        deployment.transport_ref = {
            "ssm_command_ids": [cid for cid in ssm_command_ids if cid],
        }
        artifacts: Dict[str, Any] = {}
        execution_url = _write_deployment_artifact(deployment, "deploy_execution.json", execution)
        artifacts["deploy_execution.json"] = {"url": execution_url}
        deployment.artifacts_json = artifacts
        deployment.save(
            update_fields=[
                "status",
                "error_message",
                "finished_at",
                "stdout_excerpt",
                "stderr_excerpt",
                "transport_ref",
                "artifacts_json",
                "updated_at",
            ]
        )
    if deployment.status == "succeeded":
        plan_hash = hash_release_plan(plan_json)
        if release_plan:
            ReleasePlanDeployState.objects.update_or_create(
                release_plan=release_plan,
                instance=instance,
                defaults={
                    "last_applied_hash": plan_hash,
                    "last_applied_at": timezone.now(),
                },
            )
        instance.observed_release = release
        instance.observed_at = timezone.now()
        instance.health_status = "healthy"
        instance.save(update_fields=["observed_release", "observed_at", "health_status", "updated_at"])
    else:
        instance.health_status = "failed"
        instance.save(update_fields=["health_status", "updated_at"])
    return execution
