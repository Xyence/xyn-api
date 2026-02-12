import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

import boto3
import requests
from botocore.exceptions import ClientError
from django.conf import settings
from django.utils import timezone
import yaml

from .models import (
    Deployment,
    ProvisionedInstance,
    Release,
    ReleasePlan,
    ReleasePlanDeployState,
    ReleaseTarget,
    RunArtifact,
)


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


TLS_TASK_IDS = {"tls.acme_http01", "ingress.nginx_tls_configure", "verify.public_https"}


def _is_host_ingress_target(release_target: Optional[ReleaseTarget]) -> bool:
    tls = (release_target.tls_json if release_target else {}) or {}
    return str(tls.get("mode") or "").strip().lower() == "host-ingress"


def _render_traefik_ingress_compose(network: str, acme_email: str) -> str:
    email = acme_email or "admin@xyence.io"
    return (
        "services:\n"
        "  traefik:\n"
        "    image: traefik:v3.1\n"
        "    container_name: xyn-ingress-traefik\n"
        "    command:\n"
        "      - --providers.docker=true\n"
        "      - --providers.docker.exposedbydefault=false\n"
        "      - --entrypoints.web.address=:80\n"
        "      - --entrypoints.websecure.address=:443\n"
        "      - --entrypoints.web.http.redirections.entrypoint.to=websecure\n"
        "      - --entrypoints.web.http.redirections.entrypoint.scheme=https\n"
        f"      - --certificatesresolvers.le.acme.email={email}\n"
        "      - --certificatesresolvers.le.acme.storage=/acme/acme.json\n"
        "      - --certificatesresolvers.le.acme.httpchallenge=true\n"
        "      - --certificatesresolvers.le.acme.httpchallenge.entrypoint=web\n"
        "    ports:\n"
        "      - \"80:80\"\n"
        "      - \"443:443\"\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock:ro\n"
        "      - /opt/xyn/ingress/acme:/acme\n"
        "    restart: unless-stopped\n"
        "    networks:\n"
        f"      - {network}\n"
        "networks:\n"
        f"  {network}:\n"
        "    external: true\n"
    )


def _adapt_compose_for_host_ingress(compose_content: str, release_target: Optional[ReleaseTarget]) -> str:
    if not compose_content:
        return compose_content
    try:
        data = yaml.safe_load(compose_content) or {}
    except Exception:
        return compose_content
    if not isinstance(data, dict):
        return compose_content
    services = data.get("services")
    if not isinstance(services, dict):
        return compose_content
    ingress = ((release_target.config_json if release_target else {}) or {}).get("ingress") or {}
    network = str(ingress.get("network") or "xyn-edge")
    routes = ingress.get("routes") if isinstance(ingress.get("routes"), list) else []
    ems_web = services.get("ems-web")
    ems_api = services.get("ems-api")
    if not isinstance(ems_web, dict):
        return compose_content
    if isinstance(ems_api, dict):
        api_networks = ems_api.get("networks")
        if not isinstance(api_networks, list):
            api_networks = []
        for required in ("default", network):
            if required not in api_networks:
                api_networks.append(required)
        ems_api["networks"] = api_networks
    ems_web.pop("ports", None)
    networks = ems_web.get("networks")
    if not isinstance(networks, list):
        networks = []
    for required in ("default", network):
        if required not in networks:
            networks.append(required)
    ems_web["networks"] = networks
    labels = ems_web.get("labels")
    if not isinstance(labels, list):
        labels = []
    labels = [entry for entry in labels if isinstance(entry, str) and not entry.startswith("traefik.")]
    route_entries = routes or [
        {"host": (release_target.fqdn if release_target else "") or "ems.xyence.io", "service": "ems-web", "port": 3000}
    ]
    for route in route_entries:
        if not isinstance(route, dict):
            continue
        service_name = str(route.get("service") or "ems-web")
        if service_name != "ems-web":
            continue
        host = str(route.get("host") or "").strip()
        if not host:
            continue
        rid = "".join(ch if ch.isalnum() else "-" for ch in host).strip("-").lower() or "ems"
        port = int(route.get("port") or 3000)
        labels.extend(
            [
                "traefik.enable=true",
                f"traefik.docker.network={network}",
                f"traefik.http.routers.{rid}.rule=Host(`{host}`)",
                f"traefik.http.routers.{rid}.entrypoints=websecure",
                f"traefik.http.routers.{rid}.tls=true",
                f"traefik.http.routers.{rid}.tls.certresolver=le",
                f"traefik.http.services.{rid}.loadbalancer.server.port={port}",
            ]
        )
    ems_web["labels"] = labels
    top_networks = data.get("networks")
    if not isinstance(top_networks, dict):
        top_networks = {}
    if network not in top_networks:
        top_networks[network] = {"external": True}
    data["networks"] = top_networks
    try:
        return yaml.safe_dump(data, sort_keys=False)
    except Exception:
        return compose_content


def _resolve_release_target(release: Release, instance: ProvisionedInstance) -> Optional[ReleaseTarget]:
    if not release.blueprint_id:
        return None
    target = (
        ReleaseTarget.objects.filter(blueprint_id=release.blueprint_id, target_instance=instance)
        .order_by("-updated_at")
        .first()
    )
    if target:
        return target
    return ReleaseTarget.objects.filter(blueprint_id=release.blueprint_id).order_by("-updated_at").first()


def _plan_task_ids(plan_json: Dict[str, Any]) -> set[str]:
    tasks = plan_json.get("tasks") or []
    ids = set()
    for task in tasks:
        if isinstance(task, dict) and task.get("id"):
            ids.add(str(task.get("id")))
    return ids


def _plan_expects_tls(plan_json: Dict[str, Any], release_target: Optional[ReleaseTarget]) -> bool:
    if _plan_task_ids(plan_json).intersection(TLS_TASK_IDS):
        return True
    if release_target and isinstance(release_target.tls_json, dict):
        mode = str((release_target.tls_json or {}).get("mode", "")).strip().lower()
        return mode in {"nginx+acme", "acme_http01", "host-ingress"}
    return False


def _lower_plan_steps(plan_json: Dict[str, Any], release_target: Optional[ReleaseTarget]) -> List[Dict[str, Any]]:
    steps = [step for step in (plan_json.get("steps") or []) if isinstance(step, dict)]
    if not _plan_expects_tls(plan_json, release_target):
        return steps
    if _is_host_ingress_target(release_target):
        existing = {str(step.get("name", "")).strip() for step in steps}
        if "verify_public_https" not in existing:
            steps.append({"name": "verify_public_https", "commands": []})
        return steps
    existing = {str(step.get("name", "")).strip() for step in steps}
    for name in ["tls_acme_http01_issue", "ingress_nginx_tls_configure", "verify_public_https"]:
        if name not in existing:
            steps.append({"name": name, "commands": []})
    return steps


def _build_tls_steps(
    fqdn: str,
    acme_email: str,
    compose_file: str,
    workdir: str,
    cert_dir: str,
    acme_webroot: str,
    expected_ip: str = "",
) -> List[Dict[str, Any]]:
    lego_dir = os.path.join(os.path.dirname(cert_dir), "lego-data")
    dns_mismatch_check = (
        f"[ \"$resolved\" = \"{expected_ip}\" ] || {{ echo \"tls_error_code=dns_mismatch\"; exit 52; }}; "
        if expected_ip
        else ""
    )
    issue_cmd = (
        "set -euo pipefail; "
        f"mkdir -p \"{cert_dir}\" \"{acme_webroot}\" \"{lego_dir}\"; "
        f"if [ -f \"{cert_dir}/fullchain.pem\" ] && [ -f \"{cert_dir}/privkey.pem\" ]; then "
        f"openssl x509 -checkend 1209600 -noout -in \"{cert_dir}/fullchain.pem\" >/dev/null 2>&1 && "
        "echo \"acme_noop\" && exit 0; "
        "fi; "
        f"resolved=$(getent ahostsv4 \"{fqdn}\" 2>/dev/null | awk '{{print $1}}' | sort -u | head -n1 || true); "
        "[ -n \"$resolved\" ] || { echo \"tls_error_code=dns_lookup_failed\"; exit 51; }; "
        + dns_mismatch_check
        + " "
        "command -v docker >/dev/null 2>&1 || { echo \"tls_error_code=docker_missing\"; exit 41; }; "
        "command -v curl >/dev/null 2>&1 || { echo \"tls_error_code=curl_missing\"; exit 42; }; "
        "command -v openssl >/dev/null 2>&1 || { echo \"tls_error_code=openssl_missing\"; exit 43; }; "
        f"cd \"{workdir}\"; "
        "EMS_PUBLIC_PORT=80 EMS_PUBLIC_TLS_PORT=443 "
        f"docker compose -f \"{compose_file}\" stop ems-web || true; "
        "docker run --rm -p 80:80 "
        f"-v \"{lego_dir}\":/data "
        "goacme/lego:v4.12.3 "
        f"--email \"{acme_email}\" --domains \"{fqdn}\" --path /data --accept-tos "
        "--http run; "
        f"[ -f \"{lego_dir}/certificates/{fqdn}.crt\" ] || {{ echo \"tls_error_code=acme_issue_failed\"; exit 44; }}; "
        f"[ -f \"{lego_dir}/certificates/{fqdn}.key\" ] || {{ echo \"tls_error_code=acme_key_missing\"; exit 45; }}; "
        f"cp \"{lego_dir}/certificates/{fqdn}.crt\" \"{cert_dir}/fullchain.pem\"; "
        f"cp \"{lego_dir}/certificates/{fqdn}.key\" \"{cert_dir}/privkey.pem\"; "
        f"chmod 600 \"{cert_dir}/privkey.pem\""
    )
    configure_cmd = (
        "set -euo pipefail; "
        f"cd \"{workdir}\"; "
        f"[ -f \"{cert_dir}/fullchain.pem\" ] || {{ echo \"tls_error_code=cert_missing\"; exit 46; }}; "
        f"[ -f \"{cert_dir}/privkey.pem\" ] || {{ echo \"tls_error_code=key_missing\"; exit 47; }}; "
        f"EMS_CERTS_PATH=\"{cert_dir}\" EMS_ACME_WEBROOT_PATH=\"{acme_webroot}\" "
        "EMS_PUBLIC_PORT=80 EMS_PUBLIC_TLS_PORT=443 "
        f"docker compose -f \"{compose_file}\" up -d --remove-orphans; "
        f"EMS_CERTS_PATH=\"{cert_dir}\" EMS_ACME_WEBROOT_PATH=\"{acme_webroot}\" "
        "EMS_PUBLIC_PORT=80 EMS_PUBLIC_TLS_PORT=443 "
        f"docker compose -f \"{compose_file}\" restart ems-web"
    )
    verify_cmd = (
        "set -euo pipefail; "
        "command -v curl >/dev/null 2>&1 || { echo \"tls_error_code=curl_missing\"; exit 42; }; "
        "command -v openssl >/dev/null 2>&1 || { echo \"tls_error_code=openssl_missing\"; exit 43; }; "
        f"openssl x509 -in \"{cert_dir}/fullchain.pem\" -noout -ext subjectAltName | grep -q \"DNS:{fqdn}\" "
        "|| { echo \"tls_error_code=hostname_mismatch\"; exit 48; }; "
        f"issuer=$(openssl x509 -in \"{cert_dir}/fullchain.pem\" -noout -issuer | sed 's/^issuer=//'); "
        f"subject=$(openssl x509 -in \"{cert_dir}/fullchain.pem\" -noout -subject | sed 's/^subject=//'); "
        "[ \"$issuer\" != \"$subject\" ] || { echo \"tls_error_code=self_signed_detected\"; exit 49; }; "
        f"for i in $(seq 1 24); do curl -fsS --resolve \"{fqdn}:443:127.0.0.1\" \"https://{fqdn}/health\" >/dev/null && break; sleep 5; done; "
        f"curl -fsS --resolve \"{fqdn}:443:127.0.0.1\" \"https://{fqdn}/health\" >/dev/null "
        "|| { echo \"tls_error_code=https_health_failed\"; exit 50; }"
    )
    return [
        {"name": "tls_acme_http01_issue", "commands": [issue_cmd]},
        {"name": "ingress_nginx_tls_configure", "commands": [configure_cmd]},
        {"name": "verify_public_https", "commands": [verify_cmd]},
    ]


def _verify_public_https_from_backend(fqdn: str) -> tuple[bool, str]:
    last_err = ""
    for _ in range(18):
        try:
            response = requests.get(f"https://{fqdn}/health", timeout=15)
        except requests.RequestException as exc:
            last_err = f"public_https_unreachable: {exc}"
            time.sleep(10)
            continue
        if response.status_code == 200:
            return True, ""
        last_err = f"public_https_bad_status:{response.status_code}"
        time.sleep(10)
    return False, last_err


def _extract_tls_error_code(stderr: str) -> str:
    marker = "tls_error_code="
    idx = stderr.rfind(marker)
    if idx < 0:
        lower = (stderr or "").lower()
        if "acme:error:connection" in lower and "connection refused" in lower:
            return "acme_http01_connection_refused"
        if "acme:error:connection" in lower and "timeout" in lower:
            return "acme_http01_timeout"
        if "acme:error:dns" in lower or "nxdomain" in lower:
            return "acme_dns_invalid"
        if "acme:error:ratelimited" in lower or "rate limit" in lower:
            return "acme_rate_limited"
        if "could not obtain certificates" in lower:
            return "acme_issue_failed"
        return "tls_unknown_failure"
    code = stderr[idx + len(marker) :].splitlines()[0].strip()
    return code or "tls_unknown_failure"


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
    release_target = _resolve_release_target(release, instance)
    expects_tls = _plan_expects_tls(plan_json, release_target)
    steps = _lower_plan_steps(plan_json, release_target)
    plan_json["steps"] = steps
    execution: Dict[str, Any] = {"status": "succeeded", "steps": []}
    ssm_command_ids: List[str] = []
    last_stdout = ""
    last_stderr = ""
    deploy_workdir = "/var/lib/xyn/ems"
    deploy_compose_file = "/var/lib/xyn/ems/docker-compose.yml"
    cert_dir = "/var/lib/xyn/ems/certs/current"
    acme_webroot = "/var/lib/xyn/ems/acme-webroot"
    try:
        if compose_content and compose_source == "release_artifact":
            if _is_host_ingress_target(release_target):
                compose_content = _adapt_compose_for_host_ingress(compose_content, release_target)
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
        if _is_host_ingress_target(release_target):
            ingress = (release_target.config_json or {}).get("ingress") or {}
            network = str(ingress.get("network") or "xyn-edge")
            tls = (release_target.tls_json or {}) if release_target else {}
            acme_email = str(tls.get("acme_email") or os.environ.get("XYENCE_ACME_EMAIL", "")).strip()
            ingress_compose = _render_traefik_ingress_compose(network, acme_email)
            _run_ssm_commands(
                instance.instance_id,
                instance.aws_region,
                [
                    f"docker network inspect {network} >/dev/null 2>&1 || docker network create {network}",
                    "mkdir -p /opt/xyn/ingress/acme",
                    "touch /opt/xyn/ingress/acme/acme.json",
                    "chmod 600 /opt/xyn/ingress/acme/acme.json",
                    f"cat > /opt/xyn/ingress/compose.ingress.yml <<'XYN_TRAEFIK'\n{ingress_compose}\nXYN_TRAEFIK",
                    "PORT_OWNERS=$(docker ps --format '{{.Names}} {{.Ports}}' | grep -E '(:80->|:443->)' | awk '{print $1}' | grep -v '^xyn-ingress-traefik$' || true); "
                    "if [ -n \"$PORT_OWNERS\" ]; then echo \"tls_error_code=ingress_port_collision\"; exit 61; fi",
                    "docker compose -f /opt/xyn/ingress/compose.ingress.yml up -d",
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
            fallback_root = f"/opt/xyence/deploy-{deployment.id}"
            fallback_state_root = "/opt/xyence"
            fallback_commands = [
                "set -euo pipefail",
                f"ROOT={fallback_root}",
                f"STATE={fallback_state_root}",
                "mkdir -p \"$ROOT\"",
                "mkdir -p \"$STATE/certs/current\" \"$STATE/acme-webroot\"",
                "rm -rf \"$ROOT/xyn-api\" \"$ROOT/xyn-ui\"",
                "git clone --depth 1 --branch main https://github.com/Xyence/xyn-api \"$ROOT/xyn-api\"",
                "git clone --depth 1 --branch main https://github.com/Xyence/xyn-ui \"$ROOT/xyn-ui\"",
                "cd \"$ROOT/xyn-api\"",
                "XYN_UI_PATH=\"$ROOT/xyn-ui/apps/ems-ui\" "
                "EMS_PUBLIC_PORT=80 EMS_PUBLIC_TLS_PORT=443 "
                "EMS_CERTS_PATH=\"$STATE/certs/current\" EMS_ACME_WEBROOT_PATH=\"$STATE/acme-webroot\" "
                "EMS_PLATFORM_API_BASE=https://xyence.io EMS_OIDC_APP_ID=ems.platform EMS_OIDC_ENABLED=true "
                "EMS_JWT_SECRET=\"${EMS_JWT_SECRET:-dev-secret-change-me}\" "
                "docker compose -f apps/ems-stack/docker-compose.yml down -v --remove-orphans",
                "XYN_UI_PATH=\"$ROOT/xyn-ui/apps/ems-ui\" "
                "EMS_PUBLIC_PORT=80 EMS_PUBLIC_TLS_PORT=443 "
                "EMS_CERTS_PATH=\"$STATE/certs/current\" EMS_ACME_WEBROOT_PATH=\"$STATE/acme-webroot\" "
                "EMS_PLATFORM_API_BASE=https://xyence.io EMS_OIDC_APP_ID=ems.platform EMS_OIDC_ENABLED=true "
                "EMS_JWT_SECRET=\"${EMS_JWT_SECRET:-dev-secret-change-me}\" "
                "docker compose -f apps/ems-stack/docker-compose.yml up -d --build --remove-orphans",
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
                    deploy_workdir = f"{fallback_root}/xyn-api"
                    deploy_compose_file = "apps/ems-stack/docker-compose.yml"
                    cert_dir = "/opt/xyence/certs/current"
                    acme_webroot = "/opt/xyence/acme-webroot"
                else:
                    fallback_error = "source-build fallback failed"
            except Exception as fallback_exc:
                fallback_error = str(fallback_exc)
        if deployment.status != "succeeded":
            deployment.status = "failed"
            deployment.error_message = fallback_error or str(exc)
    if deployment.status == "running":
        deployment.status = "succeeded"
    if deployment.status == "succeeded" and expects_tls:
        tls_mode = str(((release_target.tls_json if release_target else {}) or {}).get("mode", "nginx+acme")).lower()
        if tls_mode == "host-ingress":
            fqdn = (release_target.fqdn if release_target else "") or os.environ.get("EMS_PUBLIC_FQDN", "")
            if not fqdn:
                deployment.status = "failed"
                deployment.error_message = "tls_config_missing: fqdn required"
                execution["status"] = "failed"
                execution["error"] = {"code": "tls_config_missing", "message": deployment.error_message}
            else:
                ok, detail = _verify_public_https_from_backend(fqdn)
                if not ok:
                    deployment.status = "failed"
                    deployment.error_message = f"verify_public_https_failed: {detail}"
                    execution["status"] = "failed"
                    execution["error"] = {
                        "code": "verify_public_https_failed",
                        "message": "Public HTTPS verification failed",
                        "detail": detail,
                    }
        elif tls_mode not in {"nginx+acme", "acme_http01"}:
            deployment.status = "failed"
            deployment.error_message = "tls_not_supported: unsupported tls mode"
            execution["status"] = "failed"
            execution["error"] = {"code": "tls_not_supported", "message": deployment.error_message}
        else:
            fqdn = (release_target.fqdn if release_target else "") or os.environ.get("EMS_PUBLIC_FQDN", "")
            acme_email = (
                str(((release_target.tls_json if release_target else {}) or {}).get("acme_email", "")).strip()
                or os.environ.get("XYENCE_ACME_EMAIL", "")
            )
            if not fqdn or not acme_email:
                deployment.status = "failed"
                deployment.error_message = "tls_config_missing: fqdn and acme_email required"
                execution["status"] = "failed"
                execution["error"] = {"code": "tls_config_missing", "message": deployment.error_message}
            else:
                tls_steps = _build_tls_steps(
                    fqdn=fqdn,
                    acme_email=acme_email,
                    compose_file=deploy_compose_file,
                    workdir=deploy_workdir,
                    cert_dir=cert_dir,
                    acme_webroot=acme_webroot,
                    expected_ip=instance.public_ip or "",
                )
                for step in tls_steps:
                    step_record: Dict[str, Any] = {"name": step.get("name") or "tls_step", "commands": []}
                    for command in step.get("commands") or []:
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
                            error_code = _extract_tls_error_code(stderr)
                            deployment.status = "failed"
                            deployment.error_message = f"{error_code}: tls step failed"
                            execution["status"] = "failed"
                            execution["error"] = {
                                "code": error_code,
                                "message": "TLS flow failed",
                                "detail": stderr[-800:],
                            }
                            execution["failed_command"] = command_record
                            break
                    execution["steps"].append(step_record)
                    if deployment.status == "failed":
                        break
                if deployment.status == "succeeded":
                    ok, detail = _verify_public_https_from_backend(fqdn)
                    if not ok:
                        deployment.status = "failed"
                        deployment.error_message = f"verify_public_https_failed: {detail}"
                        execution["status"] = "failed"
                        execution["error"] = {
                            "code": "verify_public_https_failed",
                            "message": "Public HTTPS verification failed",
                            "detail": detail,
                        }
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
