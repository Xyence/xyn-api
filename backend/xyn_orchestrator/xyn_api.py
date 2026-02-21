import base64
import json
import logging
import os
import re
import html
import secrets
import time
import uuid
import hashlib
import fnmatch
from functools import wraps
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit, quote
from pathlib import Path
from typing import Any, Dict, Optional, List, Set, Tuple

import requests
import boto3
from authlib.jose import JsonWebKey, jwt
from django.core.paginator import Paginator
from django.db import models, transaction
from django.http import HttpRequest, JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.text import slugify
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model, login
from jsonschema import Draft202012Validator

from xyence.middleware import _get_or_create_user_from_claims, _verify_oidc_token

from .blueprints import (
    _async_mode,
    _build_context_artifacts,
    _enqueue_job,
    _enqueue_release_build,
    _recommended_context_pack_ids,
    internal_release_target_check_drift,
    internal_release_target_deploy_latest,
    internal_release_target_rollback_last_success,
    _require_staff,
    _resolve_context_pack_list,
    _write_run_artifact,
    _write_run_summary,
    instantiate_blueprint,
)
from .models import (
    Blueprint,
    BlueprintRevision,
    BlueprintDraftSession,
    DraftSessionVoiceNote,
    VoiceNote,
    Bundle,
    ContextPack,
    DevTask,
    Environment,
    EnvironmentAppState,
    Module,
    ProvisionedInstance,
    Registry,
    ReleasePlan,
    ReleasePlanDeployment,
    Release,
    Run,
    RunArtifact,
    RunCommandExecution,
    ReleaseTarget,
    IdentityProvider,
    AppOIDCClient,
    SecretStore,
    SecretRef,
    RoleBinding,
    UserIdentity,
    Workspace,
    WorkspaceMembership,
    ArtifactType,
    Artifact,
    ArtifactRevision,
    ArtifactEvent,
    ArtifactLink,
    ArtifactExternalRef,
    ArtifactReaction,
    ArtifactComment,
    Tenant,
    Contact,
    TenantMembership,
    BrandProfile,
    PlatformBranding,
    AppBrandingOverride,
    Device,
    DraftAction,
    ActionVerifierEvidence,
    RatificationEvent,
    ExecutionReceipt,
    DraftActionEvent,
    Deployment,
    AuditLog,
    ModelProvider,
    ModelConfig,
    AgentPurpose,
    ProviderCredential,
    AgentDefinition,
    AgentDefinitionPurpose,
    PlatformConfigDocument,
    Report,
    ReportAttachment,
)
from .module_registry import maybe_sync_modules_from_registry
from .deployments import (
    compute_idempotency_base,
    execute_release_plan_deploy,
    infer_app_id,
    maybe_trigger_rollback,
    load_release_plan_json,
)
from .oidc import (
    app_client_to_payload,
    generate_pkce_pair,
    get_discovery_doc,
    get_jwks,
    provider_to_payload,
    resolve_app_client,
    resolve_secret_ref as resolve_oidc_secret_ref,
)
from .secret_stores import SecretStoreError, normalize_secret_logical_name, write_secret_value
from .storage.registry import StorageProviderRegistry
from .notifications.registry import NotifierRegistry
from .ai_runtime import (
    AiConfigError,
    AiInvokeError,
    decrypt_api_key,
    encrypt_api_key,
    ensure_default_ai_seeds,
    invoke_model,
    mask_secret,
    resolve_ai_config,
)

PLATFORM_ROLE_IDS = {"platform_admin", "platform_architect", "platform_operator", "app_user"}
DOC_ARTIFACT_TYPE_SLUG = "doc_page"


def _parse_json(request: HttpRequest) -> Dict[str, Any]:
    if request.body:
        try:
            return json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _normalize_group_role_mapping_entries(raw_mappings: Any) -> list[Dict[str, str]]:
    if raw_mappings is None:
        return []
    if not isinstance(raw_mappings, list):
        return []
    mappings: list[Dict[str, str]] = []
    for item in raw_mappings:
        if not isinstance(item, dict):
            continue
        remote = str(item.get("remote_group_name") or item.get("remoteGroupName") or "").strip()
        role_id = str(item.get("xyn_role_id") or item.get("xynRoleId") or "").strip()
        mappings.append(
            {
                "remote_group_name": remote,
                "xyn_role_id": role_id,
            }
        )
    return mappings


def _validate_group_role_mappings(fallback_role: str, mappings: Any) -> list[str]:
    errors: list[str] = []
    if fallback_role and fallback_role not in PLATFORM_ROLE_IDS:
        errors.append(f"fallback_default_role_id must be one of: {', '.join(sorted(PLATFORM_ROLE_IDS))}")
    if mappings is None:
        return errors
    if not isinstance(mappings, list):
        errors.append("group_role_mappings must be a list")
        return errors
    seen_remote_groups: set[str] = set()
    for idx, entry in enumerate(mappings):
        if not isinstance(entry, dict):
            errors.append(f"group_role_mappings[{idx}] must be an object")
            continue
        remote_group_name = str(entry.get("remote_group_name") or entry.get("remoteGroupName") or "").strip()
        role_id = str(entry.get("xyn_role_id") or entry.get("xynRoleId") or "").strip()
        if not remote_group_name:
            errors.append(f"group_role_mappings[{idx}].remote_group_name is required")
        elif remote_group_name in seen_remote_groups:
            errors.append(f"group_role_mappings[{idx}].remote_group_name must be unique per provider")
        else:
            seen_remote_groups.add(remote_group_name)
        if not role_id:
            errors.append(f"group_role_mappings[{idx}].xyn_role_id is required")
        elif role_id not in PLATFORM_ROLE_IDS:
            errors.append(
                f"group_role_mappings[{idx}].xyn_role_id must be one of: {', '.join(sorted(PLATFORM_ROLE_IDS))}"
            )
    return errors


def _load_schema_local(name: str) -> Dict[str, Any]:
    base_dir = Path(__file__).resolve().parents[1]
    path = base_dir / "schemas" / name
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _validate_release_target_payload(payload: Dict[str, Any]) -> list[str]:
    schema = _load_schema_local("release_target.v1.schema.json")
    validator = Draft202012Validator(schema)
    errors = []
    for error in sorted(validator.iter_errors(payload), key=lambda e: e.path):
        path = ".".join(str(p) for p in error.path) if error.path else "root"
        errors.append(f"{path}: {error.message}")
    tls_mode = str((payload.get("tls") or {}).get("mode") or "").strip().lower()
    if tls_mode == "nginx+acme" and not (payload.get("tls") or {}).get("acme_email"):
        errors.append("tls.acme_email: required when tls.mode is nginx+acme")
    if tls_mode == "host-ingress":
        ingress = payload.get("ingress") or {}
        routes = ingress.get("routes") if isinstance(ingress, dict) else None
        if not isinstance(routes, list) or not routes:
            errors.append("ingress.routes: required when tls.mode is host-ingress")
        if not (payload.get("tls") or {}).get("acme_email"):
            errors.append("tls.acme_email: required when tls.mode is host-ingress")
    fqdn = payload.get("fqdn") or ""
    if " " in fqdn or "." not in fqdn:
        errors.append("fqdn: must be a valid hostname")
    secret_refs = payload.get("secret_refs") or []
    name_re = re.compile(r"^[A-Z0-9_]+$")
    for idx, ref in enumerate(secret_refs):
        name = (ref or {}).get("name") or ""
        value = (ref or {}).get("ref") or ""
        if not name_re.match(name):
            errors.append(f"secret_refs[{idx}].name: must match [A-Z0-9_]+")
        if not (
            value.startswith("ssm:")
            or value.startswith("ssm-arn:")
            or value.startswith("secretsmanager:")
            or value.startswith("secretsmanager-arn:")
        ):
            errors.append(
                f"secret_refs[{idx}].ref: must start with ssm:/, ssm-arn:, secretsmanager:/, or secretsmanager-arn:"
            )
    return errors


def _validate_schema_payload(payload: Dict[str, Any], schema_name: str) -> list[str]:
    schema = _load_schema_local(schema_name)
    validator = Draft202012Validator(schema)
    errors = []
    for error in sorted(validator.iter_errors(payload), key=lambda e: e.path):
        path = ".".join(str(p) for p in error.path) if error.path else "root"
        errors.append(f"{path}: {error.message}")
    return errors


def _normalize_release_target_payload(
    payload: Dict[str, Any], blueprint_id: str, target_id: Optional[str] = None
) -> Dict[str, Any]:
    dns = payload.get("dns") or {}
    runtime = payload.get("runtime") or {}
    tls = payload.get("tls") or {}
    ingress = payload.get("ingress") or {}
    normalized = {
        "schema_version": "release_target.v1",
        "id": target_id or payload.get("id") or str(uuid.uuid4()),
        "blueprint_id": str(blueprint_id),
        "name": payload.get("name") or "",
        "environment": payload.get("environment") or "",
        "target_instance_id": payload.get("target_instance_id") or "",
        "fqdn": payload.get("fqdn") or "",
        "dns": {
            "provider": dns.get("provider") or "route53",
            "zone_name": dns.get("zone_name") or "",
            "zone_id": dns.get("zone_id") or "",
            "record_type": dns.get("record_type") or "A",
            "ttl": dns.get("ttl") or 60,
        },
        "runtime": {
            "type": runtime.get("type") or "docker-compose",
            "transport": runtime.get("transport") or "ssm",
            "remote_root": runtime.get("remote_root") or "",
            "compose_file_path": runtime.get("compose_file_path") or "",
        },
        "tls": {
            "mode": tls.get("mode") or "none",
            "termination": tls.get("termination") or "",
            "provider": tls.get("provider") or "",
            "acme_email": tls.get("acme_email") or "",
            "expose_http": bool(tls.get("expose_http", True)),
            "expose_https": bool(tls.get("expose_https", True)),
            "redirect_http_to_https": bool(tls.get("redirect_http_to_https", True)),
        },
        "ingress": {
            "network": ingress.get("network") or "xyn-edge",
            "routes": ingress.get("routes") or [],
        },
        "env": payload.get("env") or {},
        "secret_refs": payload.get("secret_refs") or [],
        "auto_generated": bool(payload.get("auto_generated", False)),
        "editable": bool(payload.get("editable", True)),
        "created_at": payload.get("created_at") or timezone.now().isoformat(),
        "updated_at": payload.get("updated_at") or timezone.now().isoformat(),
    }
    return normalized


def _serialize_release_target(target: ReleaseTarget) -> Dict[str, Any]:
    payload = target.config_json or {}
    if not payload:
        target_instance_id = ""
        if target.target_instance_id:
            target_instance_id = str(target.target_instance_id)
        elif target.target_instance_ref:
            target_instance_id = target.target_instance_ref
        payload = {
            "schema_version": "release_target.v1",
            "id": str(target.id),
            "blueprint_id": str(target.blueprint_id),
            "name": target.name,
            "environment": target.environment or "",
            "target_instance_id": target_instance_id,
            "fqdn": target.fqdn,
            "dns": target.dns_json or {},
            "runtime": target.runtime_json or {},
            "tls": target.tls_json or {},
            "ingress": (target.config_json or {}).get("ingress") or {},
            "env": target.env_json or {},
            "secret_refs": target.secret_refs_json or [],
            "auto_generated": bool(target.auto_generated),
            "editable": bool((target.config_json or {}).get("editable", True)),
            "created_at": target.created_at.isoformat() if target.created_at else "",
            "updated_at": target.updated_at.isoformat() if target.updated_at else "",
        }
    payload.setdefault("auto_generated", bool(target.auto_generated))
    payload.setdefault("editable", bool((target.config_json or {}).get("editable", True)))
    return payload


def _blueprint_identifier(blueprint: Blueprint) -> str:
    return f"{blueprint.namespace}.{blueprint.name}"


def _default_release_target_remote_root(blueprint: Blueprint) -> str:
    project_key = _blueprint_identifier(blueprint)
    remote_root_slug = re.sub(r"[^a-z0-9]+", "-", project_key.lower()).strip("-") or "default"
    return f"/opt/xyn/apps/{remote_root_slug}"


def _release_target_remote_root(target: ReleaseTarget, blueprint: Blueprint) -> str:
    runtime = target.runtime_json or {}
    if isinstance(runtime, dict):
        remote_root = str(runtime.get("remote_root") or "").strip()
        if remote_root:
            return remote_root
    cfg_runtime = (target.config_json or {}).get("runtime") if isinstance(target.config_json, dict) else {}
    if isinstance(cfg_runtime, dict):
        remote_root = str(cfg_runtime.get("remote_root") or "").strip()
        if remote_root:
            return remote_root
    return _default_release_target_remote_root(blueprint)


def _build_blueprint_deprovision_plan(
    blueprint: Blueprint,
    release_targets: List[ReleaseTarget],
    *,
    stop_services: bool,
    delete_dns: bool,
    remove_runtime_markers: bool,
    force_mode: bool = False,
) -> Dict[str, Any]:
    warnings: List[str] = []
    can_execute = True
    steps: List[Dict[str, Any]] = []
    affected_targets: List[Dict[str, Any]] = []
    dns_records: List[Dict[str, Any]] = []
    runtime_roots: List[str] = []

    for target in release_targets:
        target_id = str(target.id)
        target_payload = _serialize_release_target(target)
        runtime = target_payload.get("runtime") if isinstance(target_payload.get("runtime"), dict) else {}
        dns_cfg = target_payload.get("dns") if isinstance(target_payload.get("dns"), dict) else {}
        remote_root = _release_target_remote_root(target, blueprint)
        compose_file = str((runtime or {}).get("compose_file_path") or "compose.release.yml")
        runtime_roots.append(remote_root)
        if (stop_services or remove_runtime_markers) and not target.target_instance_id:
            can_execute = False
            warnings.append(
                f"{target.name}: target instance is missing; runtime stop/cleanup cannot be executed."
            )

        zone_id = str((dns_cfg or {}).get("zone_id") or "").strip()
        zone_name = str((dns_cfg or {}).get("zone_name") or "").strip()
        dns_provider = str((dns_cfg or {}).get("provider") or "").strip().lower()
        fqdn = str(target.fqdn or "").strip()
        ownership_proven = bool((target.config_json or {}).get("dns_record_snapshot")) or bool(
            (target.config_json or {}).get("xyn_dns_managed")
        )
        if delete_dns and fqdn:
            dns_records.append(
                {
                    "release_target_id": target_id,
                    "fqdn": fqdn,
                    "provider": dns_provider or "route53",
                    "zone_id": zone_id,
                    "zone_name": zone_name,
                    "ownership_proven": ownership_proven,
                }
            )
            if dns_provider and dns_provider != "route53":
                can_execute = False
                warnings.append(f"{fqdn}: DNS provider '{dns_provider}' is not supported for deprovision delete.")
            if not ownership_proven and not force_mode:
                can_execute = False
                warnings.append(
                    f"{fqdn}: ownership cannot be proven for safe DNS delete. Use force mode or add managed snapshot."
                )

        affected_targets.append(
            {
                "id": target_id,
                "name": target.name,
                "environment": target.environment or "",
                "fqdn": fqdn,
                "target_instance_id": str(target.target_instance_id) if target.target_instance_id else "",
                "remote_root": remote_root,
                "compose_file_path": compose_file,
            }
        )

        steps.append(
            {
                "id": f"deploy.lock_check.{target_id}",
                "title": f"Check deploy lock for {target.name}",
                "capability": "deploy.lock.check",
                "work_item": {
                    "id": f"deploy.lock_check.{target_id}",
                    "title": f"Check deploy lock for {target.name}",
                    "type": "deploy",
                    "context_purpose_override": "operator",
                    "capabilities_required": ["deploy.lock.check"],
                    "config": {"release_target_id": target_id},
                    "repo_targets": [],
                },
            }
        )
        if stop_services:
            steps.append(
                {
                    "id": f"runtime.compose_down_remote.{target_id}",
                    "title": f"Stop runtime stack for {target.name}",
                    "capability": "runtime.compose.down_remote",
                    "work_item": {
                        "id": f"runtime.compose_down_remote.{target_id}",
                        "title": f"Stop runtime stack for {target.name}",
                        "type": "deploy",
                        "context_purpose_override": "operator",
                        "capabilities_required": ["runtime.compose.down_remote"],
                        "config": {
                            "release_target_id": target_id,
                            "target_instance_id": str(target.target_instance_id) if target.target_instance_id else "",
                            "remote_root": remote_root,
                            "compose_file_path": compose_file,
                        },
                        "repo_targets": [],
                    },
                }
            )
        if remove_runtime_markers:
            steps.append(
                {
                    "id": f"runtime.remove_runtime_markers.{target_id}",
                    "title": f"Remove runtime markers for {target.name}",
                    "capability": "runtime.runtime_markers.remove",
                    "work_item": {
                        "id": f"runtime.remove_runtime_markers.{target_id}",
                        "title": f"Remove runtime markers for {target.name}",
                        "type": "deploy",
                        "context_purpose_override": "operator",
                        "capabilities_required": ["runtime.runtime_markers.remove"],
                        "config": {
                            "release_target_id": target_id,
                            "target_instance_id": str(target.target_instance_id) if target.target_instance_id else "",
                            "remote_root": remote_root,
                        },
                        "repo_targets": [],
                    },
                }
            )
        if delete_dns and fqdn:
            steps.append(
                {
                    "id": f"dns.delete_record.route53.{target_id}",
                    "title": f"Delete Route53 record for {fqdn}",
                    "capability": "dns.route53.delete_record",
                    "work_item": {
                        "id": f"dns.delete_record.route53.{target_id}",
                        "title": f"Delete Route53 record for {fqdn}",
                        "type": "deploy",
                        "context_purpose_override": "operator",
                        "capabilities_required": ["dns.route53.delete_record"],
                        "config": {
                            "release_target_id": target_id,
                            "target_instance_id": str(target.target_instance_id) if target.target_instance_id else "",
                            "fqdn": fqdn,
                            "force": bool(force_mode),
                            "dns": {
                                "provider": dns_provider or "route53",
                                "zone_id": zone_id,
                                "zone_name": zone_name,
                                "ownership_proven": ownership_proven,
                            },
                        },
                        "repo_targets": [],
                    },
                }
            )
        steps.append(
            {
                "id": f"verify.deprovision.{target_id}",
                "title": f"Verify deprovision for {target.name}",
                "capability": "runtime.deprovision.verify",
                "work_item": {
                    "id": f"verify.deprovision.{target_id}",
                    "title": f"Verify deprovision for {target.name}",
                    "type": "deploy",
                    "context_purpose_override": "operator",
                    "capabilities_required": ["runtime.deprovision.verify"],
                    "config": {
                        "release_target_id": target_id,
                        "target_instance_id": str(target.target_instance_id) if target.target_instance_id else "",
                        "fqdn": fqdn,
                        "remote_root": remote_root,
                        "delete_dns": bool(delete_dns and fqdn),
                        "force": bool(force_mode),
                        "dns": {
                            "provider": dns_provider or "route53",
                            "zone_id": zone_id,
                            "zone_name": zone_name,
                        },
                    },
                    "repo_targets": [],
                },
            }
        )

    unique_runtime_roots = sorted({root for root in runtime_roots if root})
    return {
        "blueprint_id": str(blueprint.id),
        "blueprint_name": blueprint.name,
        "blueprint_namespace": blueprint.namespace,
        "identifier": _blueprint_identifier(blueprint),
        "generated_at": timezone.now().isoformat(),
        "mode": "force" if force_mode else ("stop_services" if stop_services else "safe"),
        "flags": {
            "stop_services": bool(stop_services),
            "delete_dns": bool(delete_dns),
            "remove_runtime_markers": bool(remove_runtime_markers),
            "can_execute": bool(can_execute),
        },
        "summary": {
            "release_target_count": len(affected_targets),
            "dns_record_count": len(dns_records),
            "runtime_root_count": len(unique_runtime_roots),
            "step_count": len(steps),
        },
        "affected_release_targets": affected_targets,
        "dns_records": dns_records,
        "runtime_roots": unique_runtime_roots,
        "warnings": warnings,
        "steps": steps,
    }


@login_required
def whoami(request: HttpRequest) -> JsonResponse:
    if not request.user.is_authenticated:
        return JsonResponse({"authenticated": False}, status=401)
    return JsonResponse(
        {
            "authenticated": True,
            "username": request.user.get_username(),
            "email": getattr(request.user, "email", ""),
            "is_staff": bool(request.user.is_staff),
            "is_superuser": bool(getattr(request.user, "is_superuser", False)),
        }
    )

def _paginate(request: HttpRequest, qs, key: str) -> JsonResponse:
    page_size = int(request.GET.get("page_size", 20))
    page_number = int(request.GET.get("page", 1))
    paginator = Paginator(qs, page_size)
    page = paginator.get_page(page_number)
    return JsonResponse(
        {
            key: list(page.object_list),
            "count": paginator.count,
            "next": page.next_page_number() if page.has_next() else None,
            "prev": page.previous_page_number() if page.has_previous() else None,
        }
    )


_OIDC_CONFIG: Optional[Dict[str, Any]] = None
_OIDC_CONFIG_TS: float = 0.0


def _get_oidc_config(issuer: str) -> Optional[Dict[str, Any]]:
    global _OIDC_CONFIG, _OIDC_CONFIG_TS
    now = time.time()
    if _OIDC_CONFIG and now - _OIDC_CONFIG_TS < 3600:
        return _OIDC_CONFIG
    try:
        response = requests.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration", timeout=10)
        response.raise_for_status()
        _OIDC_CONFIG = response.json()
        _OIDC_CONFIG_TS = now
        return _OIDC_CONFIG
    except Exception:
        return None


def _resolve_environment(request: HttpRequest) -> Optional[Environment]:
    forwarded_host = request.headers.get("X-Forwarded-Host") or request.headers.get("X-Forwarded-Server")
    host = forwarded_host or request.get_host()
    if host:
        host = host.split(",")[0].strip().split(":")[0].lower()
        environments = list(Environment.objects.all().order_by("name"))
        for env in environments:
            hosts = (env.metadata_json or {}).get("hosts") or []
            if host in [h.lower() for h in hosts]:
                return env
        for env in environments:
            hosts = (env.metadata_json or {}).get("hosts") or []
            for pattern in hosts:
                pattern = str(pattern).lower()
                if pattern == "*":
                    return env
                if "*" in pattern and fnmatch.fnmatch(host, pattern):
                    return env
    session = getattr(request, "session", None)
    env_id = session.get("environment_id") if session else None
    if env_id:
        return Environment.objects.filter(id=env_id).first()
    allow_query = os.environ.get("ALLOW_ENV_QUERY", "").lower() == "true"
    if allow_query:
        env_id = request.GET.get("environment_id")
        if env_id:
            return Environment.objects.filter(id=env_id).first()
    env = Environment.objects.first()
    if env:
        return env
    # Bootstrap a default environment when none exist.
    env_name = os.environ.get("DJANGO_SITE_NAME", "Default")
    slug = "default"
    base_domain = os.environ.get("DJANGO_SITE_DOMAIN", host or "")
    oidc_config = _get_oidc_env_config(Environment(name=env_name, slug=slug)) or {}
    metadata = {"hosts": [host] if host else [], "oidc": oidc_config}
    return Environment.objects.create(
        name=env_name,
        slug=slug,
        base_domain=base_domain,
        aws_region=os.environ.get("AWS_REGION", ""),
        metadata_json=metadata,
    )


def _get_oidc_env_config(env: Environment) -> Optional[Dict[str, Any]]:
    config = (env.metadata_json or {}).get("oidc") or {}
    if not config.get("issuer_url") or not config.get("client_id"):
        issuer = os.environ.get("OIDC_ISSUER", "").strip()
        client_id = os.environ.get("OIDC_CLIENT_ID", "").strip()
        if issuer and client_id:
            return {
                "issuer_url": issuer,
                "client_id": client_id,
                "client_secret_ref": {"ref": "env:OIDC_CLIENT_SECRET"},
                "redirect_uri": os.environ.get("OIDC_REDIRECT_URI", "").strip(),
                "scopes": os.environ.get("OIDC_SCOPES", "openid profile email"),
                "allowed_email_domains": [
                    domain.strip()
                    for domain in os.environ.get("OIDC_ALLOWED_DOMAINS", "").split(",")
                    if domain.strip()
                ],
            }
        return None
    return config


def _normalize_provider_payload(payload: Dict[str, Any]) -> tuple[Dict[str, Any], Dict[str, Any]]:
    client = payload.get("client") or {}
    discovery = payload.get("discovery") or {}
    schema_payload = {
        "type": "oidc.identity_provider",
        "version": "v1",
        "id": payload.get("id") or payload.get("provider_id") or "",
        "displayName": payload.get("display_name") or payload.get("displayName") or "",
        "enabled": payload.get("enabled", True),
        "issuer": payload.get("issuer") or "",
        "discovery": {
            "mode": discovery.get("mode") or "issuer",
            "jwksUri": discovery.get("jwksUri") or discovery.get("jwks_uri"),
            "authorizationEndpoint": discovery.get("authorizationEndpoint")
            or discovery.get("authorization_endpoint"),
            "tokenEndpoint": discovery.get("tokenEndpoint") or discovery.get("token_endpoint"),
            "userinfoEndpoint": discovery.get("userinfoEndpoint") or discovery.get("userinfo_endpoint"),
        },
        "client": {
            "clientId": client.get("client_id") or client.get("clientId") or "",
            "clientSecretRef": client.get("client_secret_ref") or client.get("clientSecretRef"),
        },
        "scopes": payload.get("scopes") or ["openid", "profile", "email"],
        "pkce": payload.get("pkce", True),
        "prompt": payload.get("prompt"),
        "domainRules": payload.get("domain_rules") or payload.get("domainRules") or {},
        "claims": payload.get("claims") or {},
        "audienceRules": payload.get("audience_rules") or payload.get("audienceRules") or {},
        "fallbackDefaultRoleId": payload.get("fallback_default_role_id")
        or payload.get("fallbackDefaultRoleId")
        or None,
        "requireGroupMatch": bool(payload.get("require_group_match") or payload.get("requireGroupMatch") or False),
        "groupClaimPath": str(payload.get("group_claim_path") or payload.get("groupClaimPath") or "groups").strip()
        or "groups",
        "groupRoleMappings": _normalize_group_role_mapping_entries(
            payload.get("group_role_mappings") or payload.get("groupRoleMappings") or []
        ),
    }
    model_fields = {
        "id": schema_payload["id"],
        "display_name": schema_payload["displayName"],
        "enabled": bool(schema_payload.get("enabled", True)),
        "issuer": schema_payload["issuer"],
        "discovery_json": schema_payload.get("discovery") or {},
        "client_id": schema_payload["client"]["clientId"],
        "client_secret_ref_json": schema_payload["client"].get("clientSecretRef"),
        "scopes_json": schema_payload.get("scopes"),
        "pkce_enabled": bool(schema_payload.get("pkce", True)),
        "prompt": schema_payload.get("prompt") or "",
        "domain_rules_json": schema_payload.get("domainRules") or {},
        "claims_json": schema_payload.get("claims") or {},
        "audience_rules_json": schema_payload.get("audienceRules") or {},
        "fallback_default_role_id": schema_payload.get("fallbackDefaultRoleId") or None,
        "require_group_match": bool(schema_payload.get("requireGroupMatch", False)),
        "group_claim_path": schema_payload.get("groupClaimPath") or "groups",
        "group_role_mappings_json": schema_payload.get("groupRoleMappings") or [],
    }
    return model_fields, schema_payload


def _normalize_app_client_payload(payload: Dict[str, Any]) -> tuple[Dict[str, Any], Dict[str, Any]]:
    schema_payload = {
        "type": "oidc.app_client",
        "version": "v1",
        "appId": payload.get("app_id") or payload.get("appId") or "",
        "loginMode": payload.get("login_mode") or payload.get("loginMode") or "redirect",
        "defaultProviderId": payload.get("default_provider_id") or payload.get("defaultProviderId") or "",
        "allowedProviderIds": payload.get("allowed_provider_ids") or payload.get("allowedProviderIds") or [],
        "redirectUris": payload.get("redirect_uris") or payload.get("redirectUris") or [],
        "postLogoutRedirectUris": payload.get("post_logout_redirect_uris")
        or payload.get("postLogoutRedirectUris")
        or [],
        "session": payload.get("session") or {},
        "tokenValidation": payload.get("token_validation") or payload.get("tokenValidation") or {},
    }
    model_fields = {
        "app_id": schema_payload["appId"],
        "login_mode": schema_payload.get("loginMode") or "redirect",
        "default_provider_id": schema_payload.get("defaultProviderId") or None,
        "allowed_providers_json": schema_payload.get("allowedProviderIds") or [],
        "redirect_uris_json": schema_payload.get("redirectUris") or [],
        "post_logout_redirect_uris_json": schema_payload.get("postLogoutRedirectUris") or [],
        "session_json": schema_payload.get("session") or {},
        "token_validation_json": schema_payload.get("tokenValidation") or {},
    }
    return model_fields, schema_payload


def _validate_provider_payload(payload: Dict[str, Any]) -> list[str]:
    fields, schema_payload = _normalize_provider_payload(payload)
    errors = _validate_schema_payload(schema_payload, "oidc_identity_provider.v1.schema.json")
    errors.extend(
        _validate_group_role_mappings(
            str(fields.get("fallback_default_role_id") or ""),
            fields.get("group_role_mappings_json"),
        )
    )
    return errors


def _validate_app_client_payload(payload: Dict[str, Any]) -> list[str]:
    _fields, schema_payload = _normalize_app_client_payload(payload)
    errors = _validate_schema_payload(schema_payload, "oidc_app_client.v1.schema.json")
    return errors


def _resolve_secret_ref(ref: Dict[str, Any]) -> Optional[str]:
    value = (ref or {}).get("ref") or ""
    if not value:
        return None
    if value.startswith("env:"):
        name = value[len("env:") :]
        return os.environ.get(name)
    if value.startswith("ssm:"):
        name = value[len("ssm:") :]
        region = (os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "").strip()
        client = boto3.client("ssm", region_name=region) if region else boto3.client("ssm")
        response = client.get_parameter(Name=name, WithDecryption=True)
        return response.get("Parameter", {}).get("Value")
    if value.startswith("ssm-arn:"):
        name = value[len("ssm-arn:") :]
        region = (os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "").strip()
        client = boto3.client("ssm", region_name=region) if region else boto3.client("ssm")
        response = client.get_parameter(Name=name, WithDecryption=True)
        return response.get("Parameter", {}).get("Value")
    if value.startswith("secretsmanager:"):
        name = value[len("secretsmanager:") :]
        region = (os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "").strip()
        client = boto3.client("secretsmanager", region_name=region) if region else boto3.client("secretsmanager")
        response = client.get_secret_value(SecretId=name)
        return response.get("SecretString")
    if value.startswith("secretsmanager-arn:"):
        name = value[len("secretsmanager-arn:") :]
        region = (os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "").strip()
        client = boto3.client("secretsmanager", region_name=region) if region else boto3.client("secretsmanager")
        response = client.get_secret_value(SecretId=name)
        return response.get("SecretString")
    return None


def _decode_id_token(id_token: str, issuer: str, client_id: str, nonce: str) -> Optional[Dict[str, Any]]:
    config = _get_oidc_config(issuer)
    if not config or not config.get("jwks_uri"):
        return None
    jwks = requests.get(config["jwks_uri"], timeout=10).json()
    key_set = JsonWebKey.import_key_set(jwks)
    claims = jwt.decode(
        id_token,
        key_set,
        claims_options={
            "iss": {"value": issuer},
            "aud": {"value": client_id},
            "exp": {"essential": True},
            "nonce": {"value": nonce},
        },
    )
    claims.validate()
    return dict(claims)


def _require_authenticated(request: HttpRequest) -> Optional[UserIdentity]:
    identity_id = request.session.get("user_identity_id")
    if not identity_id:
        return None
    return UserIdentity.objects.filter(id=identity_id).first()


def _require_platform_architect(request: HttpRequest) -> Optional[JsonResponse]:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _is_platform_architect(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    request.user_identity = identity  # type: ignore[attr-defined]
    return None


def _get_roles(identity: UserIdentity) -> List[str]:
    return list(
        RoleBinding.objects.filter(user_identity=identity)
        .values_list("role", flat=True)
    )


def _is_platform_admin(identity: UserIdentity) -> bool:
    return RoleBinding.objects.filter(user_identity=identity, role="platform_admin").exists()


def _has_platform_role(identity: UserIdentity, roles: List[str]) -> bool:
    return RoleBinding.objects.filter(user_identity=identity, role__in=roles).exists()


def _is_platform_architect(identity: UserIdentity) -> bool:
    return _has_platform_role(identity, ["platform_architect", "platform_admin"])


def _can_manage_docs(identity: UserIdentity) -> bool:
    return _has_platform_role(identity, ["platform_architect", "platform_admin"])


def _docs_workspace() -> Workspace:
    workspace = Workspace.objects.filter(slug="platform-builder").first()
    if workspace:
        return workspace
    workspace, _ = Workspace.objects.get_or_create(
        slug="platform-builder",
        defaults={"name": "Platform Builder", "description": "Platform governance and operator documentation"},
    )
    return workspace


def _ensure_doc_artifact_type() -> ArtifactType:
    artifact_type, _ = ArtifactType.objects.get_or_create(
        slug=DOC_ARTIFACT_TYPE_SLUG,
        defaults={
            "name": "Doc Page",
            "description": "Route-bound platform documentation",
            "icon": "FileText",
            "schema_json": {"fields": ["body_markdown", "tags", "route_bindings"]},
        },
    )
    return artifact_type


def _normalize_doc_route_bindings(raw: Any) -> list[str]:
    values: list[str] = []
    if not isinstance(raw, list):
        return values
    seen: set[str] = set()
    for entry in raw:
        route_id = str(entry or "").strip()
        if not route_id:
            continue
        if route_id in seen:
            continue
        seen.add(route_id)
        values.append(route_id)
    return values


def _normalize_doc_tags(raw: Any) -> list[str]:
    values: list[str] = []
    if not isinstance(raw, list):
        return values
    seen: set[str] = set()
    for entry in raw:
        tag = str(entry or "").strip().lower()
        if not tag:
            continue
        if tag in seen:
            continue
        seen.add(tag)
        values.append(tag)
    return values


def _can_view_doc(identity: UserIdentity, artifact: Artifact) -> bool:
    if _can_manage_docs(identity):
        return True
    if artifact.status != "published":
        return False
    return artifact.visibility in {"public", "team"}


def _serialize_doc_page(artifact: Artifact, revision: Optional[ArtifactRevision] = None) -> Dict[str, Any]:
    latest = revision or _latest_artifact_revision(artifact)
    content = dict((latest.content_json if latest else {}) or {})
    scope = dict(artifact.scope_json or {})
    return {
        "id": str(artifact.id),
        "artifact_id": str(artifact.id),
        "workspace_id": str(artifact.workspace_id),
        "type": artifact.type.slug,
        "title": artifact.title,
        "slug": _artifact_slug(artifact),
        "status": artifact.status,
        "visibility": artifact.visibility,
        "route_bindings": _normalize_doc_route_bindings(scope.get("route_bindings")),
        "tags": _normalize_doc_tags(content.get("tags")),
        "body_markdown": str(content.get("body_markdown") or ""),
        "summary": str(content.get("summary") or ""),
        "version": artifact.version,
        "created_at": artifact.created_at,
        "updated_at": artifact.updated_at,
        "published_at": artifact.published_at,
        "created_by": str(artifact.author_id) if artifact.author_id else None,
        "updated_by": str(latest.created_by_id) if latest and latest.created_by_id else None,
        "updated_by_email": latest.created_by.email if latest and latest.created_by else None,
    }


WORKSPACE_ROLE_RANK = {
    "reader": 1,
    "contributor": 2,
    "publisher": 3,
    "moderator": 4,
    "admin": 5,
}


def _workspace_membership(identity: UserIdentity, workspace_id: str) -> Optional[WorkspaceMembership]:
    return WorkspaceMembership.objects.filter(workspace_id=workspace_id, user_identity=identity).first()


def _workspace_has_role(identity: UserIdentity, workspace_id: str, minimum_role: str) -> bool:
    membership = _workspace_membership(identity, workspace_id)
    if not membership:
        return False
    return WORKSPACE_ROLE_RANK.get(membership.role, 0) >= WORKSPACE_ROLE_RANK.get(minimum_role, 99)


def _workspace_has_termination_authority(identity: UserIdentity, workspace_id: str) -> bool:
    membership = _workspace_membership(identity, workspace_id)
    if not membership:
        return False
    return bool(membership.termination_authority or membership.role == "admin")


def _next_artifact_revision_number(artifact: Artifact) -> int:
    latest = ArtifactRevision.objects.filter(artifact=artifact).aggregate(max_no=models.Max("revision_number")).get("max_no")
    return int(latest or 0) + 1


def _record_artifact_event(
    artifact: Artifact,
    event_type: str,
    actor: Optional[UserIdentity],
    payload: Optional[Dict[str, Any]] = None,
) -> ArtifactEvent:
    return ArtifactEvent.objects.create(
        artifact=artifact,
        event_type=event_type,
        actor=actor,
        payload_json=payload or {},
    )


def _control_plane_app_ids() -> set[str]:
    return {"xyn-api", "xyn-ui", "xyn-seed", "xyn-worker", "core.xyn-api", "core.xyn-ui", "core.xyn-seed"}


def _is_control_plane_release(release: Release) -> bool:
    if release.blueprint_id and release.blueprint:
        fqn = f"{release.blueprint.namespace}.{release.blueprint.name}"
        return fqn in _control_plane_app_ids() or release.blueprint.name in _control_plane_app_ids()
    if release.release_plan_id and release.release_plan:
        target = (release.release_plan.target_fqn or "").strip()
        return target in _control_plane_app_ids()
    return False


def _is_control_plane_plan(plan: ReleasePlan) -> bool:
    target = (plan.target_fqn or "").strip()
    if target in _control_plane_app_ids():
        return True
    if plan.blueprint_id and plan.blueprint:
        fqn = f"{plan.blueprint.namespace}.{plan.blueprint.name}"
        return fqn in _control_plane_app_ids() or plan.blueprint.name in _control_plane_app_ids()
    return False


def _audit_action(message: str, metadata: Optional[Dict[str, Any]] = None, request: Optional[HttpRequest] = None) -> None:
    try:
        AuditLog.objects.create(
            message=message,
            metadata_json=metadata or {},
            created_by=request.user if request and getattr(request, "user", None) and request.user.is_authenticated else None,
        )
    except Exception:
        return


def _tenant_role_rank(role: str) -> int:
    order = {"tenant_viewer": 1, "tenant_operator": 2, "tenant_admin": 3}
    return order.get(role, 0)


EMS_ACTION_TYPES: Dict[str, str] = {
    "device.reboot": "write_execute",
    "device.factory_reset": "account_security_write",
    "device.push_config": "write_execute",
    "credential_ref.attach": "account_security_write",
    "adapter.enable": "account_security_write",
    "adapter.configure": "account_security_write",
}


def _tenant_membership(identity: UserIdentity, tenant_id: str) -> Optional[TenantMembership]:
    return TenantMembership.objects.filter(
        tenant_id=tenant_id,
        user_identity=identity,
        status="active",
    ).first()


def _tenant_role_to_ems_role(tenant_role: str) -> str:
    role = str(tenant_role or "")
    if role == "tenant_admin":
        return "ems_admin"
    if role == "tenant_operator":
        return "ems_operator"
    return "ems_viewer"


def _ems_role_rank(ems_role: str) -> int:
    return {"ems_viewer": 1, "ems_operator": 2, "ems_admin": 3}.get(ems_role, 0)


def _ems_role_allowed(ems_role: str, allowed_roles: List[str]) -> bool:
    return str(ems_role or "") in {str(item or "") for item in (allowed_roles or [])}


def _resolve_action_policy(
    tenant: Tenant,
    action_type: str,
    instance_ref: str = "",
) -> Dict[str, Any]:
    default_policy: Dict[str, Dict[str, Any]] = {
        "device.reboot": {
            "requires_confirmation": True,
            "requires_ratification": False,
            "allowed_roles_to_request": ["ems_operator", "ems_admin"],
            "allowed_roles_to_ratify": ["ems_admin"],
            "allowed_roles_to_execute": ["ems_admin", "system"],
        },
        "device.factory_reset": {
            "requires_confirmation": True,
            "requires_ratification": True,
            "allowed_roles_to_request": ["ems_admin"],
            "allowed_roles_to_ratify": ["ems_admin"],
            "allowed_roles_to_execute": ["ems_admin", "system"],
        },
        "device.push_config": {
            "requires_confirmation": True,
            "requires_ratification": True,
            "allowed_roles_to_request": ["ems_admin"],
            "allowed_roles_to_ratify": ["ems_admin"],
            "allowed_roles_to_execute": ["ems_admin", "system"],
        },
        "credential_ref.attach": {
            "requires_confirmation": True,
            "requires_ratification": True,
            "allowed_roles_to_request": ["ems_admin"],
            "allowed_roles_to_ratify": ["ems_admin"],
            "allowed_roles_to_execute": ["ems_admin", "system"],
        },
        "adapter.enable": {
            "requires_confirmation": True,
            "requires_ratification": True,
            "allowed_roles_to_request": ["ems_admin"],
            "allowed_roles_to_ratify": ["ems_admin"],
            "allowed_roles_to_execute": ["ems_admin", "system"],
        },
        "adapter.configure": {
            "requires_confirmation": True,
            "requires_ratification": True,
            "allowed_roles_to_request": ["ems_admin"],
            "allowed_roles_to_ratify": ["ems_admin"],
            "allowed_roles_to_execute": ["ems_admin", "system"],
        },
    }
    merged = dict(default_policy.get(action_type) or {})
    metadata = tenant.metadata_json if isinstance(tenant.metadata_json, dict) else {}
    action_policies = metadata.get("ems_action_policies") if isinstance(metadata.get("ems_action_policies"), dict) else {}
    instance_policies = (
        metadata.get("ems_action_policies_by_instance")
        if isinstance(metadata.get("ems_action_policies_by_instance"), dict)
        else {}
    )
    tenant_override = action_policies.get(action_type) if isinstance(action_policies.get(action_type), dict) else {}
    instance_override = {}
    if instance_ref:
        item = instance_policies.get(instance_ref)
        if isinstance(item, dict) and isinstance(item.get(action_type), dict):
            instance_override = item.get(action_type) or {}
    merged.update(tenant_override)
    merged.update(instance_override)
    merged["action_type"] = action_type
    return merged


def _redact_sensitive_json(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: Dict[str, Any] = {}
        for key, raw in value.items():
            lowered = str(key).lower()
            if any(token in lowered for token in ("password", "secret", "token", "credential", "apikey", "api_key")):
                redacted[str(key)] = "***redacted***"
            else:
                redacted[str(key)] = _redact_sensitive_json(raw)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive_json(item) for item in value]
    return value


def _record_draft_action_event(
    action: DraftAction,
    event_type: str,
    actor: Optional[UserIdentity],
    from_status: str = "",
    to_status: str = "",
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    DraftActionEvent.objects.create(
        draft_action=action,
        event_type=event_type,
        actor=actor,
        from_status=from_status,
        to_status=to_status,
        payload_json=payload or {},
    )


def _transition_draft_action(
    action: DraftAction,
    new_status: str,
    actor: Optional[UserIdentity],
    event_type: str,
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    previous = action.status
    action.status = new_status
    action.save(update_fields=["status", "updated_at"])
    _record_draft_action_event(action, event_type, actor, previous, new_status, payload or {})


def _serialize_receipt(receipt: ExecutionReceipt) -> Dict[str, Any]:
    return {
        "id": str(receipt.id),
        "draft_action_id": str(receipt.draft_action_id),
        "executed_at": receipt.executed_at,
        "executed_by": str(receipt.executed_by_id) if receipt.executed_by_id else None,
        "adapter_key": receipt.adapter_key,
        "request_payload_redacted_json": receipt.request_payload_redacted_json,
        "response_redacted_json": receipt.response_redacted_json,
        "outcome": receipt.outcome,
        "error_code": receipt.error_code,
        "error_message": receipt.error_message,
        "logs_ref": receipt.logs_ref,
    }


def _serialize_draft_action(action: DraftAction) -> Dict[str, Any]:
    return {
        "id": str(action.id),
        "tenant_id": str(action.tenant_id),
        "device_id": str(action.device_id) if action.device_id else None,
        "instance_ref": action.instance_ref or None,
        "action_type": action.action_type,
        "action_class": action.action_class,
        "params_json": action.params_json or {},
        "status": action.status,
        "requested_by": str(action.requested_by_id) if action.requested_by_id else None,
        "custodian_id": str(action.custodian_id) if action.custodian_id else None,
        "last_error_code": action.last_error_code or "",
        "last_error_message": action.last_error_message or "",
        "provenance_json": action.provenance_json or {},
        "created_at": action.created_at,
        "updated_at": action.updated_at,
    }


def _action_timeline(action: DraftAction) -> List[Dict[str, Any]]:
    return [
        {
            "id": str(item.id),
            "event_type": item.event_type,
            "from_status": item.from_status,
            "to_status": item.to_status,
            "actor_id": str(item.actor_id) if item.actor_id else None,
            "payload_json": item.payload_json or {},
            "created_at": item.created_at,
        }
        for item in action.events.all().order_by("created_at")
    ]


def _execute_draft_action(
    action: DraftAction,
    actor: Optional[UserIdentity] = None,
) -> Tuple[bool, ExecutionReceipt]:
    _transition_draft_action(action, "executing", actor, "action_executing")
    adapter_key = str((action.params_json or {}).get("adapter_key") or "ems-gov-device-adapter")
    requested_payload = {
        "device_id": str(action.device_id) if action.device_id else None,
        "action_type": action.action_type,
        "params": action.params_json or {},
    }
    redacted_request = _redact_sensitive_json(requested_payload)
    try:
        if action.action_type != "device.reboot":
            raise RuntimeError("action_type_not_supported")
        simulate_failure = bool((action.params_json or {}).get("simulate_failure"))
        if simulate_failure:
            raise RuntimeError("simulated_reboot_failure")
        adapter_response = {
            "accepted": True,
            "action": action.action_type,
            "device_id": str(action.device_id) if action.device_id else None,
            "provider": adapter_key,
            "execution_mode": "inline",
        }
        receipt = ExecutionReceipt.objects.create(
            draft_action=action,
            executed_by=actor,
            adapter_key=adapter_key,
            request_payload_redacted_json=redacted_request,
            response_redacted_json=_redact_sensitive_json(adapter_response),
            outcome="success",
        )
        action.last_error_code = ""
        action.last_error_message = ""
        action.save(update_fields=["last_error_code", "last_error_message", "updated_at"])
        _transition_draft_action(action, "succeeded", actor, "action_succeeded", {"receipt_id": str(receipt.id)})
        return True, receipt
    except Exception as exc:
        error_code = "execution_failed"
        error_message = str(exc)
        failure_response = {"error": error_message}
        receipt = ExecutionReceipt.objects.create(
            draft_action=action,
            executed_by=actor,
            adapter_key=adapter_key,
            request_payload_redacted_json=redacted_request,
            response_redacted_json=_redact_sensitive_json(failure_response),
            outcome="failure",
            error_code=error_code,
            error_message=error_message,
        )
        action.last_error_code = error_code
        action.last_error_message = error_message
        action.save(update_fields=["last_error_code", "last_error_message", "updated_at"])
        _transition_draft_action(
            action,
            "failed",
            actor,
            "action_failed",
            {"receipt_id": str(receipt.id), "error_code": error_code, "error_message": error_message},
        )
        return False, receipt


def _require_tenant_access(identity: UserIdentity, tenant_id: str, minimum_role: str) -> bool:
    membership = _tenant_membership(identity, tenant_id)
    if not membership:
        return False
    return _tenant_role_rank(membership.role) >= _tenant_role_rank(minimum_role)


def _parse_bool_param(raw: Optional[str], default: bool = False) -> bool:
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _extract_tenant_hint(payload: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(payload, dict):
        return None
    direct = payload.get("tenant_id") or payload.get("tenantId")
    if direct:
        return str(direct)
    metadata = payload.get("metadata") or payload.get("metadata_json")
    if isinstance(metadata, dict):
        direct = metadata.get("tenant_id") or metadata.get("tenantId")
        if direct:
            return str(direct)
    env = payload.get("env")
    if isinstance(env, dict):
        for key in ("TENANT_ID", "tenant_id", "tenantId"):
            value = env.get(key)
            if value:
                return str(value)
    return None


def _serialize_secret_store(store: SecretStore) -> Dict[str, Any]:
    return {
        "id": str(store.id),
        "name": store.name,
        "kind": store.kind,
        "is_default": bool(store.is_default),
        "config_json": store.config_json or {},
        "created_at": store.created_at,
        "updated_at": store.updated_at,
    }


def _serialize_secret_ref(ref: SecretRef) -> Dict[str, Any]:
    return {
        "id": str(ref.id),
        "name": ref.name,
        "scope_kind": ref.scope_kind,
        "scope_id": str(ref.scope_id) if ref.scope_id else None,
        "store_id": str(ref.store_id),
        "store_name": ref.store.name if ref.store_id else "",
        "external_ref": ref.external_ref,
        "type": ref.type,
        "version": ref.version,
        "description": ref.description or "",
        "metadata_json": ref.metadata_json or {},
        "updated_at": ref.updated_at,
        "created_at": ref.created_at,
    }


def _resolve_secret_scope_path(scope_kind: str, scope_id: Optional[str], identity: UserIdentity) -> Optional[str]:
    if scope_kind == "platform":
        return None
    if scope_kind == "tenant":
        if not scope_id:
            return None
        tenant = Tenant.objects.filter(id=scope_id).first()
        if tenant and tenant.slug:
            return tenant.slug
        return scope_id
    if scope_kind == "user":
        return scope_id or str(identity.id)
    if scope_kind == "team":
        return scope_id
    return scope_id


def _scope_read_allowed(identity: UserIdentity, scope_kind: str, scope_id: Optional[str]) -> bool:
    if _is_platform_admin(identity):
        return True
    if scope_kind == "platform":
        return False
    if scope_kind == "tenant":
        if not scope_id:
            return False
        return _require_tenant_access(identity, scope_id, "tenant_admin")
    if scope_kind == "user":
        return bool(scope_id and str(scope_id) == str(identity.id))
    return False


def _scope_write_allowed(identity: UserIdentity, scope_kind: str, scope_id: Optional[str]) -> bool:
    if scope_kind == "platform":
        return _is_platform_admin(identity)
    return _scope_read_allowed(identity, scope_kind, scope_id)


def _resolve_secret_store(store_id: Optional[str]) -> Optional[SecretStore]:
    if store_id:
        return SecretStore.objects.filter(id=store_id).first()
    return SecretStore.objects.filter(is_default=True).first()


def _create_or_update_secret_ref(
    *,
    identity: UserIdentity,
    user,
    name: str,
    scope_kind: str,
    scope_id: Optional[str],
    store: SecretStore,
    value: str,
    description: str = "",
    existing_ref: Optional[SecretRef] = None,
) -> SecretRef:
    logical_name = normalize_secret_logical_name(name)
    if not logical_name:
        raise SecretStoreError("name is required")
    if not _scope_write_allowed(identity, scope_kind, scope_id):
        raise PermissionError("forbidden")
    normalized_scope_id: Optional[str] = scope_id
    if scope_kind == "platform":
        normalized_scope_id = None
    elif scope_kind == "user":
        normalized_scope_id = scope_id or str(identity.id)
    elif scope_kind in {"tenant", "team"} and not scope_id:
        raise SecretStoreError("scope_id is required for non-platform scope")
    elif scope_kind not in {"platform", "tenant", "user", "team"}:
        raise SecretStoreError("invalid scope_kind")
    if scope_kind == "team":
        raise SecretStoreError("team scope is not supported in v1")

    with transaction.atomic():
        ref: Optional[SecretRef]
        if existing_ref:
            ref = SecretRef.objects.select_for_update().filter(id=existing_ref.id).first()
        else:
            qs = SecretRef.objects.select_for_update().filter(scope_kind=scope_kind, name=logical_name)
            if normalized_scope_id is None:
                qs = qs.filter(scope_id__isnull=True)
            else:
                qs = qs.filter(scope_id=normalized_scope_id)
            ref = qs.first()
        if not ref:
            ref = SecretRef(
                name=logical_name,
                scope_kind=scope_kind,
                scope_id=normalized_scope_id,
                store=store,
                external_ref="pending",
                type="secrets_manager",
                created_by=user if getattr(user, "is_authenticated", False) else None,
            )
            ref.save()
        else:
            ref.store = store
            if description:
                ref.description = description
            ref.save(update_fields=["store", "description", "updated_at"])

        scope_path_id = _resolve_secret_scope_path(scope_kind, normalized_scope_id, identity)
        external_ref, metadata = write_secret_value(
            store,
            logical_name=logical_name,
            scope_kind=scope_kind,
            scope_id=normalized_scope_id,
            scope_path_id=scope_path_id,
            secret_ref_id=str(ref.id),
            value=value,
            description=description or ref.description or logical_name,
        )
        ref.external_ref = external_ref
        ref.type = "secrets_manager"
        ref.version = None
        ref.metadata_json = {
            **(ref.metadata_json or {}),
            **metadata,
            "last_written_at": timezone.now().isoformat(),
        }
        if description:
            ref.description = description
        ref.save(
            update_fields=[
                "external_ref",
                "type",
                "version",
                "metadata_json",
                "description",
                "updated_at",
            ]
        )
        return ref


def _derive_provider_secret_name(provider_id: str, issuer: str) -> str:
    provider_key = slugify((provider_id or "").strip())
    if not provider_key:
        host = urlsplit(issuer or "").hostname or ""
        provider_key = slugify(host) or "provider"
    return f"idp/{provider_key}/client_secret"


def _default_platform_config() -> Dict[str, Any]:
    return {
        "storage": {
            "primary": {"type": "local", "name": "local"},
            "providers": [
                {
                    "name": "local",
                    "type": "local",
                    "local": {"base_path": os.environ.get("XYN_UPLOADS_LOCAL_PATH", "/tmp/xyn-uploads")},
                }
            ],
        },
        "notifications": {
            "enabled": True,
            "channels": [],
        },
    }


def _load_platform_config() -> Dict[str, Any]:
    latest = PlatformConfigDocument.objects.order_by("-created_at", "-version").first()
    if not latest or not isinstance(latest.config_json, dict):
        return _default_platform_config()
    cfg = latest.config_json or {}
    merged = _default_platform_config()
    merged.update(cfg)
    return merged


def _platform_config_version() -> int:
    latest = PlatformConfigDocument.objects.order_by("-version").first()
    return int(latest.version) if latest else 0


def _serialize_report_attachment(attachment: ReportAttachment) -> Dict[str, Any]:
    storage_meta = attachment.storage_metadata_json or {}
    return {
        "id": str(attachment.id),
        "filename": attachment.filename,
        "content_type": attachment.content_type,
        "size_bytes": int(attachment.size_bytes or 0),
        "storage": {
            "provider": attachment.storage_provider or storage_meta.get("provider") or "local",
            "bucket": attachment.storage_bucket or storage_meta.get("bucket"),
            "key": attachment.storage_key or storage_meta.get("key"),
            "url_expires_at": storage_meta.get("url_expires_at"),
        },
        "created_at_iso": attachment.created_at.isoformat() if attachment.created_at else "",
    }


def _serialize_report(report: Report) -> Dict[str, Any]:
    created_by = {
        "id": str(report.created_by_id) if report.created_by_id else "",
        "email": getattr(report.created_by, "email", "") if report.created_by_id else "",
    }
    return {
        "id": str(report.id),
        "type": report.report_type,
        "title": report.title,
        "description": report.description,
        "priority": report.priority,
        "tags": report.tags_json or [],
        "context": report.context_json or {},
        "attachments": [_serialize_report_attachment(item) for item in report.attachments.all().order_by("created_at")],
        "created_at_iso": report.created_at.isoformat() if report.created_at else "",
        "created_by": created_by,
    }


def _sanitize_report_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_tags = payload.get("tags")
    tags = [str(item).strip() for item in raw_tags] if isinstance(raw_tags, list) else []
    tags = [item for item in tags if item]
    priority = str(payload.get("priority") or "p2").lower()
    if priority not in {"p0", "p1", "p2", "p3"}:
        priority = "p2"
    context = payload.get("context") if isinstance(payload.get("context"), dict) else {}
    return {
        "type": str(payload.get("type") or "").strip().lower(),
        "title": str(payload.get("title") or "").strip(),
        "description": str(payload.get("description") or "").strip(),
        "priority": priority,
        "tags": tags,
        "context": context,
    }


def _validate_platform_config_semantics(payload: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    storage = payload.get("storage") if isinstance(payload.get("storage"), dict) else {}
    primary = storage.get("primary") if isinstance(storage.get("primary"), dict) else {}
    providers = storage.get("providers") if isinstance(storage.get("providers"), list) else []
    provider_names = {str(item.get("name") or "").strip() for item in providers if isinstance(item, dict)}
    primary_name = str(primary.get("name") or "").strip()
    if primary_name and primary_name not in provider_names:
        errors.append("storage.primary.name must match a provider name")

    notifications = payload.get("notifications") if isinstance(payload.get("notifications"), dict) else {}
    channels = notifications.get("channels") if isinstance(notifications.get("channels"), list) else []
    for idx, channel in enumerate(channels):
        if not isinstance(channel, dict):
            continue
        enabled = bool(channel.get("enabled", True))
        ctype = str(channel.get("type") or "").strip()
        if ctype == "discord" and enabled:
            discord_cfg = channel.get("discord") if isinstance(channel.get("discord"), dict) else {}
            if not str(discord_cfg.get("webhook_url_ref") or "").strip():
                errors.append(f"notifications.channels[{idx}].discord.webhook_url_ref is required when enabled")
        if ctype == "aws_sns" and enabled:
            sns_cfg = channel.get("aws_sns") if isinstance(channel.get("aws_sns"), dict) else {}
            if not str(sns_cfg.get("topic_arn") or "").strip():
                errors.append(f"notifications.channels[{idx}].aws_sns.topic_arn is required when enabled")
            if not str(sns_cfg.get("region") or "").strip():
                errors.append(f"notifications.channels[{idx}].aws_sns.region is required when enabled")
    return errors


def _status_from_run(run: Optional[Run]) -> str:
    if not run:
        return "unknown"
    if run.status == "succeeded":
        return "ok"
    if run.status in {"failed"}:
        return "error"
    if run.status in {"pending", "running"}:
        return "warn"
    return "unknown"


def _status_from_release(release: Release) -> str:
    if release.status == "published" and release.build_state == "ready":
        return "ok"
    if release.build_state == "failed":
        return "error"
    if release.status == "draft" or release.build_state in {"building"}:
        return "warn"
    return "unknown"


def _read_json_from_artifact_url(url: str) -> Optional[Dict[str, Any]]:
    if not url:
        return None
    try:
        if url.startswith("/media/"):
            media_root = Path(__file__).resolve().parents[1] / "media"
            file_path = media_root / url.replace("/media/", "")
            if not file_path.exists():
                return None
            with open(file_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        if url.startswith("http"):
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            return response.json()
    except Exception:
        return None
    return None


def _load_release_manifest(release: Release) -> Optional[Dict[str, Any]]:
    artifacts = release.artifacts_json or {}
    if not isinstance(artifacts, dict):
        return None
    manifest = artifacts.get("release_manifest")
    if isinstance(manifest, dict):
        inline = manifest.get("content")
        if isinstance(inline, dict):
            return inline
        url = str(manifest.get("url") or "")
        if url:
            return _read_json_from_artifact_url(url)
    return None


def _extract_release_ecr_refs(release: Release) -> List[Dict[str, str]]:
    manifest = _load_release_manifest(release) or {}
    images = manifest.get("images") or {}
    if not isinstance(images, dict):
        return []
    refs: List[Dict[str, str]] = []
    for meta in images.values():
        if not isinstance(meta, dict):
            continue
        image_uri = str(meta.get("image_uri") or "").strip()
        digest = str(meta.get("digest") or "").strip()
        if not image_uri:
            continue
        parts = image_uri.split("/", 1)
        if len(parts) < 2:
            continue
        registry = parts[0]
        if ".dkr.ecr." not in registry or ".amazonaws.com" not in registry:
            continue
        repository_and_tag = parts[1]
        repository = repository_and_tag.split("@", 1)[0]
        tag = ""
        if ":" in repository and "/" in repository:
            last_colon = repository.rfind(":")
            last_slash = repository.rfind("/")
            if last_colon > last_slash:
                tag = repository[last_colon + 1 :]
                repository = repository[:last_colon]
        elif ":" in repository:
            repo_part, tag_part = repository.rsplit(":", 1)
            repository = repo_part
            tag = tag_part
        region = ""
        try:
            region = registry.split(".dkr.ecr.", 1)[1].split(".amazonaws.com", 1)[0]
        except Exception:
            region = os.environ.get("AWS_REGION", "").strip()
        refs.append(
            {
                "repository": repository,
                "region": region,
                "digest": digest,
                "tag": tag,
            }
        )
    return refs


def _delete_release_images(release: Release) -> Dict[str, Any]:
    refs = _extract_release_ecr_refs(release)
    deleted = 0
    failures: List[Dict[str, str]] = []
    grouped: Dict[tuple[str, str], List[Dict[str, str]]] = {}
    for ref in refs:
        key = (ref.get("region") or "", ref.get("repository") or "")
        grouped.setdefault(key, []).append(ref)
    for (region, repository), entries in grouped.items():
        if not repository:
            continue
        image_ids = []
        for item in entries:
            if item.get("digest"):
                image_ids.append({"imageDigest": item["digest"]})
            elif item.get("tag"):
                image_ids.append({"imageTag": item["tag"]})
        if not image_ids:
            continue
        try:
            client = boto3.client("ecr", region_name=region or None)
            result = client.batch_delete_image(repositoryName=repository, imageIds=image_ids)
            deleted += len(result.get("imageIds") or [])
            for failure in result.get("failures") or []:
                failures.append(
                    {
                        "repository": repository,
                        "region": region,
                        "code": str(failure.get("failureCode") or ""),
                        "reason": str(failure.get("failureReason") or ""),
                    }
                )
        except Exception as exc:
            failures.append(
                {
                    "repository": repository,
                    "region": region,
                    "code": "client_error",
                    "reason": str(exc),
                }
            )
    return {"referenced": len(refs), "deleted": deleted, "failures": failures}


def require_role(role: str):
    def decorator(view):
        @wraps(view)
        def _wrapped(request: HttpRequest, *args, **kwargs):
            identity = _require_authenticated(request)
            if not identity:
                return JsonResponse({"error": "not authenticated"}, status=401)
            if not RoleBinding.objects.filter(user_identity=identity, role=role).exists():
                return JsonResponse({"error": "forbidden"}, status=403)
            request.user_identity = identity  # type: ignore[attr-defined]
            return view(request, *args, **kwargs)

        return _wrapped

    return decorator


def require_any_role(*roles: str):
    role_set = {role for role in roles if role}

    def decorator(view):
        @wraps(view)
        def _wrapped(request: HttpRequest, *args, **kwargs):
            identity = _require_authenticated(request)
            if not identity:
                return JsonResponse({"error": "not authenticated"}, status=401)
            if not RoleBinding.objects.filter(user_identity=identity, role__in=role_set).exists():
                return JsonResponse({"error": "forbidden"}, status=403)
            request.user_identity = identity  # type: ignore[attr-defined]
            return view(request, *args, **kwargs)

        return _wrapped

    return decorator


@csrf_exempt
def oidc_exchange(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    code = payload.get("code")
    code_verifier = payload.get("code_verifier")
    redirect_uri = payload.get("redirect_uri")
    if not code or not code_verifier or not redirect_uri:
        return JsonResponse({"error": "code, code_verifier, and redirect_uri are required"}, status=400)
    issuer = os.environ.get("OIDC_ISSUER", "https://accounts.google.com").strip()
    client_id = os.environ.get("OIDC_CLIENT_ID", "").strip()
    client_secret = os.environ.get("OIDC_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        return JsonResponse({"error": "OIDC client not configured"}, status=500)
    config = _get_oidc_config(issuer)
    if not config or not config.get("token_endpoint"):
        return JsonResponse({"error": "OIDC configuration unavailable"}, status=502)
    try:
        token_response = requests.post(
            config["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
            timeout=15,
        )
    except Exception as exc:
        return JsonResponse({"error": f"token exchange failed: {exc}"}, status=502)
    if token_response.status_code >= 400:
        try:
            details = token_response.json()
        except Exception:
            details = token_response.text
        return JsonResponse({"error": "token exchange failed", "details": details}, status=400)
    token_payload = token_response.json()
    id_token = token_payload.get("id_token")
    if not id_token:
        return JsonResponse({"error": "id_token missing"}, status=400)
    claims = _verify_oidc_token(id_token)
    if not claims:
        return JsonResponse({"error": "invalid id_token"}, status=401)
    user = _get_or_create_user_from_claims(claims)
    if not user:
        return JsonResponse({"error": "user not allowed"}, status=403)
    return JsonResponse(
        {
            "id_token": id_token,
            "expires_in": token_payload.get("expires_in"),
        }
    )


@csrf_exempt
def internal_oidc_config(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    if not request.headers.get("X-Internal-Token"):
        return JsonResponse({"error": "Unauthorized"}, status=401)
    env = _resolve_environment(request)
    if not env:
        return JsonResponse({"error": "environment not found"}, status=404)
    config = _get_oidc_env_config(env) or {}
    return JsonResponse(
        {
            "issuer_url": config.get("issuer_url", ""),
            "client_id": config.get("client_id", ""),
            "redirect_uri": config.get("redirect_uri", ""),
            "scopes": config.get("scopes", "openid profile email"),
            "allowed_email_domains": config.get("allowed_email_domains", []),
        }
    )


@csrf_exempt
@login_required
def secret_stores_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _is_platform_admin(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    if request.method == "GET":
        stores = SecretStore.objects.all().order_by("-is_default", "name")
        return JsonResponse({"secret_stores": [_serialize_secret_store(store) for store in stores]})
    if request.method == "POST":
        payload = _parse_json(request)
        name = str(payload.get("name") or "").strip()
        kind = str(payload.get("kind") or "aws_secrets_manager").strip()
        if not name:
            return JsonResponse({"error": "name required"}, status=400)
        if kind != "aws_secrets_manager":
            return JsonResponse({"error": "invalid kind"}, status=400)
        store = SecretStore(
            name=name,
            kind=kind,
            is_default=bool(payload.get("is_default", False)),
            config_json=payload.get("config_json") if isinstance(payload.get("config_json"), dict) else {},
        )
        try:
            store.save()
        except Exception as exc:
            return JsonResponse({"error": "invalid secret store", "details": str(exc)}, status=400)
        return JsonResponse({"id": str(store.id)})
    return JsonResponse({"error": "method not allowed"}, status=405)


@csrf_exempt
@login_required
def secret_store_detail(request: HttpRequest, store_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _is_platform_admin(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    store = get_object_or_404(SecretStore, id=store_id)
    if request.method in {"PATCH", "PUT"}:
        payload = _parse_json(request)
        if "name" in payload:
            store.name = str(payload.get("name") or "").strip() or store.name
        if "kind" in payload:
            kind = str(payload.get("kind") or "").strip()
            if kind != "aws_secrets_manager":
                return JsonResponse({"error": "invalid kind"}, status=400)
            store.kind = kind
        if "is_default" in payload:
            store.is_default = bool(payload.get("is_default"))
        if "config_json" in payload:
            config = payload.get("config_json")
            if config is not None and not isinstance(config, dict):
                return JsonResponse({"error": "config_json must be object"}, status=400)
            store.config_json = config or {}
        try:
            store.save()
        except Exception as exc:
            return JsonResponse({"error": "invalid secret store", "details": str(exc)}, status=400)
        return JsonResponse({"id": str(store.id)})
    if request.method == "DELETE":
        store.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(_serialize_secret_store(store))


@csrf_exempt
@login_required
def secret_store_set_default(request: HttpRequest, store_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _is_platform_admin(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    store = get_object_or_404(SecretStore, id=store_id)
    with transaction.atomic():
        SecretStore.objects.filter(is_default=True).exclude(id=store.id).update(is_default=False, updated_at=timezone.now())
        store.is_default = True
        try:
            store.save(update_fields=["is_default", "updated_at"])
        except Exception as exc:
            return JsonResponse({"error": "invalid secret store", "details": str(exc)}, status=400)
    return JsonResponse({"id": str(store.id), "is_default": True})


@csrf_exempt
@login_required
def secret_refs_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    scope_kind = str(request.GET.get("scope_kind") or "").strip().lower()
    scope_id = str(request.GET.get("scope_id") or "").strip() or None
    qs = SecretRef.objects.select_related("store").all()
    if scope_kind:
        qs = qs.filter(scope_kind=scope_kind)
    if scope_id:
        qs = qs.filter(scope_id=scope_id)
    if not _is_platform_admin(identity):
        if scope_kind and not _scope_read_allowed(identity, scope_kind, scope_id):
            return JsonResponse({"error": "forbidden"}, status=403)
        allowed_tenants = set(
            TenantMembership.objects.filter(user_identity=identity, status="active", role__in=["tenant_admin"])
            .values_list("tenant_id", flat=True)
        )
        qs = qs.filter(
            models.Q(scope_kind="user", scope_id=identity.id)
            | models.Q(scope_kind="tenant", scope_id__in=allowed_tenants)
        )
    refs = qs.order_by("scope_kind", "name")
    return JsonResponse({"secret_refs": [_serialize_secret_ref(ref) for ref in refs]})


@csrf_exempt
@login_required
def secrets_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    name = str(payload.get("name") or "").strip()
    scope_kind = str(payload.get("scope_kind") or "").strip().lower()
    scope_id = str(payload.get("scope_id") or "").strip() or None
    store_id = str(payload.get("store_id") or "").strip() or None
    value = str(payload.get("value") or "")
    description = str(payload.get("description") or "").strip()
    if not name or not scope_kind or not value:
        return JsonResponse({"error": "name, scope_kind, and value are required"}, status=400)
    store = _resolve_secret_store(store_id)
    if not store:
        return JsonResponse({"error": "secret store not found; configure a default store"}, status=400)
    try:
        ref = _create_or_update_secret_ref(
            identity=identity,
            user=request.user,
            name=name,
            scope_kind=scope_kind,
            scope_id=scope_id,
            store=store,
            value=value,
            description=description,
        )
    except PermissionError:
        return JsonResponse({"error": "forbidden"}, status=403)
    except SecretStoreError as exc:
        return JsonResponse({"error": "secret write failed", "details": str(exc)}, status=400)
    except Exception as exc:
        return JsonResponse({"error": "secret write failed", "details": exc.__class__.__name__}, status=400)
    return JsonResponse(
        {
            "secret_ref": {
                "id": str(ref.id),
                "name": ref.name,
                "type": ref.type,
                "ref": ref.external_ref,
                "scope_kind": ref.scope_kind,
                "scope_id": str(ref.scope_id) if ref.scope_id else None,
                "store_id": str(ref.store_id),
                "updated_at": ref.updated_at,
            }
        }
    )


@csrf_exempt
@login_required
def secret_update(request: HttpRequest, secret_ref_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "PUT":
        return JsonResponse({"error": "method not allowed"}, status=405)
    ref = get_object_or_404(SecretRef.objects.select_related("store"), id=secret_ref_id)
    scope_id = str(ref.scope_id) if ref.scope_id else None
    if not _scope_write_allowed(identity, ref.scope_kind, scope_id):
        return JsonResponse({"error": "forbidden"}, status=403)
    payload = _parse_json(request)
    value = str(payload.get("value") or "")
    description = str(payload.get("description") or ref.description or "").strip()
    if not value:
        return JsonResponse({"error": "value is required"}, status=400)
    try:
        ref = _create_or_update_secret_ref(
            identity=identity,
            user=request.user,
            name=ref.name,
            scope_kind=ref.scope_kind,
            scope_id=scope_id,
            store=ref.store,
            value=value,
            description=description,
            existing_ref=ref,
        )
    except SecretStoreError as exc:
        return JsonResponse({"error": "secret write failed", "details": str(exc)}, status=400)
    except Exception as exc:
        return JsonResponse({"error": "secret write failed", "details": exc.__class__.__name__}, status=400)
    return JsonResponse(
        {
            "secret_ref": {
                "id": str(ref.id),
                "name": ref.name,
                "type": ref.type,
                "ref": ref.external_ref,
                "scope_kind": ref.scope_kind,
                "scope_id": str(ref.scope_id) if ref.scope_id else None,
                "store_id": str(ref.store_id),
                "updated_at": ref.updated_at,
            }
        }
    )


@csrf_exempt
@login_required
def platform_config_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method == "GET":
        if not _is_platform_admin(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        latest = PlatformConfigDocument.objects.order_by("-created_at", "-version").first()
        payload = _load_platform_config()
        return JsonResponse(
            {
                "version": int(latest.version) if latest else 0,
                "config": payload,
            }
        )
    if request.method in {"PUT", "PATCH"}:
        if not _is_platform_admin(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        errors = _validate_schema_payload(payload, "platform_config.v1.schema.json")
        errors.extend(_validate_platform_config_semantics(payload))
        if errors:
            return JsonResponse({"error": "invalid platform config", "details": errors}, status=400)
        next_version = _platform_config_version() + 1
        document = PlatformConfigDocument.objects.create(
            version=next_version,
            config_json=payload,
            created_by=request.user if request.user.is_authenticated else None,
        )
        return JsonResponse({"version": int(document.version), "config": document.config_json})
    return JsonResponse({"error": "method not allowed"}, status=405)


def _report_payload_from_request(request: HttpRequest) -> Dict[str, Any]:
    if request.content_type and "multipart/form-data" in request.content_type:
        payload_raw = request.POST.get("payload") or "{}"
        try:
            return json.loads(payload_raw)
        except Exception:
            return {}
    return _parse_json(request)


def _report_attachment_files(request: HttpRequest):
    return request.FILES.getlist("attachments")


@csrf_exempt
@login_required
def reports_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)

    raw_payload = _report_payload_from_request(request)
    payload = _sanitize_report_payload(raw_payload)
    validation_errors = _validate_schema_payload(payload, "report.v1.schema.json")
    if validation_errors:
        return JsonResponse({"error": "invalid report", "details": validation_errors}, status=400)

    files = _report_attachment_files(request)
    platform_config = _load_platform_config()
    storage_registry = StorageProviderRegistry(platform_config)
    notifier_registry = NotifierRegistry(platform_config)

    with transaction.atomic():
        report = Report.objects.create(
            report_type=payload.get("type") or "bug",
            title=payload.get("title") or "",
            description=payload.get("description") or "",
            priority=payload.get("priority") or "p2",
            tags_json=payload.get("tags") or [],
            context_json=payload.get("context") or {},
            created_by=request.user if request.user.is_authenticated else None,
        )
        attachments: List[ReportAttachment] = []
        for upload in files:
            attachment = ReportAttachment.objects.create(
                report=report,
                filename=str(getattr(upload, "name", "attachment")),
                content_type=str(getattr(upload, "content_type", "") or "application/octet-stream"),
                size_bytes=int(getattr(upload, "size", 0) or 0),
                storage_provider="pending",
            )
            data = upload.read()
            stored = storage_registry.store_attachment_bytes(
                report_id=str(report.id),
                attachment_id=str(attachment.id),
                filename=attachment.filename,
                content_type=attachment.content_type,
                data=data,
            )
            attachment.storage_provider = str(stored.get("provider") or "local")
            attachment.storage_bucket = str(stored.get("bucket") or "")
            attachment.storage_key = str(stored.get("key") or "")
            attachment.storage_path = str(stored.get("path") or "")
            attachment.storage_metadata_json = stored
            attachment.save(
                update_fields=[
                    "storage_provider",
                    "storage_bucket",
                    "storage_key",
                    "storage_path",
                    "storage_metadata_json",
                ]
            )
            attachments.append(attachment)

    report_payload = _serialize_report(report)
    download_refs: List[str] = []
    for attachment in attachments:
        try:
            ref = storage_registry.build_download_reference(attachment.storage_metadata_json or {}, ttl_seconds=86400)
            if ref:
                download_refs.append(ref)
        except Exception:
            continue
    try:
        notify_errors = notifier_registry.notify_report_created(report_payload, download_refs)
    except Exception as exc:
        notify_errors = [f"notify: {exc.__class__.__name__}"]
    if notify_errors:
        report.notification_errors_json = notify_errors
        report.save(update_fields=["notification_errors_json"])

    return JsonResponse(_serialize_report(report))


@csrf_exempt
@login_required
def report_detail(request: HttpRequest, report_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    report = get_object_or_404(Report.objects.prefetch_related("attachments"), id=report_id)
    return JsonResponse(_serialize_report(report))


@csrf_exempt
@login_required
def identity_providers_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if architect_error := _require_platform_architect(request):
        return architect_error
    if request.method == "POST":
        payload = _parse_json(request)
        errors = _validate_provider_payload(payload)
        if errors:
            return JsonResponse({"error": "invalid provider", "details": errors}, status=400)
        fields, _schema_payload = _normalize_provider_payload(payload)
        client_payload = payload.get("client") or {}
        secret_value = str(client_payload.get("client_secret_value") or payload.get("client_secret_value") or "")
        store_id = str(client_payload.get("store_id") or payload.get("store_id") or "").strip() or None
        provider_id = str(fields.get("id") or "")
        issuer = str(fields.get("issuer") or "")
        if secret_value:
            identity = _require_authenticated(request)
            if not identity:
                return JsonResponse({"error": "not authenticated"}, status=401)
            store = _resolve_secret_store(store_id)
            if not store:
                return JsonResponse({"error": "secret store not found; configure a default store"}, status=400)
            try:
                secret_ref = _create_or_update_secret_ref(
                    identity=identity,
                    user=request.user,
                    name=_derive_provider_secret_name(provider_id, issuer),
                    scope_kind="platform",
                    scope_id=None,
                    store=store,
                    value=secret_value,
                    description=f"OIDC client secret for {provider_id}",
                )
            except SecretStoreError as exc:
                return JsonResponse({"error": "invalid provider", "details": [str(exc)]}, status=400)
            fields["client_secret_ref_json"] = {"type": "aws.secrets_manager", "ref": secret_ref.external_ref}
        provider = IdentityProvider.objects.create(
            **fields,
            created_by=request.user,
        )
        return JsonResponse({"id": provider.id})
    providers = IdentityProvider.objects.all().order_by("id")
    data = [provider_to_payload(provider) for provider in providers]
    return JsonResponse({"identity_providers": data})


@csrf_exempt
@login_required
def identity_provider_detail(request: HttpRequest, provider_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if architect_error := _require_platform_architect(request):
        return architect_error
    provider = get_object_or_404(IdentityProvider, id=provider_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        errors = _validate_provider_payload({**provider_to_payload(provider), **payload})
        if errors:
            return JsonResponse({"error": "invalid provider", "details": errors}, status=400)
        fields, _schema_payload = _normalize_provider_payload({**provider_to_payload(provider), **payload})
        client_payload = payload.get("client") or {}
        secret_value = str(client_payload.get("client_secret_value") or payload.get("client_secret_value") or "")
        store_id = str(client_payload.get("store_id") or payload.get("store_id") or "").strip() or None
        if secret_value:
            identity = _require_authenticated(request)
            if not identity:
                return JsonResponse({"error": "not authenticated"}, status=401)
            store = _resolve_secret_store(store_id)
            if not store:
                return JsonResponse({"error": "secret store not found; configure a default store"}, status=400)
            try:
                secret_ref = _create_or_update_secret_ref(
                    identity=identity,
                    user=request.user,
                    name=_derive_provider_secret_name(provider.id, fields.get("issuer") or provider.issuer),
                    scope_kind="platform",
                    scope_id=None,
                    store=store,
                    value=secret_value,
                    description=f"OIDC client secret for {provider.id}",
                )
            except SecretStoreError as exc:
                return JsonResponse({"error": "invalid provider", "details": [str(exc)]}, status=400)
            fields["client_secret_ref_json"] = {"type": "aws.secrets_manager", "ref": secret_ref.external_ref}
        for key, value in fields.items():
            setattr(provider, key, value)
        provider.save()
        return JsonResponse({"id": provider.id})
    if request.method == "DELETE":
        provider.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(provider_to_payload(provider))


@csrf_exempt
@login_required
def identity_provider_test(request: HttpRequest, provider_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if architect_error := _require_platform_architect(request):
        return architect_error
    provider = get_object_or_404(IdentityProvider, id=provider_id)
    try:
        discovery = get_discovery_doc(provider, force=True)
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=502)
    return JsonResponse(
        {
            "ok": True,
            "issuer": provider.issuer,
            "authorization_endpoint": (discovery or {}).get("authorization_endpoint"),
            "token_endpoint": (discovery or {}).get("token_endpoint"),
            "jwks_uri": (discovery or {}).get("jwks_uri"),
        }
    )


@csrf_exempt
@login_required
def oidc_app_clients_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if architect_error := _require_platform_architect(request):
        return architect_error
    if request.method == "POST":
        payload = _parse_json(request)
        errors = _validate_app_client_payload(payload)
        if errors:
            return JsonResponse({"error": "invalid app client", "details": errors}, status=400)
        fields, _schema_payload = _normalize_app_client_payload(payload)
        with transaction.atomic():
            existing = (
                AppOIDCClient.objects.select_for_update()
                .filter(app_id=fields["app_id"])
                .order_by("-updated_at", "-created_at")
            )
            client = existing.first()
            if client:
                for key, value in fields.items():
                    setattr(client, key, value)
                if not client.created_by_id:
                    client.created_by = request.user
                client.save()
                duplicate_ids = list(existing.values_list("id", flat=True))[1:]
                if duplicate_ids:
                    AppOIDCClient.objects.filter(id__in=duplicate_ids).delete()
            else:
                client = AppOIDCClient.objects.create(
                    **fields,
                    created_by=request.user,
                )
        return JsonResponse({"id": str(client.id)})
    clients = AppOIDCClient.objects.all().order_by("app_id", "-created_at")
    data = [app_client_to_payload(client) for client in clients]
    return JsonResponse({"oidc_app_clients": data})


@csrf_exempt
@login_required
def oidc_app_client_detail(request: HttpRequest, client_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if architect_error := _require_platform_architect(request):
        return architect_error
    client = get_object_or_404(AppOIDCClient, id=client_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        errors = _validate_app_client_payload({**app_client_to_payload(client), **payload})
        if errors:
            return JsonResponse({"error": "invalid app client", "details": errors}, status=400)
        fields, _schema_payload = _normalize_app_client_payload({**app_client_to_payload(client), **payload})
        for key, value in fields.items():
            setattr(client, key, value)
        client.save()
        return JsonResponse({"id": str(client.id)})
    if request.method == "DELETE":
        client.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(app_client_to_payload(client))


def _resolve_app_config(app_id: str) -> Optional[AppOIDCClient]:
    return resolve_app_client(app_id)


def _build_oidc_config_payload(client: AppOIDCClient) -> Dict[str, Any]:
    allowed_ids = client.allowed_providers_json or []
    providers = IdentityProvider.objects.filter(id__in=allowed_ids, enabled=True).order_by("id")
    provider_payloads = []
    for provider in providers:
        provider_payloads.append(
            {
                "id": provider.id,
                "display_name": provider.display_name,
                "issuer": provider.issuer,
                "client_id": provider.client_id,
                "prompt": provider.prompt or None,
                "pkce": provider.pkce_enabled,
                "scopes": provider.scopes_json or ["openid", "profile", "email"],
                "domain_rules": provider.domain_rules_json or {},
            }
        )
    pkce_required = any(bool(provider.get("pkce")) for provider in provider_payloads) if provider_payloads else True
    return {
        "app_id": client.app_id,
        "appId": client.app_id,
        "login_mode": client.login_mode,
        "loginMode": client.login_mode,
        "default_provider_id": client.default_provider_id if client.default_provider_id else None,
        "defaultProviderId": client.default_provider_id if client.default_provider_id else None,
        "allowed_providers": provider_payloads,
        "providers": [
            {
                "id": provider["id"],
                "displayName": provider["display_name"],
                "issuer": provider["issuer"],
            }
            for provider in provider_payloads
        ],
        "redirect_uris": client.redirect_uris_json or [],
        "post_logout_redirect_uris": client.post_logout_redirect_uris_json or [],
        "session": client.session_json or {},
        "token_validation": client.token_validation_json or {},
        "pkce": pkce_required,
    }


@csrf_exempt
def oidc_config(request: HttpRequest) -> JsonResponse:
    app_id = request.GET.get("appId") or request.GET.get("app_id") or ""
    if not app_id:
        return JsonResponse({"error": "appId required"}, status=400)
    client = _resolve_app_config(app_id)
    if not client:
        return JsonResponse({"error": "app not configured"}, status=404)
    return JsonResponse(_build_oidc_config_payload(client))


def _decode_oidc_id_token(
    provider: IdentityProvider,
    client: AppOIDCClient,
    id_token: str,
    nonce: str,
) -> Optional[Dict[str, Any]]:
    def _token_kid(token: str) -> str:
        try:
            header_b64 = token.split(".")[0]
            header_b64 += "=" * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64.encode("utf-8")).decode("utf-8"))
            return header.get("kid") or ""
        except Exception:
            return ""

    kid = _token_kid(id_token)
    jwks = get_jwks(provider, kid=kid or None)
    if not jwks:
        return None
    token_validation = client.token_validation_json or {}
    clock_skew = int(token_validation.get("clockSkewSeconds", 120))
    try:
        key_set = JsonWebKey.import_key_set(jwks)
        claims = jwt.decode(
            id_token,
            key_set,
            claims_options={
                "iss": {"value": provider.issuer},
                "exp": {"essential": True},
            },
        )
        claims.validate(leeway=clock_skew)
    except Exception:
        if kid:
            jwks = get_jwks(provider, force=True, kid=kid)
            if not jwks:
                return None
            key_set = JsonWebKey.import_key_set(jwks)
            claims = jwt.decode(
                id_token,
                key_set,
                claims_options={
                    "iss": {"value": provider.issuer},
                    "exp": {"essential": True},
                },
            )
            claims.validate(leeway=clock_skew)
        else:
            return None
    if nonce and claims.get("nonce") != nonce:
        return None
    aud = claims.get("aud")
    azp = claims.get("azp")
    accept_aud = (provider.audience_rules_json or {}).get("acceptAudiences") or [provider.client_id]
    if isinstance(aud, list):
        aud_ok = any(item in accept_aud for item in aud)
    else:
        aud_ok = aud in accept_aud
    if not aud_ok:
        return None
    accept_azp = bool((provider.audience_rules_json or {}).get("acceptAzp", True))
    if azp and not accept_azp:
        return None
    return dict(claims)


def _extract_claim(claims: Dict[str, Any], key: str, fallback: str) -> str:
    value = claims.get(key) if key else None
    if value is None:
        value = claims.get(fallback)
    return str(value) if value is not None else ""


def _extract_claim_at_path(claims: Dict[str, Any], claim_path: str) -> Any:
    current: Any = claims
    for segment in [part.strip() for part in (claim_path or "groups").split(".") if part.strip()]:
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def _extract_remote_groups_from_claims(claims: Dict[str, Any], claim_path: str) -> Set[str]:
    raw = _extract_claim_at_path(claims, claim_path or "groups")
    groups: set[str] = set()
    if isinstance(raw, str):
        value = raw.strip()
        if value:
            groups.add(value)
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                value = item.strip()
                if value:
                    groups.add(value)
            elif isinstance(item, dict):
                value = str(item.get("name") or "").strip()
                if value:
                    groups.add(value)
    return groups


def _apply_first_login_role_mappings(
    identity: UserIdentity,
    provider: IdentityProvider,
    claims: Dict[str, Any],
) -> Dict[str, Any]:
    existing_roles = list(
        RoleBinding.objects.filter(user_identity=identity, scope_kind="platform").values_list("role", flat=True)
    )
    if existing_roles:
        return {
            "denied": False,
            "reason": "roles_already_present",
            "assigned_roles": [],
            "remote_groups": [],
            "error": "",
        }

    claim_path = (provider.group_claim_path or "groups").strip() or "groups"
    mappings = _normalize_group_role_mapping_entries(provider.group_role_mappings_json or [])
    remote_groups = _extract_remote_groups_from_claims(claims, claim_path)
    assigned_roles: list[str] = []
    for mapping in mappings:
        remote_group_name = mapping["remote_group_name"]
        role_id = mapping["xyn_role_id"]
        if (
            remote_group_name
            and role_id
            and remote_group_name in remote_groups
            and role_id in PLATFORM_ROLE_IDS
            and role_id not in assigned_roles
        ):
            RoleBinding.objects.get_or_create(
                user_identity=identity,
                scope_kind="platform",
                scope_id=None,
                role=role_id,
            )
            assigned_roles.append(role_id)
    if assigned_roles:
        return {
            "denied": False,
            "reason": "matched_mapping",
            "assigned_roles": assigned_roles,
            "remote_groups": sorted(remote_groups),
            "error": "",
        }

    fallback_role_id = str(provider.fallback_default_role_id or "").strip()
    if fallback_role_id and fallback_role_id in PLATFORM_ROLE_IDS:
        RoleBinding.objects.get_or_create(
            user_identity=identity,
            scope_kind="platform",
            scope_id=None,
            role=fallback_role_id,
        )
        return {
            "denied": False,
            "reason": "fallback_default_role",
            "assigned_roles": [fallback_role_id],
            "remote_groups": sorted(remote_groups),
            "error": "",
        }

    if provider.require_group_match:
        return {
            "denied": True,
            "reason": "require_group_match_no_mapping",
            "assigned_roles": [],
            "remote_groups": sorted(remote_groups),
            "error": (
                "No mapped groups were found in your identity claims. "
                "Contact your administrator to update Identity Provider group-role mappings."
            ),
        }

    return {
        "denied": False,
        "reason": "no_mapping_no_fallback",
        "assigned_roles": [],
        "remote_groups": sorted(remote_groups),
        "error": "",
    }


def _load_oidc_flow(request: HttpRequest, state: str) -> Dict[str, Any]:
    if not state:
        return {}
    flow = request.session.get(f"oidc_flow:{state}") or {}
    if isinstance(flow, dict):
        return flow
    return {}


def _render_post_login_bridge(target_url: str) -> HttpResponse:
    safe_target = html.escape(target_url, quote=True)
    body = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="refresh" content="0;url={safe_target}" />
    <title>Signing in...</title>
  </head>
  <body>
    <p>Signing you in…</p>
    <p><a href="{safe_target}">Continue</a></p>
    <script>
      window.location.replace("{safe_target}");
    </script>
  </body>
</html>"""
    response = HttpResponse(body, content_type="text/html; charset=utf-8")
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response["Pragma"] = "no-cache"
    return response


@csrf_exempt
def oidc_authorize(request: HttpRequest, provider_id: str) -> HttpResponse:
    app_id = request.GET.get("appId") or request.GET.get("app_id") or ""
    if not app_id:
        return JsonResponse({"error": "appId required"}, status=400)
    client = _resolve_app_config(app_id)
    if not client:
        return JsonResponse({"error": "app not configured"}, status=404)
    allowed_ids = client.allowed_providers_json or []
    if provider_id not in allowed_ids:
        fallback_provider = (client.default_provider_id or "").strip()
        if fallback_provider and fallback_provider in allowed_ids and fallback_provider != provider_id:
            params = request.GET.copy()
            return redirect(
                f"/xyn/api/auth/oidc/{fallback_provider}/authorize?{params.urlencode()}"
            )
        return JsonResponse({"error": "provider not allowed"}, status=403)
    provider = get_object_or_404(IdentityProvider, id=provider_id)
    if not provider.enabled:
        return JsonResponse({"error": "provider disabled"}, status=400)
    discovery = get_discovery_doc(provider)
    if not discovery or not discovery.get("authorization_endpoint"):
        return JsonResponse({"error": "provider discovery unavailable"}, status=502)
    redirect_uris = client.redirect_uris_json or []
    if not redirect_uris:
        return JsonResponse({"error": "redirect_uris missing"}, status=400)
    redirect_uri = redirect_uris[0]
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce_pair()
    request.session[f"oidc_state:{app_id}:{provider_id}"] = state
    request.session[f"oidc_nonce:{app_id}:{provider_id}"] = nonce
    request.session[f"oidc_verifier:{app_id}:{provider_id}"] = code_verifier
    request.session["oidc_app_id"] = app_id
    request.session["oidc_provider_id"] = provider_id
    requested_return_to = request.GET.get("returnTo") or request.GET.get("next") or ""
    post_login_redirect = _sanitize_return_to(requested_return_to, request, client, app_id)
    request.session["post_login_redirect"] = post_login_redirect
    request.session[f"oidc_flow:{state}"] = {
        "app_id": app_id,
        "provider_id": provider_id,
        "return_to": post_login_redirect,
    }
    scopes = provider.scopes_json or ["openid", "profile", "email"]
    params = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if provider.prompt:
        params["prompt"] = provider.prompt
    domain_rules = provider.domain_rules_json or {}
    if domain_rules.get("allowedHostedDomain"):
        params["hd"] = domain_rules.get("allowedHostedDomain")
    url = f"{discovery['authorization_endpoint']}?{urlencode(params)}"
    return redirect(url)


@csrf_exempt
def oidc_callback(request: HttpRequest, provider_id: str) -> HttpResponse:
    if request.method not in {"POST", "GET"}:
        return JsonResponse({"error": "POST required"}, status=405)
    callback_error = request.POST.get("error") if request.method == "POST" else request.GET.get("error")
    callback_error_description = (
        request.POST.get("error_description") if request.method == "POST" else request.GET.get("error_description")
    )
    if callback_error:
        return JsonResponse(
            {
                "error": "oidc_authorize_failed",
                "provider_error": callback_error,
                "provider_error_description": callback_error_description or "",
            },
            status=400,
        )
    code = request.POST.get("code") if request.method == "POST" else request.GET.get("code")
    state = request.POST.get("state") if request.method == "POST" else request.GET.get("state")
    app_id = request.POST.get("appId") if request.method == "POST" else request.GET.get("appId")
    flow = _load_oidc_flow(request, state or "")
    flow_app_id = str(flow.get("app_id") or "")
    flow_provider_id = str(flow.get("provider_id") or "")
    app_id = app_id or flow_app_id or request.session.get("oidc_app_id") or ""
    if not code or not state:
        return JsonResponse({"error": "missing code/state"}, status=400)
    if not app_id:
        return JsonResponse({"error": "appId required"}, status=400)
    if flow_provider_id and flow_provider_id != provider_id:
        return JsonResponse({"error": "invalid state"}, status=400)
    expected_state = request.session.get(f"oidc_state:{app_id}:{provider_id}")
    if state != expected_state:
        if not expected_state and flow_app_id == app_id and flow_provider_id in {"", provider_id}:
            expected_state = state
        else:
            return JsonResponse({"error": "invalid state"}, status=400)
    if state != expected_state:
        return JsonResponse({"error": "invalid state"}, status=400)
    client = _resolve_app_config(app_id)
    if not client:
        return JsonResponse({"error": "app not configured"}, status=404)
    allowed_ids = client.allowed_providers_json or []
    if provider_id not in allowed_ids:
        return JsonResponse({"error": "provider not allowed"}, status=403)
    provider = get_object_or_404(IdentityProvider, id=provider_id)
    discovery = get_discovery_doc(provider)
    if not discovery or not discovery.get("token_endpoint"):
        return JsonResponse({"error": "provider discovery unavailable"}, status=502)
    redirect_uris = client.redirect_uris_json or []
    if not redirect_uris:
        return JsonResponse({"error": "redirect_uris missing"}, status=400)
    redirect_uri = redirect_uris[0]
    code_verifier = request.session.get(f"oidc_verifier:{app_id}:{provider_id}") or ""
    token_payload = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
    }
    if code_verifier:
        token_payload["code_verifier"] = code_verifier
    try:
        client_secret = resolve_oidc_secret_ref(provider.client_secret_ref_json)
    except Exception as exc:
        return JsonResponse(
            {
                "error": "client_secret_resolve_failed",
                "details": str(exc),
                "provider_id": provider.id,
            },
            status=400,
        )
    if client_secret:
        token_payload["client_secret"] = client_secret
    try:
        token_response = requests.post(discovery["token_endpoint"], data=token_payload, timeout=15)
    except requests.RequestException as exc:
        return JsonResponse({"error": "token_endpoint_unreachable", "details": str(exc)}, status=502)
    if token_response.status_code >= 400:
        try:
            details = token_response.json()
        except Exception:
            details = token_response.text
        return JsonResponse({"error": "token exchange failed", "details": details}, status=400)
    try:
        token_body = token_response.json()
    except ValueError:
        return JsonResponse({"error": "token_response_invalid_json", "details": token_response.text}, status=502)
    id_token = token_body.get("id_token")
    if not id_token:
        return JsonResponse({"error": "id_token missing"}, status=400)
    nonce = request.session.get(f"oidc_nonce:{app_id}:{provider_id}") or ""
    claims = _decode_oidc_id_token(provider, client, id_token, nonce)
    if not claims:
        return JsonResponse({"error": "invalid id_token"}, status=401)
    claim_map = provider.claims_json or {}
    subject = _extract_claim(claims, claim_map.get("subject", ""), "sub")
    email = _extract_claim(claims, claim_map.get("email", ""), "email")
    name = _extract_claim(claims, claim_map.get("name", ""), "name")
    given_name = _extract_claim(claims, claim_map.get("givenName", ""), "given_name")
    family_name = _extract_claim(claims, claim_map.get("familyName", ""), "family_name")
    domain_rules = provider.domain_rules_json or {}
    allowed_domains = domain_rules.get("allowedEmailDomains") or []
    if allowed_domains and email:
        domain = email.split("@")[-1].lower()
        if domain not in [d.lower() for d in allowed_domains]:
            return JsonResponse({"error": "email domain not allowed"}, status=403)
    hosted_domain = domain_rules.get("allowedHostedDomain")
    if hosted_domain:
        hd_claim = claims.get("hd") or claims.get("hosted_domain") or ""
        if hd_claim and str(hd_claim).lower() != str(hosted_domain).lower():
            return JsonResponse({"error": "hosted domain not allowed"}, status=403)
    identity, created = UserIdentity.objects.get_or_create(
        issuer=provider.issuer,
        subject=subject,
        defaults={
            "provider": "oidc",
            "provider_id": provider.id,
            "email": email,
            "display_name": name or " ".join([given_name, family_name]).strip(),
            "claims_json": claims,
            "last_login_at": timezone.now(),
        },
    )
    if not created:
        identity.provider_id = provider.id
        identity.provider = "oidc"
        identity.email = email
        identity.display_name = name or " ".join([given_name, family_name]).strip()
        identity.claims_json = claims
        identity.last_login_at = timezone.now()
        identity.save(
            update_fields=[
                "provider_id",
                "provider",
                "email",
                "display_name",
                "claims_json",
                "last_login_at",
                "updated_at",
            ]
        )
    if not RoleBinding.objects.exists() and os.environ.get("ALLOW_FIRST_ADMIN_BOOTSTRAP", "").lower() == "true":
        RoleBinding.objects.create(user_identity=identity, scope_kind="platform", role="platform_admin")
    assignment = _apply_first_login_role_mappings(identity, provider, claims)
    extracted_groups = assignment.get("remote_groups") or []
    if len(extracted_groups) > 25:
        extracted_groups = extracted_groups[:25] + ["__truncated__"]
    logger.info(
        "oidc first-login role evaluation",
        extra={
            "provider_id": provider.id,
            "user_identity_id": str(identity.id),
            "reason": assignment.get("reason"),
            "assigned_roles": assignment.get("assigned_roles") or [],
            "extracted_groups": extracted_groups,
        },
    )
    if assignment.get("denied"):
        return JsonResponse(
            {
                "error": "group match required",
                "details": assignment.get("error"),
                "provider_id": provider.id,
                "hint": "Ask a platform admin to add a group mapping or configure a fallback default role.",
            },
            status=403,
        )
    roles = _get_roles(identity)
    User = get_user_model()
    issuer_hash = hashlib.sha256(provider.issuer.encode("utf-8")).hexdigest()[:12]
    username = f"oidc:{issuer_hash}:{subject}"
    user, created = User.objects.get_or_create(
        username=username,
        defaults={
            "email": email,
            "is_staff": ("platform_admin" in roles or "platform_architect" in roles),
            "is_active": True,
        },
    )
    if email and user.email != email:
        user.email = email
    user.is_staff = ("platform_admin" in roles or "platform_architect" in roles)
    user.is_superuser = False
    user.is_active = True
    user.save()
    if not roles and app_id == "xyn-ui":
        return JsonResponse(
            {
                "error": "no roles assigned",
                "details": "No mapped group roles were found and no fallback default role is configured.",
                "hint": "Ask a platform admin to configure group-role mappings on your identity provider.",
            },
            status=403,
        )
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    request.session["user_identity_id"] = str(identity.id)
    redirect_to = _sanitize_return_to(
        request.session.get("post_login_redirect") or str(flow.get("return_to") or ""),
        request,
        client,
        app_id,
    )
    request.session.pop(f"oidc_state:{app_id}:{provider_id}", None)
    request.session.pop(f"oidc_nonce:{app_id}:{provider_id}", None)
    request.session.pop(f"oidc_verifier:{app_id}:{provider_id}", None)
    request.session.pop(f"oidc_flow:{state}", None)
    if request.session.get("oidc_app_id") == app_id:
        request.session.pop("oidc_app_id", None)
    if request.session.get("oidc_provider_id") == provider_id:
        request.session.pop("oidc_provider_id", None)
    request.session.pop("post_login_redirect", None)
    if app_id != "xyn-ui":
        split = urlsplit(redirect_to)
        fragment_params = dict(parse_qsl(split.fragment, keep_blank_values=True))
        fragment_params["id_token"] = id_token
        rebuilt = split._replace(fragment=urlencode(fragment_params))
        redirect_to = urlunsplit(rebuilt)
        return _render_post_login_bridge(redirect_to)
    return redirect(redirect_to)


@csrf_exempt
def _start_env_fallback_login(request: HttpRequest, app_id: str, return_to: str) -> HttpResponse:
    if AppOIDCClient.objects.exists():
        return JsonResponse({"error": "OIDC app not configured"}, status=500)
    logger.warning("Using ENV OIDC fallback (no app client configured)")
    env = _resolve_environment(request)
    if not env:
        return JsonResponse({"error": "environment not found"}, status=404)
    config = _get_oidc_env_config(env)
    if not config:
        return JsonResponse({"error": "OIDC not configured"}, status=500)
    issuer = config.get("issuer_url")
    client_id = config.get("client_id")
    scopes = config.get("scopes") or "openid profile email"
    if not issuer or not client_id:
        return JsonResponse({"error": "OIDC client not configured"}, status=500)
    oidc_config = _get_oidc_config(issuer)
    if not oidc_config or not oidc_config.get("authorization_endpoint"):
        return JsonResponse({"error": "OIDC configuration unavailable"}, status=502)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    request.session["oidc_state"] = state
    request.session["oidc_nonce"] = nonce
    request.session["environment_id"] = str(env.id)
    request.session["post_login_redirect"] = return_to
    redirect_uri = config.get("redirect_uri") or request.build_absolute_uri("/auth/callback")
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
    }
    url = f"{oidc_config['authorization_endpoint']}?{urlencode(params)}"
    return redirect(url)


@csrf_exempt
def auth_login(request: HttpRequest) -> HttpResponse:
    app_id = request.GET.get("appId") or "xyn-ui"
    client = _resolve_app_config(app_id)
    return_to = _sanitize_return_to(request.GET.get("returnTo") or request.GET.get("next") or "", request, client, app_id)
    if client:
        config = _build_oidc_config_payload(client)
        providers = config.get("providers") or []
        if not providers and config.get("allowed_providers"):
            providers = [
                {
                    "id": provider.get("id"),
                    "displayName": provider.get("display_name") or provider.get("id"),
                    "issuer": provider.get("issuer"),
                }
                for provider in config.get("allowed_providers")
            ]
        branding = _merge_branding_for_app(app_id)
        context = {
            "app_id": app_id,
            "return_to": return_to,
            "providers": providers,
            "default_provider_id": config.get("defaultProviderId"),
            "branding": branding,
            "login_title": f"Sign in to {branding.get('display_name') or app_id}",
        }
        response = render(request, "xyn_orchestrator/auth_login.html", context)
        # Provider lists are dynamic; avoid stale cached login pages pointing to removed providers.
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response["Pragma"] = "no-cache"
        return response
    request.session["post_login_redirect"] = return_to
    return _start_env_fallback_login(request, app_id=app_id, return_to=return_to)


@csrf_exempt
def auth_callback(request: HttpRequest) -> HttpResponse:
    provider_id = request.session.get("oidc_provider_id")
    state = request.POST.get("state") if request.method == "POST" else request.GET.get("state")
    if not provider_id:
        flow = _load_oidc_flow(request, state or "")
        flow_provider_id = str(flow.get("provider_id") or "")
        flow_app_id = str(flow.get("app_id") or "")
        if flow_provider_id:
            provider_id = flow_provider_id
            request.session["oidc_provider_id"] = flow_provider_id
        if flow_app_id:
            request.session["oidc_app_id"] = flow_app_id
        flow_return_to = str(flow.get("return_to") or "")
        if flow_return_to and not request.session.get("post_login_redirect"):
            request.session["post_login_redirect"] = flow_return_to
    if provider_id:
        return oidc_callback(request, provider_id)
    error = request.GET.get("error")
    if error:
        return JsonResponse({"error": error}, status=400)
    code = request.GET.get("code")
    if not code or not state:
        return JsonResponse({"error": "missing code/state"}, status=400)
    if state != request.session.get("oidc_state"):
        return JsonResponse({"error": "invalid state"}, status=400)
    env = _resolve_environment(request)
    if not env:
        return JsonResponse({"error": "environment not found"}, status=404)
    config = _get_oidc_env_config(env)
    if not config:
        return JsonResponse({"error": "OIDC not configured"}, status=500)
    issuer = config.get("issuer_url")
    client_id = config.get("client_id")
    secret_ref = config.get("client_secret_ref") or {}
    client_secret = _resolve_secret_ref(secret_ref) if secret_ref else None
    if not issuer or not client_id or not client_secret:
        return JsonResponse({"error": "OIDC client not configured"}, status=500)
    oidc_config = _get_oidc_config(issuer)
    if not oidc_config or not oidc_config.get("token_endpoint"):
        return JsonResponse({"error": "OIDC configuration unavailable"}, status=502)
    redirect_uri = config.get("redirect_uri") or request.build_absolute_uri("/auth/callback")
    token_response = requests.post(
        oidc_config["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        },
        timeout=15,
    )
    if token_response.status_code >= 400:
        return JsonResponse({"error": "token exchange failed"}, status=400)
    token_payload = token_response.json()
    id_token = token_payload.get("id_token")
    if not id_token:
        return JsonResponse({"error": "id_token missing"}, status=400)
    nonce = request.session.get("oidc_nonce", "")
    claims = _decode_id_token(id_token, issuer, client_id, nonce)
    if not claims:
        return JsonResponse({"error": "invalid id_token"}, status=401)
    email = claims.get("email") or ""
    allowed_domains = config.get("allowed_email_domains") or []
    if allowed_domains and email:
        domain = email.split("@")[-1].lower()
        if domain not in [d.lower() for d in allowed_domains]:
            return JsonResponse({"error": "email domain not allowed"}, status=403)
    identity, created = UserIdentity.objects.get_or_create(
        issuer=issuer,
        subject=str(claims.get("sub")),
        defaults={
            "provider": "oidc",
            "email": email,
            "display_name": claims.get("name") or claims.get("preferred_username") or "",
            "claims_json": {
                "sub": claims.get("sub"),
                "email": claims.get("email"),
                "name": claims.get("name"),
                "preferred_username": claims.get("preferred_username"),
            },
            "last_login_at": timezone.now(),
        },
    )
    if not created:
        identity.email = email
        identity.display_name = claims.get("name") or claims.get("preferred_username") or ""
        identity.claims_json = {
            "sub": claims.get("sub"),
            "email": claims.get("email"),
            "name": claims.get("name"),
            "preferred_username": claims.get("preferred_username"),
        }
        identity.last_login_at = timezone.now()
        identity.save(update_fields=["email", "display_name", "claims_json", "last_login_at", "updated_at"])
    if not RoleBinding.objects.exists() and os.environ.get("ALLOW_FIRST_ADMIN_BOOTSTRAP", "").lower() == "true":
        RoleBinding.objects.create(
            user_identity=identity,
            scope_kind="platform",
            role="platform_admin",
        )
    roles = _get_roles(identity)
    User = get_user_model()
    issuer_hash = hashlib.sha256(issuer.encode("utf-8")).hexdigest()[:12]
    username = f"oidc:{issuer_hash}:{claims.get('sub')}"
    user, created = User.objects.get_or_create(
        username=username,
        defaults={
            "email": email,
            "is_staff": ("platform_admin" in roles or "platform_architect" in roles),
            "is_active": True,
        },
    )
    if email and user.email != email:
        user.email = email
    user.is_staff = ("platform_admin" in roles or "platform_architect" in roles)
    user.is_superuser = False
    user.is_active = True
    user.save()
    if not roles:
        return JsonResponse({"error": "no roles assigned"}, status=403)
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    request.session["user_identity_id"] = str(identity.id)
    request.session["environment_id"] = str(env.id)
    redirect_to = _sanitize_return_to(
        request.session.get("post_login_redirect") or "",
        request,
        None,
        "xyn-ui",
    )
    return redirect(redirect_to)


@csrf_exempt
def auth_logout(request: HttpRequest) -> JsonResponse:
    request.session.flush()
    return JsonResponse({"status": "ok"})


@csrf_exempt
def auth_session_check(request: HttpRequest) -> HttpResponse:
    app_id = (request.GET.get("appId") or "xyn-ui").strip() or "xyn-ui"
    client = _resolve_app_config(app_id)
    forwarded_proto = (request.META.get("HTTP_X_FORWARDED_PROTO") or "https").split(",")[0].strip() or "https"
    forwarded_host = (
        (request.META.get("HTTP_X_FORWARDED_HOST") or request.get_host() or "").split(",")[0].strip()
    )
    forwarded_uri = (
        (request.META.get("HTTP_X_FORWARDED_URI") or request.get_full_path() or "/").split(",")[0].strip()
    )
    if not forwarded_uri.startswith("/"):
        forwarded_uri = f"/{forwarded_uri}"
    if app_id == "ems.platform":
        callback_uri = "/auth/callback"
        return_to_candidate = f"{forwarded_proto}://{forwarded_host}{callback_uri}" if forwarded_host else callback_uri
    else:
        return_to_candidate = f"{forwarded_proto}://{forwarded_host}{forwarded_uri}" if forwarded_host else forwarded_uri
    return_to = _sanitize_return_to(return_to_candidate, request, client, app_id)

    if request.user.is_authenticated and request.session.get("user_identity_id"):
        return JsonResponse({"status": "ok"})

    login_url = f"/auth/login?appId={quote(app_id, safe='')}&returnTo={quote(return_to, safe='')}"
    return redirect(login_url)


def api_me(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    roles = _get_roles(identity)
    memberships = WorkspaceMembership.objects.filter(user_identity=identity).select_related("workspace").order_by("workspace__name")
    return JsonResponse(
        {
            "user": {
                "issuer": identity.issuer,
                "subject": identity.subject,
                "email": identity.email,
                "display_name": identity.display_name,
            },
            "roles": roles,
            "workspaces": [
                {
                    "id": str(m.workspace_id),
                    "slug": m.workspace.slug,
                    "name": m.workspace.name,
                    "role": m.role,
                    "termination_authority": m.termination_authority,
                }
                for m in memberships
            ],
        }
    )


def _serialize_tenant(tenant: Tenant) -> Dict[str, Any]:
    return {
        "id": str(tenant.id),
        "name": tenant.name,
        "slug": tenant.slug,
        "status": tenant.status,
        "metadata_json": tenant.metadata_json,
        "created_at": tenant.created_at,
        "updated_at": tenant.updated_at,
    }


def _serialize_contact(contact: Contact) -> Dict[str, Any]:
    return {
        "id": str(contact.id),
        "tenant_id": str(contact.tenant_id),
        "name": contact.name,
        "email": contact.email,
        "phone": contact.phone,
        "role_title": contact.role_title,
        "status": contact.status,
        "metadata_json": contact.metadata_json,
        "created_at": contact.created_at,
        "updated_at": contact.updated_at,
    }


def _serialize_membership(membership: TenantMembership) -> Dict[str, Any]:
    return {
        "id": str(membership.id),
        "tenant_id": str(membership.tenant_id),
        "user_identity_id": str(membership.user_identity_id),
        "role": membership.role,
        "status": membership.status,
        "created_at": membership.created_at,
        "updated_at": membership.updated_at,
    }


def _default_branding() -> Dict[str, Any]:
    return {
        "display_name": "Xyn Console",
        "logo_url": "/xyence-logo.png",
        "theme": {},
    }


_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_GRADIENT_RE = re.compile(r"^linear-gradient\([a-zA-Z0-9\s,#.%()-]+\)$")


def _default_platform_branding() -> Dict[str, Any]:
    return {
        "brand_name": "Xyn",
        "logo_url": "/xyence-logo.png",
        "favicon_url": "",
        "primary_color": "#0f4c81",
        "background_color": "#f5f7fb",
        "background_gradient": "",
        "text_color": "#10203a",
        "font_family": "Space Grotesk, Source Sans 3, sans-serif",
        "button_radius_px": 12,
    }


def _get_platform_branding() -> PlatformBranding:
    defaults = _default_platform_branding()
    branding, _created = PlatformBranding.objects.get_or_create(
        id=PlatformBranding.objects.order_by("created_at").values_list("id", flat=True).first() or uuid.uuid4(),
        defaults={
            "brand_name": defaults["brand_name"],
            "logo_url": defaults["logo_url"],
            "favicon_url": defaults["favicon_url"],
            "primary_color": defaults["primary_color"],
            "background_color": defaults["background_color"],
            "background_gradient": defaults["background_gradient"],
            "text_color": defaults["text_color"],
            "font_family": defaults["font_family"],
            "button_radius_px": defaults["button_radius_px"],
        },
    )
    return branding


def _serialize_platform_branding(branding: PlatformBranding) -> Dict[str, Any]:
    return {
        "brand_name": branding.brand_name,
        "logo_url": branding.logo_url or "",
        "favicon_url": branding.favicon_url or "",
        "primary_color": branding.primary_color,
        "background_color": branding.background_color,
        "background_gradient": branding.background_gradient or "",
        "text_color": branding.text_color,
        "font_family": branding.font_family or "",
        "button_radius_px": int(branding.button_radius_px or 12),
        "updated_at": branding.updated_at,
    }


def _serialize_app_branding_override(override: Optional[AppBrandingOverride], app_id: str) -> Dict[str, Any]:
    if not override:
        return {
            "app_id": app_id,
            "display_name": "",
            "logo_url": "",
            "primary_color": "",
            "background_color": "",
            "background_gradient": "",
            "text_color": "",
            "font_family": "",
            "button_radius_px": None,
            "updated_at": None,
        }
    return {
        "app_id": override.app_id,
        "display_name": override.display_name or "",
        "logo_url": override.logo_url or "",
        "primary_color": override.primary_color or "",
        "background_color": override.background_color or "",
        "background_gradient": override.background_gradient or "",
        "text_color": override.text_color or "",
        "font_family": override.font_family or "",
        "button_radius_px": override.button_radius_px,
        "updated_at": override.updated_at,
    }


def _merge_branding_for_app(app_id: str) -> Dict[str, Any]:
    base = _serialize_platform_branding(_get_platform_branding())
    override = AppBrandingOverride.objects.filter(app_id=app_id).first()
    payload = _serialize_app_branding_override(override, app_id)
    display_name = payload["display_name"] or base["brand_name"]
    merged = {
        "app_id": app_id,
        "brand_name": display_name,
        "display_name": display_name,
        "logo_url": payload["logo_url"] or base["logo_url"],
        "favicon_url": base["favicon_url"],
        "primary_color": payload["primary_color"] or base["primary_color"],
        "background_color": payload["background_color"] or base["background_color"],
        "background_gradient": payload["background_gradient"] or base["background_gradient"],
        "text_color": payload["text_color"] or base["text_color"],
        "font_family": payload["font_family"] or base["font_family"],
        "button_radius_px": payload["button_radius_px"] if payload["button_radius_px"] is not None else base["button_radius_px"],
    }
    merged["css_variables"] = {
        "--brand-primary": merged["primary_color"],
        "--brand-bg": merged["background_color"],
        "--brand-text": merged["text_color"],
        "--brand-radius": f"{int(merged['button_radius_px'])}px",
        "--brand-font": merged["font_family"],
    }
    if merged["background_gradient"]:
        merged["css_variables"]["--brand-bg-gradient"] = merged["background_gradient"]
    return merged


def _branding_tokens_for_app(app_id: str) -> Dict[str, Any]:
    merged = _merge_branding_for_app(app_id)
    radius = int(merged.get("button_radius_px") or 12)
    brand_name = str(merged.get("display_name") or merged.get("brand_name") or "Xyn").strip() or "Xyn"
    return {
        "appKey": app_id,
        "brandName": brand_name,
        "logoUrl": merged.get("logo_url") or "",
        "faviconUrl": merged.get("favicon_url") or "",
        "colors": {
            "primary": merged.get("primary_color") or "#0f4c81",
            "text": merged.get("text_color") or "#10203a",
            "mutedText": "#475569",
            "bg": merged.get("background_color") or "#f5f7fb",
            "surface": "#ffffff",
            "border": "#dbe3ef",
        },
        "radii": {
            "button": radius,
            "card": max(radius + 4, 16),
        },
        "fonts": {
            "ui": merged.get("font_family") or "Space Grotesk, Source Sans 3, sans-serif",
        },
        "spacing": {
            "pageMaxWidth": 1120,
            "gutter": 24,
        },
        "shadows": {
            "card": "0 10px 28px rgba(2, 6, 23, 0.08)",
        },
    }


def _branding_theme_css(tokens: Dict[str, Any]) -> str:
    colors = tokens.get("colors") or {}
    radii = tokens.get("radii") or {}
    fonts = tokens.get("fonts") or {}
    spacing = tokens.get("spacing") or {}
    shadows = tokens.get("shadows") or {}
    gradient = ""
    app_id = str(tokens.get("appKey") or "xyn-ui").strip() or "xyn-ui"
    merged = _merge_branding_for_app(app_id)
    if merged.get("background_gradient"):
        gradient = str(merged["background_gradient"])
    safe_brand_name = str(tokens.get("brandName") or "Xyn").replace('"', '\\"')
    safe_logo_url = str(tokens.get("logoUrl") or "").replace('"', '\\"')
    lines = [
        ":root {",
        f"  --xyn-brand-name: \"{safe_brand_name}\";",
        f"  --xyn-logo-url: \"{safe_logo_url}\";",
        f"  --xyn-color-primary: {colors.get('primary') or '#0f4c81'};",
        f"  --xyn-color-text: {colors.get('text') or '#10203a'};",
        f"  --xyn-color-muted: {colors.get('mutedText') or '#475569'};",
        f"  --xyn-color-bg: {colors.get('bg') or '#f5f7fb'};",
        f"  --xyn-color-surface: {colors.get('surface') or '#ffffff'};",
        f"  --xyn-color-border: {colors.get('border') or '#dbe3ef'};",
        f"  --xyn-radius-button: {int(radii.get('button') or 12)}px;",
        f"  --xyn-radius-card: {int(radii.get('card') or 16)}px;",
        f"  --xyn-font-ui: {fonts.get('ui') or 'Space Grotesk, Source Sans 3, sans-serif'};",
        f"  --xyn-spacing-page-max: {int(spacing.get('pageMaxWidth') or 1120)}px;",
        f"  --xyn-spacing-gutter: {int(spacing.get('gutter') or 24)}px;",
        f"  --xyn-shadow-card: {shadows.get('card') or '0 10px 28px rgba(2, 6, 23, 0.08)'};",
        f"  --brand-primary: {colors.get('primary') or '#0f4c81'};",
        f"  --brand-bg: {colors.get('bg') or '#f5f7fb'};",
        f"  --brand-text: {colors.get('text') or '#10203a'};",
        f"  --brand-radius: {int(radii.get('button') or 12)}px;",
        f"  --brand-font: {fonts.get('ui') or 'Space Grotesk, Source Sans 3, sans-serif'};",
    ]
    if gradient:
        lines.append(f"  --xyn-bg-gradient: {gradient};")
        lines.append(f"  --brand-bg-gradient: {gradient};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _set_theme_headers(response: HttpResponse, body: str) -> HttpResponse:
    etag = hashlib.sha256(body.encode("utf-8")).hexdigest()
    response["ETag"] = f"\"{etag}\""
    response["Cache-Control"] = "public, max-age=300"
    response["Access-Control-Allow-Origin"] = "*"
    response["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    response["Access-Control-Allow-Headers"] = "Content-Type"
    return response


def _validate_branding_payload(payload: Dict[str, Any], partial: bool = True) -> Dict[str, str]:
    errors: Dict[str, str] = {}
    color_fields = ("primary_color", "background_color", "text_color")
    for field in color_fields:
        if field not in payload and partial:
            continue
        value = (payload.get(field) or "").strip()
        if value and not _HEX_COLOR_RE.match(value):
            errors[field] = "must be a hex color like #0f4c81"
    if "background_gradient" in payload:
        gradient = (payload.get("background_gradient") or "").strip()
        if gradient and not _GRADIENT_RE.match(gradient):
            errors["background_gradient"] = "must be a safe linear-gradient(...) value"
    if "button_radius_px" in payload:
        try:
            radius = int(payload.get("button_radius_px"))
        except Exception:
            errors["button_radius_px"] = "must be an integer"
        else:
            if radius < 0 or radius > 32:
                errors["button_radius_px"] = "must be between 0 and 32"
    return errors


def _default_post_login_redirect(client: Optional[AppOIDCClient], app_id: str) -> str:
    if app_id == "xyn-ui":
        return "/app"
    if client:
        post_logout_uris = client.post_logout_redirect_uris_json or []
        if post_logout_uris:
            first = str(post_logout_uris[0] or "").strip()
            if first:
                return first
    return "/"


def _sanitize_return_to(raw_value: str, request: HttpRequest, client: Optional[AppOIDCClient], app_id: str) -> str:
    fallback = _default_post_login_redirect(client, app_id)
    value = (raw_value or "").strip()
    if not value:
        return fallback
    split = urlsplit(value)
    if split.scheme and split.scheme not in {"http", "https"}:
        return fallback
    if split.scheme == "":
        if not value.startswith("/") or value.startswith("//"):
            return fallback
        return value
    env_hosts = {
        host.strip().lower()
        for host in os.environ.get("XYENCE_ALLOWED_RETURN_HOSTS", "").split(",")
        if host.strip()
    }
    allowed_host_suffixes = {
        suffix.strip().lower().lstrip(".")
        for suffix in os.environ.get("XYENCE_ALLOWED_RETURN_HOST_SUFFIXES", "xyence.io").split(",")
        if suffix.strip()
    }
    allowed_hosts = {request.get_host().lower(), *env_hosts}
    if client:
        for uri in (client.redirect_uris_json or []) + (client.post_logout_redirect_uris_json or []):
            try:
                netloc = urlsplit(uri).netloc.lower()
            except Exception:
                netloc = ""
            if netloc:
                allowed_hosts.add(netloc)
    target_netloc = split.netloc.lower()
    target_host = (split.hostname or "").lower()
    exact_allowed = target_netloc in allowed_hosts or target_host in allowed_hosts
    suffix_allowed = any(
        target_host == suffix or target_host.endswith(f".{suffix}")
        for suffix in allowed_host_suffixes
    )
    if not exact_allowed and not suffix_allowed:
        return fallback
    return urlunsplit(split)


def _serialize_branding(profile: Optional[BrandProfile]) -> Dict[str, Any]:
    if not profile:
        return _default_branding()
    theme = profile.theme_json or {}
    if profile.primary_color:
        theme = {**theme, "--accent": profile.primary_color}
    if profile.secondary_color:
        theme = {**theme, "--accent-secondary": profile.secondary_color}
    return {
        "display_name": profile.display_name or _default_branding()["display_name"],
        "logo_url": profile.logo_url or _default_branding()["logo_url"],
        "theme": theme,
    }


def _serialize_device(device: Device) -> Dict[str, Any]:
    return {
        "id": str(device.id),
        "tenant_id": str(device.tenant_id),
        "name": device.name,
        "device_type": device.device_type,
        "mgmt_ip": device.mgmt_ip,
        "status": device.status,
        "tags": device.tags,
        "metadata_json": device.metadata_json,
        "created_at": device.created_at,
        "updated_at": device.updated_at,
    }


def _artifact_slug(artifact: Artifact) -> str:
    if artifact.slug:
        return artifact.slug
    ref = ArtifactExternalRef.objects.filter(artifact=artifact).exclude(slug_path="").order_by("created_at").first()
    if ref:
        return ref.slug_path
    return str((artifact.scope_json or {}).get("slug") or "")


def _normalize_artifact_slug(raw_slug: str, *, fallback_title: str = "") -> str:
    candidate = str(raw_slug or "").strip().lower()
    if not candidate and fallback_title:
        candidate = slugify(fallback_title)
    return slugify(candidate).strip().lower()


def _artifact_slug_exists(workspace_id: str, slug: str, *, exclude_artifact_id: Optional[str] = None) -> bool:
    if not slug:
        return False
    qs = Artifact.objects.filter(workspace_id=workspace_id, slug=slug)
    if exclude_artifact_id:
        qs = qs.exclude(id=exclude_artifact_id)
    return qs.exists()


def _latest_artifact_revision(artifact: Artifact) -> Optional[ArtifactRevision]:
    return ArtifactRevision.objects.filter(artifact=artifact).order_by("-revision_number").first()


def _serialize_artifact_summary(artifact: Artifact) -> Dict[str, Any]:
    latest = _latest_artifact_revision(artifact)
    content = latest.content_json if latest else {}
    return {
        "id": str(artifact.id),
        "workspace_id": str(artifact.workspace_id),
        "type": artifact.type.slug,
        "title": artifact.title,
        "slug": _artifact_slug(artifact),
        "status": artifact.status,
        "version": artifact.version,
        "visibility": artifact.visibility,
        "published_at": artifact.published_at,
        "updated_at": artifact.updated_at,
        "content": {
            "summary": content.get("summary") or "",
            "tags": content.get("tags") or [],
        },
    }


def _serialize_comment(comment: ArtifactComment) -> Dict[str, Any]:
    return {
        "id": str(comment.id),
        "artifact_id": str(comment.artifact_id),
        "user_id": str(comment.user_id) if comment.user_id else None,
        "parent_comment_id": str(comment.parent_comment_id) if comment.parent_comment_id else None,
        "body": comment.body,
        "status": comment.status,
        "created_at": comment.created_at,
    }


@csrf_exempt
def workspaces_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    memberships = WorkspaceMembership.objects.filter(user_identity=identity).select_related("workspace").order_by("workspace__name")
    return JsonResponse(
        {
            "workspaces": [
                {
                    "id": str(m.workspace_id),
                    "slug": m.workspace.slug,
                    "name": m.workspace.name,
                    "description": m.workspace.description,
                    "role": m.role,
                    "termination_authority": m.termination_authority,
                }
                for m in memberships
            ]
        }
    )


@csrf_exempt
def workspace_artifacts_collection(request: HttpRequest, workspace_id: str) -> JsonResponse:
    workspace = get_object_or_404(Workspace, id=workspace_id)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    membership = _workspace_membership(identity, workspace_id)
    if not membership:
        return JsonResponse({"error": "forbidden"}, status=403)
    if request.method == "POST":
        if not _workspace_has_role(identity, workspace_id, "contributor"):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        type_slug = str(payload.get("type") or "article").strip().lower()
        artifact_type = ArtifactType.objects.filter(slug=type_slug).first()
        if not artifact_type:
            return JsonResponse({"error": "artifact type not found"}, status=404)
        title = str(payload.get("title") or "").strip()
        if not title:
            return JsonResponse({"error": "title is required"}, status=400)
        slug = _normalize_artifact_slug(str(payload.get("slug") or ""), fallback_title=title)
        if not slug:
            return JsonResponse({"error": "slug is required"}, status=400)
        if _artifact_slug_exists(str(workspace.id), slug):
            return JsonResponse({"error": "slug already exists in this workspace"}, status=400)
        body_markdown = str(payload.get("body_markdown") or "")
        body_html = str(payload.get("body_html") or "")
        summary = str(payload.get("summary") or "")
        tags = payload.get("tags") if isinstance(payload.get("tags"), list) else []
        visibility = str(payload.get("visibility") or "private")
        if visibility not in {"private", "team", "public"}:
            visibility = "private"
        with transaction.atomic():
            artifact = Artifact.objects.create(
                workspace=workspace,
                type=artifact_type,
                title=title,
                slug=slug,
                status="draft",
                version=1,
                visibility=visibility,
                author=identity,
                custodian=identity,
                scope_json={"slug": slug, "summary": summary},
                provenance_json={"source_system": "shine", "source_id": None},
            )
            ArtifactRevision.objects.create(
                artifact=artifact,
                revision_number=1,
                content_json={
                    "title": title,
                    "summary": summary,
                    "body_markdown": body_markdown,
                    "body_html": body_html,
                    "tags": tags,
                },
                created_by=identity,
            )
            ArtifactExternalRef.objects.create(
                artifact=artifact,
                system="shine",
                external_id=str(artifact.id),
                slug_path=slug,
            )
            _record_artifact_event(artifact, "artifact_created", identity, {"workspace_id": str(workspace.id)})
        return JsonResponse({"id": str(artifact.id)})

    artifact_type = request.GET.get("type") or ""
    status = request.GET.get("status") or ""
    qs = Artifact.objects.filter(workspace=workspace).select_related("type")
    if artifact_type:
        qs = qs.filter(type__slug=artifact_type)
    if status:
        qs = qs.filter(status=status)
    if membership.role == "reader":
        qs = qs.filter(status="published").filter(visibility__in=["team", "public"])
    data = [_serialize_artifact_summary(item) for item in qs.order_by("-published_at", "-updated_at")]
    return JsonResponse({"artifacts": data})


@csrf_exempt
def workspace_artifact_detail(request: HttpRequest, workspace_id: str, artifact_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    membership = _workspace_membership(identity, workspace_id)
    if not membership:
        return JsonResponse({"error": "forbidden"}, status=403)
    artifact = get_object_or_404(Artifact.objects.select_related("type"), id=artifact_id, workspace_id=workspace_id)
    latest = _latest_artifact_revision(artifact)
    if request.method in ("PATCH", "PUT"):
        if not _workspace_has_role(identity, workspace_id, "contributor"):
            return JsonResponse({"error": "forbidden"}, status=403)
        if artifact.author_id and str(artifact.author_id) != str(identity.id) and not _workspace_has_role(identity, workspace_id, "admin"):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        content = dict((latest.content_json if latest else {}) or {})
        for key in ["title", "summary", "body_markdown", "body_html", "tags"]:
            if key in payload:
                content[key] = payload.get(key)
        if "title" in payload:
            artifact.title = str(payload.get("title") or artifact.title)
        if "visibility" in payload and payload.get("visibility") in {"private", "team", "public"}:
            artifact.visibility = payload.get("visibility")
        if "slug" in payload:
            slug = _normalize_artifact_slug(str(payload.get("slug") or ""), fallback_title=artifact.title)
            if slug:
                if _artifact_slug_exists(str(workspace_id), slug, exclude_artifact_id=str(artifact.id)):
                    return JsonResponse({"error": "slug already exists in this workspace"}, status=400)
                artifact.slug = slug
                scope = dict(artifact.scope_json or {})
                scope["slug"] = slug
                artifact.scope_json = scope
                ArtifactExternalRef.objects.update_or_create(
                    artifact=artifact,
                    system="shine",
                    defaults={"external_id": str(artifact.id), "slug_path": slug},
                )
        ai_metadata = payload.get("ai_metadata") if isinstance(payload.get("ai_metadata"), dict) else None
        if ai_metadata:
            provenance = dict(artifact.provenance_json or {})
            provenance["last_ai_invocation"] = {
                "agent_slug": ai_metadata.get("agent_slug"),
                "provider": ai_metadata.get("provider"),
                "model_name": ai_metadata.get("model_name"),
                "invoked_at": ai_metadata.get("invoked_at") or timezone.now().isoformat(),
                "mode": ai_metadata.get("mode"),
            }
            artifact.provenance_json = provenance
        artifact.version = _next_artifact_revision_number(artifact)
        artifact.save(update_fields=["title", "slug", "visibility", "scope_json", "provenance_json", "version", "updated_at"])
        ArtifactRevision.objects.create(
            artifact=artifact,
            revision_number=artifact.version,
            content_json=content,
            created_by=identity,
        )
        _record_artifact_event(artifact, "artifact_revised", identity, {"version": artifact.version})
        if ai_metadata:
            _record_artifact_event(
                artifact,
                "ai_invocation",
                identity,
                {
                    "version": artifact.version,
                    "agent_slug": ai_metadata.get("agent_slug"),
                    "provider": ai_metadata.get("provider"),
                    "model_name": ai_metadata.get("model_name"),
                    "mode": ai_metadata.get("mode"),
                },
            )
        latest = _latest_artifact_revision(artifact)

    reaction_counts = {"endorse": 0, "oppose": 0, "neutral": 0}
    for row in ArtifactReaction.objects.filter(artifact=artifact).values("value").annotate(count=models.Count("id")):
        reaction_counts[str(row["value"])] = int(row["count"])
    comments = ArtifactComment.objects.filter(artifact=artifact).order_by("created_at")
    payload = {
        **_serialize_artifact_summary(artifact),
        "content": (latest.content_json if latest else {}) or {},
        "provenance_json": artifact.provenance_json or {},
        "scope_json": artifact.scope_json or {},
        "reactions": reaction_counts,
        "comments": [_serialize_comment(comment) for comment in comments],
    }
    return JsonResponse(payload)


@csrf_exempt
def workspace_artifact_publish(request: HttpRequest, workspace_id: str, artifact_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _workspace_has_role(identity, workspace_id, "publisher"):
        return JsonResponse({"error": "publisher role required"}, status=403)
    if not _workspace_has_termination_authority(identity, workspace_id):
        return JsonResponse({"error": "termination authority required"}, status=403)
    artifact = get_object_or_404(Artifact, id=artifact_id, workspace_id=workspace_id)
    artifact.status = "published"
    artifact.visibility = "public"
    artifact.published_at = timezone.now()
    artifact.ratified_by = identity
    artifact.ratified_at = timezone.now()
    artifact.save(update_fields=["status", "visibility", "published_at", "ratified_by", "ratified_at", "updated_at"])
    _record_artifact_event(artifact, "article_published", identity, {"status": "published"})
    return JsonResponse({"id": str(artifact.id), "status": artifact.status})


@csrf_exempt
def workspace_artifact_deprecate(request: HttpRequest, workspace_id: str, artifact_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _workspace_has_role(identity, workspace_id, "publisher"):
        return JsonResponse({"error": "forbidden"}, status=403)
    artifact = get_object_or_404(Artifact, id=artifact_id, workspace_id=workspace_id)
    artifact.status = "deprecated"
    artifact.save(update_fields=["status", "updated_at"])
    _record_artifact_event(artifact, "artifact_deprecated", identity, {})
    return JsonResponse({"id": str(artifact.id), "status": artifact.status})


@csrf_exempt
def workspace_artifact_reactions_collection(request: HttpRequest, workspace_id: str, artifact_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _workspace_has_role(identity, workspace_id, "contributor"):
        return JsonResponse({"error": "forbidden"}, status=403)
    artifact = get_object_or_404(Artifact, id=artifact_id, workspace_id=workspace_id)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    value = str(payload.get("value") or "").strip().lower()
    if value not in {"endorse", "oppose", "neutral"}:
        return JsonResponse({"error": "value must be endorse|oppose|neutral"}, status=400)
    ArtifactReaction.objects.update_or_create(
        artifact=artifact,
        user=identity,
        defaults={"value": value},
    )
    _record_artifact_event(artifact, "reaction_set", identity, {"value": value})
    return JsonResponse({"status": "ok"})


@csrf_exempt
def workspace_artifact_comments_collection(request: HttpRequest, workspace_id: str, artifact_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = get_object_or_404(Artifact, id=artifact_id, workspace_id=workspace_id)
    if request.method == "POST":
        if not _workspace_has_role(identity, workspace_id, "contributor"):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        body = str(payload.get("body") or "").strip()
        if not body:
            return JsonResponse({"error": "body is required"}, status=400)
        parent_id = payload.get("parent_comment_id")
        parent = ArtifactComment.objects.filter(id=parent_id, artifact=artifact).first() if parent_id else None
        comment = ArtifactComment.objects.create(
            artifact=artifact,
            user=identity,
            parent_comment=parent,
            body=body,
        )
        _record_artifact_event(artifact, "comment_created", identity, {"comment_id": str(comment.id)})
        return JsonResponse({"id": str(comment.id)})
    comments = ArtifactComment.objects.filter(artifact=artifact).order_by("created_at")
    return JsonResponse({"comments": [_serialize_comment(comment) for comment in comments]})


@csrf_exempt
def workspace_artifact_comment_detail(request: HttpRequest, workspace_id: str, artifact_id: str, comment_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = get_object_or_404(Artifact, id=artifact_id, workspace_id=workspace_id)
    comment = get_object_or_404(ArtifactComment, id=comment_id, artifact=artifact)
    if request.method != "PATCH":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if not _workspace_has_role(identity, workspace_id, "moderator"):
        return JsonResponse({"error": "forbidden"}, status=403)
    payload = _parse_json(request)
    status = str(payload.get("status") or "").strip().lower()
    if status not in {"hidden", "deleted"}:
        return JsonResponse({"error": "status must be hidden or deleted"}, status=400)
    comment.status = status
    comment.save(update_fields=["status"])
    event_type = "comment_hidden" if status == "hidden" else "comment_deleted"
    _record_artifact_event(artifact, event_type, identity, {"comment_id": str(comment.id)})
    return JsonResponse({"id": str(comment.id), "status": comment.status})


@csrf_exempt
def workspace_activity(request: HttpRequest, workspace_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _workspace_membership(identity, workspace_id):
        return JsonResponse({"error": "forbidden"}, status=403)
    events = (
        ArtifactEvent.objects.filter(artifact__workspace_id=workspace_id)
        .select_related("artifact", "actor")
        .order_by("-created_at")[:300]
    )
    data = [
        {
            "id": str(event.id),
            "artifact_id": str(event.artifact_id),
            "artifact_title": event.artifact.title,
            "event_type": event.event_type,
            "actor_id": str(event.actor_id) if event.actor_id else None,
            "payload_json": event.payload_json or {},
            "created_at": event.created_at,
        }
        for event in events
    ]
    return JsonResponse({"events": data})


@csrf_exempt
def workspace_memberships_collection(request: HttpRequest, workspace_id: str) -> JsonResponse:
    workspace = get_object_or_404(Workspace, id=workspace_id)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method == "POST":
        if not _workspace_has_role(identity, workspace_id, "admin"):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        user_identity_id = str(payload.get("user_identity_id") or "")
        role = str(payload.get("role") or "").strip().lower()
        termination_authority = bool(payload.get("termination_authority", False))
        if role not in WORKSPACE_ROLE_RANK:
            return JsonResponse({"error": "invalid role"}, status=400)
        user_identity = get_object_or_404(UserIdentity, id=user_identity_id)
        membership, _ = WorkspaceMembership.objects.update_or_create(
            workspace=workspace,
            user_identity=user_identity,
            defaults={"role": role, "termination_authority": termination_authority},
        )
        return JsonResponse({"id": str(membership.id)})
    members = WorkspaceMembership.objects.filter(workspace=workspace).select_related("user_identity").order_by("user_identity__email")
    return JsonResponse(
        {
            "memberships": [
                {
                    "id": str(member.id),
                    "workspace_id": str(member.workspace_id),
                    "user_identity_id": str(member.user_identity_id),
                    "email": member.user_identity.email,
                    "display_name": member.user_identity.display_name,
                    "role": member.role,
                    "termination_authority": member.termination_authority,
                }
                for member in members
            ]
        }
    )


@csrf_exempt
def workspace_membership_detail(request: HttpRequest, workspace_id: str, membership_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _workspace_has_role(identity, workspace_id, "admin"):
        return JsonResponse({"error": "forbidden"}, status=403)
    membership = get_object_or_404(WorkspaceMembership, id=membership_id, workspace_id=workspace_id)
    if request.method != "PATCH":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    role = str(payload.get("role") or membership.role).strip().lower()
    if role not in WORKSPACE_ROLE_RANK:
        return JsonResponse({"error": "invalid role"}, status=400)
    membership.role = role
    if "termination_authority" in payload:
        membership.termination_authority = bool(payload.get("termination_authority"))
    membership.save(update_fields=["role", "termination_authority", "updated_at"])
    return JsonResponse({"id": str(membership.id)})


@csrf_exempt
def docs_by_route(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    route_id = str(request.GET.get("route_id") or "").strip()
    if not route_id:
        return JsonResponse({"error": "route_id is required"}, status=400)
    _ensure_doc_artifact_type()
    workspace_id = str(request.GET.get("workspace_id") or "").strip()
    qs = Artifact.objects.filter(type__slug=DOC_ARTIFACT_TYPE_SLUG).select_related("type", "workspace", "author")
    if workspace_id:
        qs = qs.filter(workspace_id=workspace_id)
    if not _can_manage_docs(identity):
        qs = qs.filter(status="published", visibility__in=["public", "team"])
    candidates: list[Artifact] = []
    for artifact in qs.order_by("-published_at", "-updated_at", "-created_at"):
        bindings = _normalize_doc_route_bindings((artifact.scope_json or {}).get("route_bindings"))
        if route_id in bindings:
            candidates.append(artifact)
    doc = candidates[0] if candidates else None
    if not doc:
        return JsonResponse({"doc": None, "route_id": route_id})
    return JsonResponse({"doc": _serialize_doc_page(doc), "route_id": route_id})


@csrf_exempt
def docs_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    docs_workspace = _docs_workspace()
    doc_type = _ensure_doc_artifact_type()
    if request.method == "POST":
        if not _can_manage_docs(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        title = str(payload.get("title") or "").strip()
        if not title:
            return JsonResponse({"error": "title is required"}, status=400)
        slug = _normalize_artifact_slug(str(payload.get("slug") or ""), fallback_title=title)
        if not slug:
            return JsonResponse({"error": "slug is required"}, status=400)
        if _artifact_slug_exists(str(docs_workspace.id), slug):
            return JsonResponse({"error": "slug already exists in docs workspace"}, status=400)
        visibility = str(payload.get("visibility") or "team").strip().lower()
        if visibility not in {"private", "team", "public"}:
            visibility = "team"
        route_bindings = _normalize_doc_route_bindings(payload.get("route_bindings"))
        tags = _normalize_doc_tags(payload.get("tags"))
        summary = str(payload.get("summary") or "")
        body_markdown = str(payload.get("body_markdown") or "")
        with transaction.atomic():
            artifact = Artifact.objects.create(
                workspace=docs_workspace,
                type=doc_type,
                title=title,
                slug=slug,
                status="draft",
                version=1,
                visibility=visibility,
                author=identity,
                custodian=identity,
                scope_json={"route_bindings": route_bindings, "slug": slug},
                provenance_json={"source_system": "shine", "source_id": None},
            )
            revision = ArtifactRevision.objects.create(
                artifact=artifact,
                revision_number=1,
                content_json={
                    "title": title,
                    "summary": summary,
                    "body_markdown": body_markdown,
                    "tags": tags,
                },
                created_by=identity,
            )
            _record_artifact_event(
                artifact,
                "doc_created",
                identity,
                {"route_bindings": route_bindings, "visibility": visibility},
            )
        return JsonResponse({"doc": _serialize_doc_page(artifact, revision)})

    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    tags_query = str(request.GET.get("tags") or "").strip()
    tags_filter = {tag.strip().lower() for tag in tags_query.split(",") if tag.strip()} if tags_query else set()
    include_drafts = request.GET.get("include_drafts") == "1"
    qs = Artifact.objects.filter(type__slug=DOC_ARTIFACT_TYPE_SLUG).select_related("type", "workspace")
    if not _can_manage_docs(identity) or not include_drafts:
        qs = qs.filter(status="published", visibility__in=["public", "team"])
    docs: list[Dict[str, Any]] = []
    for artifact in qs.order_by("-published_at", "-updated_at", "-created_at"):
        serialized = _serialize_doc_page(artifact)
        doc_tags = set(serialized.get("tags") or [])
        if tags_filter and not tags_filter.issubset(doc_tags):
            continue
        docs.append(serialized)
    return JsonResponse({"docs": docs})


@csrf_exempt
def doc_detail_by_slug(request: HttpRequest, slug: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = get_object_or_404(Artifact.objects.select_related("type"), type__slug=DOC_ARTIFACT_TYPE_SLUG, slug=slug)
    if not _can_view_doc(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    return JsonResponse({"doc": _serialize_doc_page(artifact)})


@csrf_exempt
def doc_detail(request: HttpRequest, doc_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = get_object_or_404(Artifact.objects.select_related("type"), id=doc_id, type__slug=DOC_ARTIFACT_TYPE_SLUG)
    if request.method in {"PUT", "PATCH"}:
        if not _can_manage_docs(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        latest = _latest_artifact_revision(artifact)
        content = dict((latest.content_json if latest else {}) or {})
        if "title" in payload:
            artifact.title = str(payload.get("title") or artifact.title).strip() or artifact.title
            content["title"] = artifact.title
        if "slug" in payload:
            normalized_slug = _normalize_artifact_slug(str(payload.get("slug") or ""), fallback_title=artifact.title)
            if not normalized_slug:
                return JsonResponse({"error": "slug is required"}, status=400)
            if _artifact_slug_exists(str(artifact.workspace_id), normalized_slug, exclude_artifact_id=str(artifact.id)):
                return JsonResponse({"error": "slug already exists in docs workspace"}, status=400)
            artifact.slug = normalized_slug
        if "visibility" in payload:
            visibility = str(payload.get("visibility") or "").strip().lower()
            if visibility not in {"private", "team", "public"}:
                return JsonResponse({"error": "invalid visibility"}, status=400)
            artifact.visibility = visibility
        if "summary" in payload:
            content["summary"] = str(payload.get("summary") or "")
        if "body_markdown" in payload:
            content["body_markdown"] = str(payload.get("body_markdown") or "")
        if "tags" in payload:
            content["tags"] = _normalize_doc_tags(payload.get("tags"))
        scope = dict(artifact.scope_json or {})
        if "route_bindings" in payload:
            scope["route_bindings"] = _normalize_doc_route_bindings(payload.get("route_bindings"))
        if artifact.slug:
            scope["slug"] = artifact.slug
        artifact.scope_json = scope
        artifact.version = _next_artifact_revision_number(artifact)
        artifact.save(update_fields=["title", "slug", "visibility", "scope_json", "version", "updated_at"])
        revision = ArtifactRevision.objects.create(
            artifact=artifact,
            revision_number=artifact.version,
            content_json=content,
            created_by=identity,
        )
        _record_artifact_event(artifact, "doc_updated", identity, {"version": artifact.version})
        return JsonResponse({"doc": _serialize_doc_page(artifact, revision)})

    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if not _can_view_doc(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    return JsonResponse({"doc": _serialize_doc_page(artifact)})


@csrf_exempt
def doc_publish(request: HttpRequest, doc_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _can_manage_docs(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    artifact = get_object_or_404(Artifact, id=doc_id, type__slug=DOC_ARTIFACT_TYPE_SLUG)
    artifact.status = "published"
    if artifact.visibility == "private":
        artifact.visibility = "team"
    artifact.published_at = timezone.now()
    artifact.ratified_by = identity
    artifact.ratified_at = timezone.now()
    artifact.save(update_fields=["status", "visibility", "published_at", "ratified_by", "ratified_at", "updated_at"])
    _record_artifact_event(artifact, "doc_published", identity, {"status": "published"})
    return JsonResponse({"doc": _serialize_doc_page(artifact)})


def _subscriber_notes_prompt_template() -> str:
    return (
        "Create a Subscriber Notes app for a telecom support team.\n\n"
        "Requirements:\n"
        "- Show a list of subscriber notes with created time and status.\n"
        "- Allow add, edit, and archive note entries.\n"
        "- Include search/filter by subscriber id and status.\n"
        "- Keep UI minimal and readable for operator workflows.\n"
        "- Expose API endpoints for list/create/update/archive."
    )


def _default_tour_payload(slug: str) -> Dict[str, Any]:
    if slug != "deploy-subscriber-notes":
        return {"error": "tour not found"}
    return {
        "schema_version": 2,
        "slug": "deploy-subscriber-notes",
        "title": "Deploy Subscriber Notes",
        "description": "Draft to deployment lifecycle with deterministic naming and resilient guidance.",
        "variables": {
            "short_id": {"type": "generated", "format": "base32", "length": 8},
            "draft_name": {"type": "template", "value": "subscriber-notes-${short_id}"},
            "subscriber_notes_prompt": {"type": "static", "value": _subscriber_notes_prompt_template()},
        },
        "steps": [
            {
                "id": "intro",
                "route": "/app/drafts",
                "attach": {"selector": None, "fallback": "center"},
                "title": "Drafts are where intent becomes structure",
                "body": (
                    "Draft Sessions capture the shape of what you want to build before turning it into a reusable blueprint. "
                    "This keeps experimentation separate from published artifacts. "
                    "In this tour you will create one fresh draft and move it through release and deployment."
                ),
                "actions": [],
                "wait_for": None,
            },
            {
                "id": "draft-create",
                "route": "/app/drafts",
                "attach": {"selector": "[data-tour='draft-create']", "fallback": "center", "wait_ms": 3000},
                "title": "Create a new draft session",
                "body": (
                    "Use a unique draft name so this flow works from a clean install and avoids collisions. "
                    "You can create the draft automatically, then continue editing in the UI."
                ),
                "actions": [
                    {
                        "type": "copy_to_clipboard",
                        "label": "Copy Subscriber Notes prompt",
                        "value_template": "${subscriber_notes_prompt}",
                    },
                    {
                        "type": "ensure_resource",
                        "label": "Create draft for me",
                        "resource": "draft_session",
                        "id_key": "draft_id",
                        "create_via": {
                            "method": "POST",
                            "path": "/xyn/api/draft-sessions",
                            "body_template": {
                                "title": "${draft_name}",
                                "kind": "blueprint",
                                "namespace": "core",
                                "project_key": "core.subscriber-notes-${short_id}",
                                "generate_code": False,
                                "initial_prompt": "${subscriber_notes_prompt}",
                            },
                        },
                        "instructions": "If auto-create is blocked, click New draft session and paste the copied prompt.",
                    },
                ],
                "wait_for": None,
            },
            {
                "id": "draft-promote",
                "route": "/app/drafts",
                "attach": {"selector": "[data-tour='draft-promote']", "fallback": "center", "wait_ms": 3000},
                "title": "Promote draft to blueprint",
                "body": (
                    "Promotion converts the working draft into a governed blueprint that can be versioned and released. "
                    "This is the handoff from proposal to buildable definition."
                ),
                "actions": [
                    {
                        "type": "ui_hint",
                        "text": "Use Submit as Blueprint, then confirm fields in the modal before continuing.",
                    }
                ],
                "wait_for": None,
            },
            {
                "id": "release-plan-create",
                "route": "/app/release-plans",
                "attach": {"selector": "[data-tour='release-plan-create']", "fallback": "center", "wait_ms": 3000},
                "title": "Create a release plan",
                "body": (
                    "Release Plans bind a blueprint output to a target environment and deployment context. "
                    "This is where you define what should change and where it should land."
                ),
                "actions": [
                    {"type": "ui_hint", "text": "Select an environment and click Create."}
                ],
                "wait_for": None,
            },
            {
                "id": "instance-select",
                "route": "/app/instances",
                "attach": {"selector": "[data-tour='instance-select']", "fallback": "center", "wait_ms": 3000},
                "title": "Choose a development instance",
                "body": (
                    "Pick any available development instance, preferably Local when available. "
                    "This tour does not require xyn-seed-dev-1 or any preseeded remote target."
                ),
                "actions": [
                    {"type": "ui_hint", "text": "Select the instance you want for deployment, then return to Release Plans."}
                ],
                "wait_for": None,
            },
            {
                "id": "deploy-plan",
                "route": "/app/release-plans",
                "attach": {"selector": "[data-tour='release-plan-deploy']", "fallback": "center", "wait_ms": 3000},
                "title": "Deploy the plan",
                "body": (
                    "Deployment executes the release plan against your selected instance. "
                    "If the button is disabled, complete required fields first and continue once ready."
                ),
                "actions": [],
                "wait_for": None,
            },
            {
                "id": "observe",
                "route": "/app/runs",
                "attach": {"selector": "[data-tour='run-artifacts']", "fallback": "center", "wait_ms": 3000},
                "title": "Observe logs and artifacts",
                "body": (
                    "Runs, logs, and artifacts provide the auditable record of what executed and what was produced. "
                    "Use this page to validate outcomes and troubleshoot failures."
                ),
                "actions": [],
                "wait_for": None,
            },
        ],
    }


@csrf_exempt
def tour_detail(request: HttpRequest, tour_slug: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _default_tour_payload(tour_slug)
    if payload.get("error"):
        return JsonResponse(payload, status=404)
    if "schema_version" not in payload:
        payload["schema_version"] = 1
    return JsonResponse(payload)


def _ensure_default_agent_purposes() -> None:
    ensure_default_ai_seeds()


def _serialize_agent_purpose(purpose: AgentPurpose) -> Dict[str, Any]:
    model = purpose.model_config
    provider = model.provider if model else None
    return {
        "slug": purpose.slug,
        "name": purpose.name or purpose.slug.replace("-", " ").title(),
        "description": purpose.description or "",
        "enabled": purpose.enabled,
        "preamble": purpose.preamble or "",
        "updated_at": purpose.updated_at,
        "model_config": (
            {
                "id": str(model.id),
                "provider": provider.slug if provider else None,
                "model_name": model.model_name,
                "temperature": model.temperature,
                "max_tokens": model.max_tokens,
                "top_p": model.top_p,
                "frequency_penalty": model.frequency_penalty,
                "presence_penalty": model.presence_penalty,
                "extra_json": model.extra_json or {},
            }
            if model
            else None
        ),
    }


def _can_manage_ai(identity: UserIdentity) -> bool:
    return _has_platform_role(identity, ["platform_admin", "platform_architect"])


def _serialize_model_provider(provider: ModelProvider) -> Dict[str, Any]:
    return {
        "id": str(provider.id),
        "slug": provider.slug,
        "name": provider.name,
        "enabled": provider.enabled,
    }


def _serialize_credential(credential: ProviderCredential) -> Dict[str, Any]:
    resolved_secret = ""
    if credential.auth_type == "api_key":
        if credential.secret_ref and credential.secret_ref.external_ref:
            resolved_secret = str(
                resolve_oidc_secret_ref({"type": "aws.secrets_manager", "ref": credential.secret_ref.external_ref}) or ""
            )
        elif credential.api_key_encrypted:
            try:
                resolved_secret = decrypt_api_key(str(credential.api_key_encrypted or ""))
            except Exception:
                resolved_secret = ""
    elif credential.auth_type == "env_ref":
        env_name = str(credential.env_var_name or "").strip()
        resolved_secret = str(os.environ.get(env_name) or "") if env_name else ""
    masked = mask_secret(resolved_secret)
    return {
        "id": str(credential.id),
        "provider": credential.provider.slug,
        "provider_id": str(credential.provider_id),
        "name": credential.name,
        "auth_type": credential.auth_type,
        "secret_ref_id": str(credential.secret_ref_id) if credential.secret_ref_id else None,
        "env_var_name": credential.env_var_name or "",
        "is_default": credential.is_default,
        "enabled": credential.enabled,
        "secret": {
            "configured": bool(masked["has_value"]),
            "masked": masked["masked"],
            "last4": masked["last4"],
        },
        "created_at": credential.created_at,
        "updated_at": credential.updated_at,
    }


def _serialize_model_config(config: ModelConfig) -> Dict[str, Any]:
    return {
        "id": str(config.id),
        "provider": config.provider.slug,
        "provider_id": str(config.provider_id),
        "credential_id": str(config.credential_id) if config.credential_id else None,
        "model_name": config.model_name,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "top_p": config.top_p,
        "frequency_penalty": config.frequency_penalty,
        "presence_penalty": config.presence_penalty,
        "extra_json": config.extra_json or {},
        "enabled": config.enabled,
        "created_at": config.created_at,
        "updated_at": config.updated_at,
    }


def _serialize_agent_definition(agent: AgentDefinition) -> Dict[str, Any]:
    purpose_slugs = [item.slug for item in agent.purposes.all().order_by("slug")]
    return {
        "id": str(agent.id),
        "slug": agent.slug,
        "name": agent.name,
        "model_config_id": str(agent.model_config_id),
        "model_config": _serialize_model_config(agent.model_config),
        "system_prompt_text": agent.system_prompt_text or "",
        "context_pack_refs_json": agent.context_pack_refs_json or [],
        "is_default": bool(agent.is_default),
        "enabled": agent.enabled,
        "purposes": purpose_slugs,
        "created_at": agent.created_at,
        "updated_at": agent.updated_at,
    }


@csrf_exempt
def ai_providers_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if not _can_manage_ai(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    _ensure_default_agent_purposes()
    providers = ModelProvider.objects.all().order_by("slug")
    return JsonResponse({"providers": [_serialize_model_provider(item) for item in providers]})


@csrf_exempt
def ai_credentials_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _can_manage_ai(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    _ensure_default_agent_purposes()
    if request.method == "GET":
        credentials = ProviderCredential.objects.select_related("provider").order_by("provider__slug", "-is_default", "name")
        return JsonResponse({"credentials": [_serialize_credential(item) for item in credentials]})
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    provider_slug = str(payload.get("provider") or "").strip().lower()
    name = str(payload.get("name") or "").strip()
    auth_type = str(payload.get("auth_type") or "api_key").strip()
    if auth_type == "api_key_encrypted":
        auth_type = "api_key"
    if not provider_slug or not name:
        return JsonResponse({"error": "provider and name are required"}, status=400)
    provider = ModelProvider.objects.filter(slug=provider_slug).first()
    if not provider:
        return JsonResponse({"error": "invalid provider"}, status=400)
    if auth_type not in {"api_key", "env_ref"}:
        return JsonResponse({"error": "invalid auth_type"}, status=400)

    api_key_encrypted = None
    env_var_name = ""
    secret_ref = None
    if auth_type == "api_key":
        raw_key = str(payload.get("api_key") or "").strip()
        if not raw_key:
            return JsonResponse({"error": "api_key is required for api_key"}, status=400)
        store = _resolve_secret_store(str(payload.get("store_id") or "").strip() or None)
        if store:
            logical_name = normalize_secret_logical_name(f"ai/{provider_slug}/{name}/api_key")
            try:
                secret_ref = _create_or_update_secret_ref(
                    identity=identity,
                    user=getattr(request, "user", None),
                    name=logical_name,
                    scope_kind="platform",
                    scope_id=None,
                    store=store,
                    value=raw_key,
                    description=f"{provider_slug} AI credential: {name}",
                )
            except (SecretStoreError, PermissionError) as exc:
                return JsonResponse({"error": str(exc)}, status=400)
        else:
            try:
                api_key_encrypted = encrypt_api_key(raw_key)
            except AiConfigError as exc:
                return JsonResponse({"error": str(exc)}, status=400)
    else:
        env_var_name = str(payload.get("env_var_name") or "").strip()
        if not env_var_name:
            return JsonResponse({"error": "env_var_name is required for env_ref"}, status=400)

    credential = ProviderCredential.objects.create(
        provider=provider,
        name=name,
        auth_type=auth_type,
        api_key_encrypted=api_key_encrypted,
        secret_ref=secret_ref,
        env_var_name=env_var_name,
        enabled=bool(payload.get("enabled", True)),
        is_default=bool(payload.get("is_default", False)),
    )
    if credential.is_default:
        ProviderCredential.objects.filter(provider=provider).exclude(id=credential.id).update(is_default=False)
    return JsonResponse({"credential": _serialize_credential(credential)})


@csrf_exempt
def ai_credential_detail(request: HttpRequest, credential_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _can_manage_ai(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    credential = get_object_or_404(ProviderCredential.objects.select_related("provider"), id=credential_id)
    if request.method == "GET":
        return JsonResponse({"credential": _serialize_credential(credential)})
    if request.method == "DELETE":
        credential.delete()
        return JsonResponse({}, status=204)
    if request.method != "PATCH":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    if "name" in payload:
        credential.name = str(payload.get("name") or credential.name).strip()
    if "enabled" in payload:
        credential.enabled = bool(payload.get("enabled"))
    if "is_default" in payload:
        credential.is_default = bool(payload.get("is_default"))
    if "auth_type" in payload:
        auth_type = str(payload.get("auth_type") or "").strip()
        if auth_type == "api_key_encrypted":
            auth_type = "api_key"
        if auth_type not in {"api_key", "env_ref"}:
            return JsonResponse({"error": "invalid auth_type"}, status=400)
        credential.auth_type = auth_type
    if credential.auth_type == "api_key" and "api_key" in payload:
        raw_key = str(payload.get("api_key") or "").strip()
        if raw_key:
            store = _resolve_secret_store(str(payload.get("store_id") or "").strip() or None)
            if store:
                logical_name = normalize_secret_logical_name(
                    f"ai/{credential.provider.slug}/{credential.name or str(credential.id)}/api_key"
                )
                try:
                    secret_ref = _create_or_update_secret_ref(
                        identity=identity,
                        user=getattr(request, "user", None),
                        name=logical_name,
                        scope_kind="platform",
                        scope_id=None,
                        store=store,
                        value=raw_key,
                        description=f"{credential.provider.slug} AI credential: {credential.name}",
                        existing_ref=credential.secret_ref,
                    )
                except (SecretStoreError, PermissionError) as exc:
                    return JsonResponse({"error": str(exc)}, status=400)
                credential.secret_ref = secret_ref
                credential.api_key_encrypted = None
            else:
                try:
                    credential.api_key_encrypted = encrypt_api_key(raw_key)
                except AiConfigError as exc:
                    return JsonResponse({"error": str(exc)}, status=400)
    if credential.auth_type == "env_ref" and "env_var_name" in payload:
        credential.env_var_name = str(payload.get("env_var_name") or "").strip()
    if credential.auth_type == "env_ref":
        credential.secret_ref = None
        if "env_var_name" not in payload and not credential.env_var_name:
            credential.env_var_name = ""
    credential.save(
        update_fields=[
            "name",
            "auth_type",
            "api_key_encrypted",
            "secret_ref",
            "env_var_name",
            "enabled",
            "is_default",
            "updated_at",
        ]
    )
    if credential.is_default:
        ProviderCredential.objects.filter(provider_id=credential.provider_id).exclude(id=credential.id).update(is_default=False)
    return JsonResponse({"credential": _serialize_credential(credential)})


@csrf_exempt
def ai_model_configs_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _can_manage_ai(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    _ensure_default_agent_purposes()
    if request.method == "GET":
        configs = ModelConfig.objects.select_related("provider", "credential").order_by("provider__slug", "model_name")
        return JsonResponse({"model_configs": [_serialize_model_config(item) for item in configs]})
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    provider_slug = str(payload.get("provider") or "").strip().lower()
    model_name = str(payload.get("model_name") or "").strip()
    if not provider_slug or not model_name:
        return JsonResponse({"error": "provider and model_name are required"}, status=400)
    provider = ModelProvider.objects.filter(slug=provider_slug).first()
    if not provider:
        return JsonResponse({"error": "invalid provider"}, status=400)
    credential = None
    credential_id = payload.get("credential_id")
    if credential_id:
        credential = ProviderCredential.objects.filter(id=credential_id, provider=provider).first()
        if not credential:
            return JsonResponse({"error": "credential_id not found for provider"}, status=400)
    config = ModelConfig.objects.create(
        provider=provider,
        credential=credential,
        model_name=model_name,
        temperature=float(payload.get("temperature") if payload.get("temperature") is not None else 0.2),
        max_tokens=int(payload.get("max_tokens") or 1200),
        top_p=float(payload.get("top_p") if payload.get("top_p") is not None else 1.0),
        frequency_penalty=float(payload.get("frequency_penalty") if payload.get("frequency_penalty") is not None else 0.0),
        presence_penalty=float(payload.get("presence_penalty") if payload.get("presence_penalty") is not None else 0.0),
        extra_json=payload.get("extra_json") if isinstance(payload.get("extra_json"), dict) else {},
        enabled=bool(payload.get("enabled", True)),
    )
    return JsonResponse({"model_config": _serialize_model_config(config)})


@csrf_exempt
def ai_model_config_detail(request: HttpRequest, model_config_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _can_manage_ai(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    config = get_object_or_404(ModelConfig.objects.select_related("provider", "credential"), id=model_config_id)
    if request.method == "GET":
        return JsonResponse({"model_config": _serialize_model_config(config)})
    if request.method == "DELETE":
        config.delete()
        return JsonResponse({}, status=204)
    if request.method != "PATCH":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    if "provider" in payload:
        provider_slug = str(payload.get("provider") or "").strip().lower()
        provider = ModelProvider.objects.filter(slug=provider_slug).first()
        if not provider:
            return JsonResponse({"error": "invalid provider"}, status=400)
        config.provider = provider
    if "credential_id" in payload:
        credential_id = payload.get("credential_id")
        if credential_id:
            credential = ProviderCredential.objects.filter(id=credential_id, provider_id=config.provider_id).first()
            if not credential:
                return JsonResponse({"error": "credential_id not found for provider"}, status=400)
            config.credential = credential
        else:
            config.credential = None
    if "model_name" in payload:
        config.model_name = str(payload.get("model_name") or config.model_name).strip()
    if "temperature" in payload:
        config.temperature = float(payload.get("temperature") if payload.get("temperature") is not None else 0.2)
    if "max_tokens" in payload:
        config.max_tokens = int(payload.get("max_tokens") or 1200)
    if "top_p" in payload:
        config.top_p = float(payload.get("top_p") if payload.get("top_p") is not None else 1.0)
    if "frequency_penalty" in payload:
        config.frequency_penalty = float(payload.get("frequency_penalty") if payload.get("frequency_penalty") is not None else 0.0)
    if "presence_penalty" in payload:
        config.presence_penalty = float(payload.get("presence_penalty") if payload.get("presence_penalty") is not None else 0.0)
    if "extra_json" in payload and isinstance(payload.get("extra_json"), dict):
        config.extra_json = payload.get("extra_json")
    if "enabled" in payload:
        config.enabled = bool(payload.get("enabled"))
    config.save(
        update_fields=[
            "provider",
            "credential",
            "model_name",
            "temperature",
            "max_tokens",
            "top_p",
            "frequency_penalty",
            "presence_penalty",
            "extra_json",
            "enabled",
            "updated_at",
        ]
    )
    return JsonResponse({"model_config": _serialize_model_config(config)})


@csrf_exempt
def ai_agents_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    _ensure_default_agent_purposes()
    if request.method == "GET":
        purpose = str(request.GET.get("purpose") or "").strip().lower()
        enabled_only = str(request.GET.get("enabled") or "").strip().lower() in {"1", "true", "yes"}
        agents = AgentDefinition.objects.select_related("model_config__provider", "model_config__credential").prefetch_related("purposes")
        if purpose:
            agents = agents.filter(purposes__slug=purpose)
        if enabled_only:
            agents = agents.filter(enabled=True)
        return JsonResponse({"agents": [_serialize_agent_definition(item) for item in agents.order_by("name", "slug")]})
    if not _can_manage_ai(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    slug = str(payload.get("slug") or "").strip().lower()
    name = str(payload.get("name") or "").strip()
    model_config_id = payload.get("model_config_id")
    if not slug or not name or not model_config_id:
        return JsonResponse({"error": "slug, name, and model_config_id are required"}, status=400)
    if AgentDefinition.objects.filter(slug=slug).exists():
        return JsonResponse({"error": "slug already exists"}, status=400)
    model_config = ModelConfig.objects.filter(id=model_config_id).first()
    if not model_config:
        return JsonResponse({"error": "invalid model_config_id"}, status=400)
    agent = AgentDefinition.objects.create(
        slug=slug,
        name=name,
        model_config=model_config,
        system_prompt_text=str(payload.get("system_prompt_text") or ""),
        context_pack_refs_json=payload.get("context_pack_refs_json") if isinstance(payload.get("context_pack_refs_json"), list) else [],
        is_default=bool(payload.get("is_default", False)),
        enabled=bool(payload.get("enabled", True)),
    )
    if agent.is_default:
        AgentDefinition.objects.exclude(id=agent.id).update(is_default=False)
    purpose_slugs = payload.get("purposes") if isinstance(payload.get("purposes"), list) else []
    purposes = list(AgentPurpose.objects.filter(slug__in=purpose_slugs))
    for purpose in purposes:
        AgentDefinitionPurpose.objects.get_or_create(agent_definition=agent, purpose=purpose)
    agent.refresh_from_db()
    return JsonResponse({"agent": _serialize_agent_definition(agent)})


@csrf_exempt
def ai_agent_detail(request: HttpRequest, agent_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    agent = get_object_or_404(
        AgentDefinition.objects.select_related("model_config__provider", "model_config__credential").prefetch_related("purposes"),
        id=agent_id,
    )
    if request.method == "GET":
        return JsonResponse({"agent": _serialize_agent_definition(agent)})
    if not _can_manage_ai(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    if request.method == "DELETE":
        agent.delete()
        return JsonResponse({}, status=204)
    if request.method != "PATCH":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    if "slug" in payload:
        next_slug = str(payload.get("slug") or agent.slug).strip().lower()
        if next_slug != agent.slug and AgentDefinition.objects.filter(slug=next_slug).exists():
            return JsonResponse({"error": "slug already exists"}, status=400)
        agent.slug = next_slug
    if "name" in payload:
        agent.name = str(payload.get("name") or agent.name).strip()
    if "model_config_id" in payload:
        model_config = ModelConfig.objects.filter(id=payload.get("model_config_id")).first()
        if not model_config:
            return JsonResponse({"error": "invalid model_config_id"}, status=400)
        agent.model_config = model_config
    if "system_prompt_text" in payload:
        agent.system_prompt_text = str(payload.get("system_prompt_text") or "")
    if "context_pack_refs_json" in payload and isinstance(payload.get("context_pack_refs_json"), list):
        agent.context_pack_refs_json = payload.get("context_pack_refs_json")
    if "enabled" in payload:
        agent.enabled = bool(payload.get("enabled"))
    if "is_default" in payload:
        agent.is_default = bool(payload.get("is_default"))
    agent.save(
        update_fields=[
            "slug",
            "name",
            "model_config",
            "system_prompt_text",
            "context_pack_refs_json",
            "is_default",
            "enabled",
            "updated_at",
        ]
    )
    if agent.is_default:
        AgentDefinition.objects.exclude(id=agent.id).update(is_default=False)
    if "purposes" in payload and isinstance(payload.get("purposes"), list):
        desired = list(AgentPurpose.objects.filter(slug__in=payload.get("purposes")))
        AgentDefinitionPurpose.objects.filter(agent_definition=agent).exclude(purpose__in=desired).delete()
        for purpose in desired:
            AgentDefinitionPurpose.objects.get_or_create(agent_definition=agent, purpose=purpose)
    agent.refresh_from_db()
    return JsonResponse({"agent": _serialize_agent_definition(agent)})


@csrf_exempt
def ai_invoke(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    agent_slug = str(payload.get("agent_slug") or "").strip()
    if not agent_slug:
        return JsonResponse({"error": "agent_slug is required"}, status=400)
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return JsonResponse({"error": "messages must be a list"}, status=400)
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    # Server owns the system prompt; client-provided system messages are ignored.
    filtered_messages = [msg for msg in messages if isinstance(msg, dict) and str(msg.get("role") or "").strip().lower() != "system"]
    try:
        resolved = resolve_ai_config(agent_slug=agent_slug)
        result = invoke_model(resolved_config=resolved, messages=filtered_messages)
    except (AiConfigError, AiInvokeError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    AuditLog.objects.create(
        message="ai_invocation",
        metadata_json={
            "actor_identity_id": str(identity.id),
            "agent_slug": resolved.get("agent_slug") or agent_slug,
            "provider": resolved.get("provider"),
            "model_name": resolved.get("model_name"),
            "purpose": resolved.get("purpose"),
            "metadata": metadata,
        },
    )
    return JsonResponse(
        {
            "content": result.get("content") or "",
            "provider": result.get("provider"),
            "model": result.get("model"),
            "usage": result.get("usage"),
            "agent_slug": resolved.get("agent_slug") or agent_slug,
        }
    )


@csrf_exempt
def ai_purposes_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    _ensure_default_agent_purposes()
    purposes = AgentPurpose.objects.select_related("model_config__provider").order_by("slug")
    return JsonResponse({"purposes": [_serialize_agent_purpose(item) for item in purposes]})


@csrf_exempt
def ai_purpose_detail(request: HttpRequest, purpose_slug: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    _ensure_default_agent_purposes()
    purpose = get_object_or_404(AgentPurpose.objects.select_related("model_config__provider"), slug=purpose_slug)
    if request.method == "GET":
        return JsonResponse({"purpose": _serialize_agent_purpose(purpose)})
    if request.method not in {"PUT", "PATCH"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    if not _is_platform_admin(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    payload = _parse_json(request)
    if "enabled" in payload:
        purpose.enabled = bool(payload.get("enabled"))
    if "name" in payload:
        purpose.name = str(payload.get("name") or purpose.name)
    if "description" in payload:
        purpose.description = str(payload.get("description") or "")
    preamble_value = None
    if "preamble" in payload:
        preamble_value = str(payload.get("preamble") or "")
    elif "system_prompt" in payload:
        # Backward compatibility for one release.
        preamble_value = str(payload.get("system_prompt") or "")
    elif "system_prompt_markdown" in payload:
        # Backward compatibility for one release.
        preamble_value = str(payload.get("system_prompt_markdown") or "")
    if preamble_value is not None:
        if len(preamble_value) > 1000:
            return JsonResponse({"error": "preamble must be 1000 characters or less"}, status=400)
        purpose.preamble = preamble_value
    model_payload = payload.get("model_config")
    if isinstance(model_payload, dict):
        provider_slug = str(model_payload.get("provider") or "").strip().lower()
        model_name = str(model_payload.get("model_name") or "").strip()
        provider = None
        if provider_slug:
            provider = ModelProvider.objects.filter(slug=provider_slug).first()
            if not provider:
                return JsonResponse({"error": "invalid provider"}, status=400)
        if model_name:
            if not provider:
                provider = purpose.model_config.provider if purpose.model_config else ModelProvider.objects.filter(slug="openai").first()
            if not provider:
                return JsonResponse({"error": "model provider unavailable"}, status=400)
            model_config = purpose.model_config
            if model_config and model_config.provider_id == provider.id and model_config.model_name == model_name:
                pass
            else:
                model_config = ModelConfig.objects.create(
                    provider=provider,
                    model_name=model_name,
                    temperature=float(model_payload.get("temperature") if model_payload.get("temperature") is not None else 0.2),
                    max_tokens=int(model_payload.get("max_tokens") or 1200),
                    top_p=float(model_payload.get("top_p") if model_payload.get("top_p") is not None else 1.0),
                    frequency_penalty=float(model_payload.get("frequency_penalty") if model_payload.get("frequency_penalty") is not None else 0.0),
                    presence_penalty=float(model_payload.get("presence_penalty") if model_payload.get("presence_penalty") is not None else 0.0),
                    extra_json=model_payload.get("extra_json") if isinstance(model_payload.get("extra_json"), dict) else {},
                )
            purpose.model_config = model_config
    purpose.updated_by = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
    purpose.save(
        update_fields=["name", "description", "enabled", "preamble", "model_config", "updated_by", "updated_at"]
    )
    return JsonResponse({"purpose": _serialize_agent_purpose(purpose)})


@csrf_exempt
@require_role("platform_admin")
def tenants_collection(request: HttpRequest) -> JsonResponse:
    if request.method == "POST":
        payload = _parse_json(request)
        name = (payload.get("name") or "").strip()
        if not name:
            return JsonResponse({"error": "name is required"}, status=400)
        slug = (payload.get("slug") or slugify(name)).lower()
        status = payload.get("status") or "active"
        metadata_json = payload.get("metadata_json")
        if Tenant.objects.filter(slug=slug).exists():
            return JsonResponse({"error": "slug already exists"}, status=400)
        tenant = Tenant.objects.create(
            name=name,
            slug=slug,
            status=status,
            metadata_json=metadata_json,
        )
        return JsonResponse({"id": str(tenant.id)})

    qs = Tenant.objects.all().order_by("name")
    if query := request.GET.get("q"):
        qs = qs.filter(models.Q(name__icontains=query) | models.Q(slug__icontains=query))
    data = [_serialize_tenant(t) for t in qs]
    return _paginate(request, data, "tenants")


@csrf_exempt
@require_role("platform_admin")
def tenant_detail(request: HttpRequest, tenant_id: str) -> JsonResponse:
    tenant = get_object_or_404(Tenant, id=tenant_id)
    if request.method == "GET":
        return JsonResponse(_serialize_tenant(tenant))
    if request.method in ("PATCH", "PUT"):
        payload = _parse_json(request)
        if "name" in payload:
            tenant.name = payload.get("name") or tenant.name
        if "slug" in payload:
            slug = (payload.get("slug") or tenant.slug).lower()
            if slug != tenant.slug and Tenant.objects.filter(slug=slug).exists():
                return JsonResponse({"error": "slug already exists"}, status=400)
            tenant.slug = slug
        if "status" in payload:
            tenant.status = payload.get("status") or tenant.status
        if "metadata_json" in payload:
            tenant.metadata_json = payload.get("metadata_json")
        tenant.save(update_fields=["name", "slug", "status", "metadata_json", "updated_at"])
        return JsonResponse({"id": str(tenant.id)})
    if request.method == "DELETE":
        tenant.status = "suspended"
        tenant.save(update_fields=["status", "updated_at"])
        return JsonResponse({"status": "suspended"})
    return JsonResponse({"error": "method not allowed"}, status=405)


@csrf_exempt
def tenant_contacts_collection(request: HttpRequest, tenant_id: str) -> JsonResponse:
    tenant = get_object_or_404(Tenant, id=tenant_id)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _is_platform_admin(identity):
        if not _require_tenant_access(identity, tenant_id, "tenant_viewer"):
            return JsonResponse({"error": "forbidden"}, status=403)
    if request.method == "POST":
        if not _is_platform_admin(identity):
            if not _require_tenant_access(identity, tenant_id, "tenant_operator"):
                return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        name = (payload.get("name") or "").strip()
        if not name:
            return JsonResponse({"error": "name is required"}, status=400)
        email = payload.get("email")
        if email and Contact.objects.filter(tenant=tenant, email=email).exists():
            return JsonResponse({"error": "email already exists for tenant"}, status=400)
        contact = Contact.objects.create(
            tenant=tenant,
            name=name,
            email=email,
            phone=payload.get("phone"),
            role_title=payload.get("role_title"),
            status=payload.get("status") or "active",
            metadata_json=payload.get("metadata_json"),
        )
        return JsonResponse({"id": str(contact.id)})

    contacts = Contact.objects.filter(tenant=tenant).order_by("name")
    data = [_serialize_contact(c) for c in contacts]
    return JsonResponse({"contacts": data})


@csrf_exempt
def contact_detail(request: HttpRequest, contact_id: str) -> JsonResponse:
    contact = get_object_or_404(Contact, id=contact_id)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _is_platform_admin(identity):
        if not _require_tenant_access(identity, str(contact.tenant_id), "tenant_viewer"):
            return JsonResponse({"error": "forbidden"}, status=403)
    if request.method == "GET":
        return JsonResponse(_serialize_contact(contact))
    if request.method in ("PATCH", "PUT"):
        if not _is_platform_admin(identity):
            if not _require_tenant_access(identity, str(contact.tenant_id), "tenant_operator"):
                return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        if "name" in payload:
            contact.name = payload.get("name") or contact.name
        if "email" in payload:
            email = payload.get("email")
            if email and Contact.objects.filter(tenant=contact.tenant, email=email).exclude(id=contact.id).exists():
                return JsonResponse({"error": "email already exists for tenant"}, status=400)
            contact.email = email
        if "phone" in payload:
            contact.phone = payload.get("phone")
        if "role_title" in payload:
            contact.role_title = payload.get("role_title")
        if "status" in payload:
            contact.status = payload.get("status") or contact.status
        if "metadata_json" in payload:
            contact.metadata_json = payload.get("metadata_json")
        contact.save(
            update_fields=["name", "email", "phone", "role_title", "status", "metadata_json", "updated_at"]
        )
        return JsonResponse({"id": str(contact.id)})
    if request.method == "DELETE":
        if not _is_platform_admin(identity):
            if not _require_tenant_access(identity, str(contact.tenant_id), "tenant_operator"):
                return JsonResponse({"error": "forbidden"}, status=403)
        contact.status = "inactive"
        contact.save(update_fields=["status", "updated_at"])
        return JsonResponse({"status": "inactive"})
    return JsonResponse({"error": "method not allowed"}, status=405)


@csrf_exempt
@require_role("platform_admin")
def identities_collection(request: HttpRequest) -> JsonResponse:
    identities = UserIdentity.objects.all().order_by("-last_login_at", "email")
    provider_names = {
        provider.id: provider.display_name
        for provider in IdentityProvider.objects.filter(enabled=True)
    }
    data = [
        {
            "id": str(i.id),
            "provider": i.provider,
            "provider_id": i.provider_id or None,
            "provider_display_name": provider_names.get(i.provider_id or "", ""),
            "issuer": i.issuer,
            "subject": i.subject,
            "email": i.email,
            "display_name": i.display_name,
            "last_login_at": i.last_login_at,
        }
        for i in identities
    ]
    return JsonResponse({"identities": data})


@csrf_exempt
@require_role("platform_admin")
def role_bindings_collection(request: HttpRequest) -> JsonResponse:
    if request.method == "POST":
        payload = _parse_json(request)
        identity_id = payload.get("user_identity_id")
        role = payload.get("role")
        if not identity_id or not role:
            return JsonResponse({"error": "user_identity_id and role required"}, status=400)
        identity = get_object_or_404(UserIdentity, id=identity_id)
        binding = RoleBinding.objects.create(
            user_identity=identity,
            scope_kind="platform",
            scope_id=None,
            role=role,
        )
        return JsonResponse({"id": str(binding.id)})

    identity_id = request.GET.get("identity_id")
    qs = RoleBinding.objects.all().order_by("role")
    if identity_id:
        qs = qs.filter(user_identity_id=identity_id)
    data = [
        {
            "id": str(b.id),
            "user_identity_id": str(b.user_identity_id),
            "scope_kind": b.scope_kind,
            "scope_id": str(b.scope_id) if b.scope_id else None,
            "role": b.role,
            "created_at": b.created_at,
        }
        for b in qs
    ]
    return JsonResponse({"role_bindings": data})


@csrf_exempt
@require_role("platform_admin")
def role_binding_detail(request: HttpRequest, binding_id: str) -> JsonResponse:
    if request.method != "DELETE":
        return JsonResponse({"error": "method not allowed"}, status=405)
    binding = get_object_or_404(RoleBinding, id=binding_id)
    binding.delete()
    return JsonResponse({"status": "deleted"})


def tenants_public(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if _is_platform_admin(identity):
        tenants = Tenant.objects.all().order_by("name")
        data = [
            {
                **_serialize_tenant(t),
                "membership_role": "platform_admin",
            }
            for t in tenants
        ]
        return JsonResponse({"tenants": data})
    memberships = TenantMembership.objects.filter(user_identity=identity, status="active").select_related("tenant")
    data = [
        {
            **_serialize_tenant(m.tenant),
            "membership_role": m.role,
        }
        for m in memberships
    ]
    return JsonResponse({"tenants": data})


def my_profile(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    roles = _get_roles(identity)
    memberships = TenantMembership.objects.filter(user_identity=identity, status="active").select_related("tenant")
    membership_data = [
        {"tenant_id": str(m.tenant_id), "tenant_name": m.tenant.name, "role": m.role}
        for m in memberships
    ]
    return JsonResponse(
        {
            "user": {
                "issuer": identity.issuer,
                "subject": identity.subject,
                "email": identity.email,
                "display_name": identity.display_name,
            },
            "roles": roles,
            "memberships": membership_data,
            "active_tenant_id": request.session.get("active_tenant_id"),
        }
    )


def set_active_tenant(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = _parse_json(request)
    tenant_id = payload.get("tenant_id")
    if not tenant_id:
        return JsonResponse({"error": "tenant_id required"}, status=400)
    if not _is_platform_admin(identity) and not _require_tenant_access(identity, tenant_id, "tenant_viewer"):
        return JsonResponse({"error": "forbidden"}, status=403)
    request.session["active_tenant_id"] = str(tenant_id)
    return JsonResponse({"status": "ok", "tenant_id": str(tenant_id)})


def _get_active_tenant(identity: UserIdentity, request: HttpRequest) -> Optional[Tenant]:
    session = getattr(request, "session", None)
    tenant_id = session.get("active_tenant_id") if session else None
    if tenant_id:
        tenant = Tenant.objects.filter(id=tenant_id).first()
        if tenant and (_is_platform_admin(identity) or _require_tenant_access(identity, tenant_id, "tenant_viewer")):
            return tenant
    memberships = list(
        TenantMembership.objects.filter(user_identity=identity, status="active").select_related("tenant")
    )
    if len(memberships) == 1:
        tenant = memberships[0].tenant
        if session is not None:
            session["active_tenant_id"] = str(tenant.id)
        return tenant
    if _is_platform_admin(identity):
        tenants = list(Tenant.objects.all())
        if len(tenants) == 1:
            tenant = tenants[0]
            if session is not None:
                session["active_tenant_id"] = str(tenant.id)
            return tenant
    return None


@csrf_exempt
def tenant_devices_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    tenant = _get_active_tenant(identity, request)
    if not tenant:
        return JsonResponse({"error": "active tenant not set"}, status=400)
    if request.method == "POST":
        if not (_is_platform_admin(identity) or _require_tenant_access(identity, str(tenant.id), "tenant_operator")):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        name = (payload.get("name") or "").strip()
        if not name:
            return JsonResponse({"error": "name is required"}, status=400)
        if Device.objects.filter(tenant=tenant, name=name).exists():
            return JsonResponse({"error": "device name already exists"}, status=400)
        device = Device.objects.create(
            tenant=tenant,
            name=name,
            device_type=payload.get("device_type") or "unknown",
            mgmt_ip=payload.get("mgmt_ip"),
            status=payload.get("status") or "unknown",
            tags=payload.get("tags"),
            metadata_json=payload.get("metadata_json"),
        )
        return JsonResponse(_serialize_device(device), status=201)

    devices = Device.objects.filter(tenant=tenant).order_by("name")
    return JsonResponse({"devices": [_serialize_device(d) for d in devices]})


@csrf_exempt
def device_detail(request: HttpRequest, device_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    device = get_object_or_404(Device, id=device_id)
    if not _is_platform_admin(identity):
        tenant = _get_active_tenant(identity, request)
        if not tenant or str(device.tenant_id) != str(tenant.id):
            return JsonResponse({"error": "forbidden"}, status=403)
    if request.method == "GET":
        return JsonResponse(_serialize_device(device))
    if request.method in ("PATCH", "PUT"):
        if not (_is_platform_admin(identity) or _require_tenant_access(identity, str(device.tenant_id), "tenant_operator")):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        if "name" in payload:
            name = (payload.get("name") or "").strip()
            if name and Device.objects.filter(tenant=device.tenant, name=name).exclude(id=device.id).exists():
                return JsonResponse({"error": "device name already exists"}, status=400)
            device.name = name or device.name
        if "device_type" in payload:
            device.device_type = payload.get("device_type") or device.device_type
        if "mgmt_ip" in payload:
            device.mgmt_ip = payload.get("mgmt_ip")
        if "status" in payload:
            device.status = payload.get("status") or device.status
        if "tags" in payload:
            device.tags = payload.get("tags")
        if "metadata_json" in payload:
            device.metadata_json = payload.get("metadata_json")
        device.save(
            update_fields=[
                "name",
                "device_type",
                "mgmt_ip",
                "status",
                "tags",
                "metadata_json",
                "updated_at",
            ]
        )
        return JsonResponse(_serialize_device(device))
    if request.method == "DELETE":
        if not (_is_platform_admin(identity) or _require_tenant_access(identity, str(device.tenant_id), "tenant_operator")):
            return JsonResponse({"error": "forbidden"}, status=403)
        device.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse({"error": "method not allowed"}, status=405)


def _resolve_action_scope(identity: UserIdentity, request: HttpRequest) -> Tuple[Optional[Tenant], Optional[str], Optional[str]]:
    tenant = _get_active_tenant(identity, request)
    if not tenant:
        return None, None, "active tenant not set"
    return tenant, str(tenant.id), None


def _action_for_tenant(identity: UserIdentity, request: HttpRequest, action_id: str) -> Tuple[Optional[DraftAction], Optional[JsonResponse]]:
    action = get_object_or_404(DraftAction, id=action_id)
    if _is_platform_admin(identity):
        return action, None
    tenant = _get_active_tenant(identity, request)
    if not tenant or str(action.tenant_id) != str(tenant.id):
        return None, JsonResponse({"error": "forbidden"}, status=403)
    if not _require_tenant_access(identity, str(action.tenant_id), "tenant_viewer"):
        return None, JsonResponse({"error": "forbidden"}, status=403)
    return action, None


@csrf_exempt
def device_actions_collection(request: HttpRequest, device_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    device = get_object_or_404(Device, id=device_id)
    if not _is_platform_admin(identity):
        tenant = _get_active_tenant(identity, request)
        if not tenant or str(tenant.id) != str(device.tenant_id):
            return JsonResponse({"error": "forbidden"}, status=403)

    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)

    payload = _parse_json(request)
    action_type = str(payload.get("action_type") or "").strip()
    if not action_type:
        return JsonResponse({"error": "action_type is required"}, status=400)
    if action_type not in EMS_ACTION_TYPES:
        return JsonResponse({"error": "unsupported action_type"}, status=400)

    membership = _tenant_membership(identity, str(device.tenant_id))
    ems_role = "ems_admin" if _is_platform_admin(identity) else _tenant_role_to_ems_role(membership.role if membership else "")
    policy = _resolve_action_policy(
        device.tenant,
        action_type,
        str(payload.get("instance_id") or payload.get("instance_ref") or ""),
    )
    allowed_request = [str(item) for item in (policy.get("allowed_roles_to_request") or [])]
    if not _is_platform_admin(identity) and not _ems_role_allowed(ems_role, allowed_request):
        return JsonResponse({"error": "forbidden: request role not allowed"}, status=403)

    params_json = payload.get("params")
    if params_json is None:
        params_json = {}
    if not isinstance(params_json, dict):
        return JsonResponse({"error": "params must be an object"}, status=400)
    params_json = _redact_sensitive_json(params_json)
    action_class = EMS_ACTION_TYPES.get(action_type, "write_execute")
    requires_confirmation = bool(policy.get("requires_confirmation", True))
    requires_ratification = bool(policy.get("requires_ratification", False))
    next_status = "pending_verification" if requires_confirmation else ("pending_ratification" if requires_ratification else "executing")

    provenance = {
        "request_id": str(uuid.uuid4()),
        "correlation_id": request.headers.get("X-Request-ID") or str(uuid.uuid4()),
        "source": "ems-ui",
        "ip": request.META.get("REMOTE_ADDR"),
        "user_agent": request.META.get("HTTP_USER_AGENT", ""),
    }
    action = DraftAction.objects.create(
        tenant=device.tenant,
        device=device,
        instance_ref=str(payload.get("instance_id") or payload.get("instance_ref") or ""),
        action_type=action_type,
        action_class=action_class,
        params_json=params_json,
        status=next_status,
        requested_by=identity,
        custodian=identity if ems_role == "ems_admin" else None,
        provenance_json=provenance,
    )
    _record_draft_action_event(
        action,
        "action_requested",
        identity,
        "",
        next_status,
        {
            "action_type": action_type,
            "action_class": action_class,
            "requires_confirmation": requires_confirmation,
            "requires_ratification": requires_ratification,
        },
    )
    if requires_confirmation:
        ActionVerifierEvidence.objects.create(
            draft_action=action,
            verifier_type="user_confirmation",
            status="required",
            evidence_json={"required": True},
        )

    # Fast path for policies that do not require confirmation/ratification.
    if next_status == "executing":
        _execute_draft_action(action, None)
        action.refresh_from_db()

    return JsonResponse(
        {
            "action": _serialize_draft_action(action),
            "requires_confirmation": requires_confirmation,
            "requires_ratification": requires_ratification,
            "next_status": action.status,
        },
        status=201,
    )


@csrf_exempt
def actions_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    tenant, tenant_id, error = _resolve_action_scope(identity, request)
    if error:
        return JsonResponse({"error": error}, status=400)
    qs = DraftAction.objects.filter(tenant_id=tenant_id).select_related("device").order_by("-created_at")
    device_id = (request.GET.get("device_id") or "").strip()
    if device_id:
        qs = qs.filter(device_id=device_id)
    data = [_serialize_draft_action(item) for item in qs[:200]]
    return JsonResponse({"actions": data})


@csrf_exempt
def action_detail(request: HttpRequest, action_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    action, error = _action_for_tenant(identity, request, action_id)
    if error:
        return error
    assert action is not None
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    return JsonResponse(
        {
            "action": _serialize_draft_action(action),
            "timeline": _action_timeline(action),
            "evidence": [
                {
                    "id": str(item.id),
                    "verifier_type": item.verifier_type,
                    "status": item.status,
                    "evidence_json": item.evidence_json or {},
                    "created_at": item.created_at,
                }
                for item in action.verifier_evidence.all().order_by("created_at")
            ],
            "ratifications": [
                {
                    "id": str(item.id),
                    "ratified_by": str(item.ratified_by_id) if item.ratified_by_id else None,
                    "ratified_at": item.ratified_at,
                    "method": item.method,
                    "notes": item.notes,
                }
                for item in action.ratification_events.all().order_by("-ratified_at")
            ],
        }
    )


@csrf_exempt
def action_receipts_collection(request: HttpRequest, action_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    action, error = _action_for_tenant(identity, request, action_id)
    if error:
        return error
    assert action is not None
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    data = [_serialize_receipt(item) for item in action.receipts.all().order_by("-executed_at")]
    return JsonResponse({"receipts": data})


@csrf_exempt
def action_confirm(request: HttpRequest, action_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    action, error = _action_for_tenant(identity, request, action_id)
    if error:
        return error
    assert action is not None
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if action.status != "pending_verification":
        return JsonResponse({"error": "action is not pending_verification"}, status=400)

    membership = _tenant_membership(identity, str(action.tenant_id))
    ems_role = "ems_admin" if _is_platform_admin(identity) else _tenant_role_to_ems_role(membership.role if membership else "")
    if not _is_platform_admin(identity) and _ems_role_rank(ems_role) < _ems_role_rank("ems_operator"):
        return JsonResponse({"error": "forbidden"}, status=403)

    evidence = ActionVerifierEvidence.objects.filter(
        draft_action=action,
        verifier_type="user_confirmation",
    ).order_by("-created_at").first()
    if evidence:
        evidence.status = "satisfied"
        evidence.evidence_json = {
            "confirmed_by": str(identity.id),
            "confirmed_at": timezone.now().isoformat(),
        }
        evidence.save(update_fields=["status", "evidence_json"])
    else:
        ActionVerifierEvidence.objects.create(
            draft_action=action,
            verifier_type="user_confirmation",
            status="satisfied",
            evidence_json={"confirmed_by": str(identity.id), "confirmed_at": timezone.now().isoformat()},
        )

    policy = _resolve_action_policy(action.tenant, action.action_type, action.instance_ref)
    if bool(policy.get("requires_ratification", False)):
        _transition_draft_action(action, "pending_ratification", identity, "verification_satisfied")
        action.refresh_from_db()
        return JsonResponse({"action": _serialize_draft_action(action)})

    allowed_execute = [str(item) for item in (policy.get("allowed_roles_to_execute") or [])]
    if "system" in allowed_execute:
        success, receipt = _execute_draft_action(action, None)
    elif _is_platform_admin(identity) or _ems_role_allowed(ems_role, allowed_execute):
        success, receipt = _execute_draft_action(action, identity)
    else:
        _transition_draft_action(action, "pending_ratification", identity, "verification_satisfied")
        action.refresh_from_db()
        return JsonResponse({"action": _serialize_draft_action(action)})

    action.refresh_from_db()
    return JsonResponse(
        {
            "action": _serialize_draft_action(action),
            "receipt": _serialize_receipt(receipt),
            "success": success,
        }
    )


@csrf_exempt
def action_ratify(request: HttpRequest, action_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    action, error = _action_for_tenant(identity, request, action_id)
    if error:
        return error
    assert action is not None
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if action.status != "pending_ratification":
        return JsonResponse({"error": "action is not pending_ratification"}, status=400)

    membership = _tenant_membership(identity, str(action.tenant_id))
    ems_role = "ems_admin" if _is_platform_admin(identity) else _tenant_role_to_ems_role(membership.role if membership else "")
    policy = _resolve_action_policy(action.tenant, action.action_type, action.instance_ref)
    allowed_ratify = [str(item) for item in (policy.get("allowed_roles_to_ratify") or [])]
    if not (_is_platform_admin(identity) or _ems_role_allowed(ems_role, allowed_ratify)):
        return JsonResponse({"error": "forbidden: ratify role not allowed"}, status=403)

    payload = _parse_json(request)
    RatificationEvent.objects.create(
        draft_action=action,
        ratified_by=identity,
        method=str(payload.get("method") or "ui_confirm"),
        notes=str(payload.get("notes") or ""),
    )
    _record_draft_action_event(action, "action_ratified", identity, action.status, action.status)
    success, receipt = _execute_draft_action(action, identity)
    action.refresh_from_db()
    return JsonResponse({"action": _serialize_draft_action(action), "receipt": _serialize_receipt(receipt), "success": success})


@csrf_exempt
def action_execute(request: HttpRequest, action_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    action, error = _action_for_tenant(identity, request, action_id)
    if error:
        return error
    assert action is not None
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if action.status not in {"pending_ratification", "pending_verification", "draft"}:
        return JsonResponse({"error": f"action cannot be executed from status '{action.status}'"}, status=400)

    membership = _tenant_membership(identity, str(action.tenant_id))
    ems_role = "ems_admin" if _is_platform_admin(identity) else _tenant_role_to_ems_role(membership.role if membership else "")
    policy = _resolve_action_policy(action.tenant, action.action_type, action.instance_ref)
    allowed_execute = [str(item) for item in (policy.get("allowed_roles_to_execute") or [])]
    if not (_is_platform_admin(identity) or _ems_role_allowed(ems_role, allowed_execute)):
        return JsonResponse({"error": "forbidden: execute role not allowed"}, status=403)

    # If confirmation is required, ensure it was satisfied.
    if bool(policy.get("requires_confirmation", False)):
        confirmed = ActionVerifierEvidence.objects.filter(
            draft_action=action,
            verifier_type="user_confirmation",
            status="satisfied",
        ).exists()
        if not confirmed:
            return JsonResponse({"error": "confirmation required"}, status=400)

    if bool(policy.get("requires_ratification", False)):
        ratified = RatificationEvent.objects.filter(draft_action=action).exists()
        if not ratified and not _is_platform_admin(identity):
            return JsonResponse({"error": "ratification required"}, status=400)

    success, receipt = _execute_draft_action(action, identity)
    action.refresh_from_db()
    return JsonResponse({"action": _serialize_draft_action(action), "receipt": _serialize_receipt(receipt), "success": success})


def tenant_branding_public(request: HttpRequest, tenant_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _is_platform_admin(identity) and not _require_tenant_access(identity, tenant_id, "tenant_viewer"):
        return JsonResponse({"error": "forbidden"}, status=403)
    tenant = get_object_or_404(Tenant, id=tenant_id)
    profile = getattr(tenant, "brand_profile", None)
    return JsonResponse(_serialize_branding(profile))


@csrf_exempt
def tenant_branding_update(request: HttpRequest, tenant_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _is_platform_admin(identity) and not _require_tenant_access(identity, tenant_id, "tenant_admin"):
        return JsonResponse({"error": "forbidden"}, status=403)
    if request.method not in ("PATCH", "PUT"):
        return JsonResponse({"error": "method not allowed"}, status=405)
    tenant = get_object_or_404(Tenant, id=tenant_id)
    payload = _parse_json(request)
    profile, _created = BrandProfile.objects.get_or_create(tenant=tenant)
    if "display_name" in payload:
        profile.display_name = payload.get("display_name")
    if "logo_url" in payload:
        profile.logo_url = payload.get("logo_url")
    if "primary_color" in payload:
        profile.primary_color = payload.get("primary_color")
    if "secondary_color" in payload:
        profile.secondary_color = payload.get("secondary_color")
    if "theme_json" in payload:
        profile.theme_json = payload.get("theme_json")
    profile.save(
        update_fields=[
            "display_name",
            "logo_url",
            "primary_color",
            "secondary_color",
            "theme_json",
            "updated_at",
        ]
    )
    return JsonResponse({"status": "ok"})


@csrf_exempt
@require_any_role("platform_admin", "platform_architect")
def platform_branding(request: HttpRequest) -> JsonResponse:
    branding = _get_platform_branding()
    if request.method == "GET":
        return JsonResponse(_serialize_platform_branding(branding))
    if request.method not in {"PUT", "PATCH"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    errors = _validate_branding_payload(payload, partial=request.method == "PATCH")
    if errors:
        return JsonResponse({"error": "invalid branding payload", "details": errors}, status=400)
    for field in (
        "brand_name",
        "logo_url",
        "favicon_url",
        "primary_color",
        "background_color",
        "background_gradient",
        "text_color",
        "font_family",
        "button_radius_px",
    ):
        if field in payload:
            setattr(branding, field, payload.get(field))
    identity = _require_authenticated(request)
    if identity and request.user.is_authenticated:
        branding.updated_by = request.user
    branding.save()
    return JsonResponse(_serialize_platform_branding(branding))


@csrf_exempt
@require_any_role("platform_admin", "platform_architect")
def platform_app_branding(request: HttpRequest, app_id: str) -> JsonResponse:
    override = AppBrandingOverride.objects.filter(app_id=app_id).first()
    if request.method == "GET":
        return JsonResponse(_serialize_app_branding_override(override, app_id))
    if request.method not in {"PUT", "PATCH"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    errors = _validate_branding_payload(payload, partial=request.method == "PATCH")
    if errors:
        return JsonResponse({"error": "invalid branding payload", "details": errors}, status=400)
    if not override:
        override = AppBrandingOverride(app_id=app_id)
    for field in (
        "display_name",
        "logo_url",
        "primary_color",
        "background_color",
        "background_gradient",
        "text_color",
        "font_family",
        "button_radius_px",
    ):
        if field in payload:
            setattr(override, field, payload.get(field))
    identity = _require_authenticated(request)
    if identity and request.user.is_authenticated:
        override.updated_by = request.user
    override.save()
    return JsonResponse(_serialize_app_branding_override(override, app_id))


def public_branding(request: HttpRequest) -> JsonResponse:
    app_id = request.GET.get("appId") or request.GET.get("app_id") or "xyn-ui"
    return JsonResponse(_merge_branding_for_app(app_id))


def branding_tokens(request: HttpRequest) -> JsonResponse:
    app_id = request.GET.get("app") or request.GET.get("appId") or request.GET.get("app_id") or "xyn-ui"
    return JsonResponse(_branding_tokens_for_app(str(app_id)))


def branding_theme_css(request: HttpRequest) -> HttpResponse:
    if request.method == "OPTIONS":
        response = HttpResponse("", content_type="text/css")
        return _set_theme_headers(response, "")
    app_id = request.GET.get("app") or request.GET.get("appId") or request.GET.get("app_id") or "xyn-ui"
    css = _branding_theme_css(_branding_tokens_for_app(str(app_id)))
    etag = hashlib.sha256(css.encode("utf-8")).hexdigest()
    if request.headers.get("If-None-Match", "").strip('"') == etag:
        response = HttpResponse(status=304)
        return _set_theme_headers(response, css)
    response = HttpResponse(css, content_type="text/css; charset=utf-8")
    return _set_theme_headers(response, css)


@csrf_exempt
@require_role("platform_admin")
def tenant_memberships_collection(request: HttpRequest, tenant_id: str) -> JsonResponse:
    tenant = get_object_or_404(Tenant, id=tenant_id)
    if request.method == "POST":
        payload = _parse_json(request)
        identity_id = payload.get("user_identity_id")
        role = payload.get("role") or "tenant_viewer"
        if not identity_id:
            return JsonResponse({"error": "user_identity_id required"}, status=400)
        identity = get_object_or_404(UserIdentity, id=identity_id)
        membership, created = TenantMembership.objects.get_or_create(
            tenant=tenant,
            user_identity=identity,
            defaults={"role": role, "status": "active"},
        )
        if not created:
            membership.role = role
            membership.status = "active"
            membership.save(update_fields=["role", "status", "updated_at"])
        return JsonResponse({"id": str(membership.id)})
    memberships = TenantMembership.objects.filter(tenant=tenant).select_related("user_identity").order_by("created_at")
    data = [
        {
            **_serialize_membership(m),
            "user_email": m.user_identity.email,
            "user_display_name": m.user_identity.display_name,
        }
        for m in memberships
    ]
    return JsonResponse({"memberships": data})


@csrf_exempt
@require_role("platform_admin")
def tenant_membership_detail(request: HttpRequest, membership_id: str) -> JsonResponse:
    membership = get_object_or_404(TenantMembership, id=membership_id)
    if request.method in ("PATCH", "PUT"):
        payload = _parse_json(request)
        if "role" in payload:
            membership.role = payload.get("role") or membership.role
        if "status" in payload:
            membership.status = payload.get("status") or membership.status
        membership.save(update_fields=["role", "status", "updated_at"])
        return JsonResponse({"id": str(membership.id)})
    if request.method == "DELETE":
        membership.status = "inactive"
        membership.save(update_fields=["status", "updated_at"])
        return JsonResponse({"status": "inactive"})
    return JsonResponse({"error": "method not allowed"}, status=405)
    data = [_serialize_tenant(t) for t in tenants]
    return JsonResponse({"tenants": data})


@csrf_exempt
@login_required
def blueprints_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name")
        if not name:
            return JsonResponse({"error": "name is required"}, status=400)
        namespace = payload.get("namespace", "core")
        description = payload.get("description", "")
        blueprint, created = Blueprint.objects.get_or_create(
            name=name,
            namespace=namespace,
            defaults={
                "description": description,
                "spec_text": payload.get("spec_text", ""),
                "metadata_json": payload.get("metadata_json"),
                "created_by": request.user,
                "updated_by": request.user,
            },
        )
        if not created:
            blueprint.description = description
            if "spec_text" in payload:
                blueprint.spec_text = payload.get("spec_text", "")
            if "metadata_json" in payload:
                blueprint.metadata_json = payload.get("metadata_json")
            blueprint.updated_by = request.user
            blueprint.save(update_fields=["description", "spec_text", "metadata_json", "updated_by", "updated_at"])
        spec_json = payload.get("spec_json")
        if not spec_json and (payload.get("spec_text") or payload.get("metadata_json")):
            spec_json = {
                "spec_text": payload.get("spec_text", ""),
                "metadata": payload.get("metadata_json") or {},
            }
        if spec_json:
            revision = blueprint.revisions.order_by("-revision").first()
            next_rev = (revision.revision + 1) if revision else 1
            BlueprintRevision.objects.create(
                blueprint=blueprint,
                revision=next_rev,
                spec_json=spec_json,
                blueprint_kind=payload.get("blueprint_kind", "solution"),
                created_by=request.user,
            )
        return JsonResponse({"id": str(blueprint.id)})

    qs = Blueprint.objects.all().order_by("namespace", "name")
    include_archived = (request.GET.get("include_archived") or "").strip() in {"1", "true", "yes"}
    if not include_archived:
        qs = qs.exclude(status="archived")
    if query := request.GET.get("q"):
        qs = qs.filter(models.Q(name__icontains=query) | models.Q(namespace__icontains=query))
    blueprints = list(qs)
    project_keys = [f"{item.namespace}.{item.name}" for item in blueprints]
    active_statuses = {"drafting", "queued", "ready", "ready_with_errors"}
    draft_counts_by_project: Dict[str, int] = {}
    if project_keys:
        draft_rows = (
            BlueprintDraftSession.objects.filter(project_key__in=project_keys, status__in=active_statuses)
            .exclude(project_key="")
            .values("project_key")
            .annotate(total=models.Count("id"))
        )
        draft_counts_by_project = {str(row["project_key"]): int(row["total"]) for row in draft_rows}
    data = [
        {
            "id": str(b.id),
            "name": b.name,
            "namespace": b.namespace,
            "description": b.description,
            "status": b.status,
            "archived_at": b.archived_at,
            "deprovisioned_at": b.deprovisioned_at,
            "deprovision_last_run_id": str(b.deprovision_last_run_id) if b.deprovision_last_run_id else None,
            "spec_text": b.spec_text,
            "metadata_json": b.metadata_json,
            "created_at": b.created_at,
            "updated_at": b.updated_at,
            "latest_revision": b.revisions.order_by("-revision").first().revision if b.revisions.exists() else None,
            "active_draft_count": draft_counts_by_project.get(f"{b.namespace}.{b.name}", 0),
        }
        for b in blueprints
    ]
    return _paginate(request, data, "blueprints")


@csrf_exempt
@login_required
def blueprint_detail(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    blueprint = get_object_or_404(Blueprint, id=blueprint_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["name", "namespace", "description", "spec_text", "metadata_json", "status"]:
            if field in payload:
                setattr(blueprint, field, payload[field])
        if payload.get("status") == "archived":
            blueprint.archived_at = timezone.now()
        elif payload.get("status") == "deprovisioned":
            blueprint.deprovisioned_at = timezone.now()
        elif payload.get("status") == "active":
            blueprint.archived_at = None
        blueprint.updated_by = request.user
        blueprint.save(
            update_fields=[
                "name",
                "namespace",
                "description",
                "spec_text",
                "metadata_json",
                "status",
                "archived_at",
                "deprovisioned_at",
                "updated_by",
                "updated_at",
            ]
        )
        if payload.get("spec_json"):
            revision = blueprint.revisions.order_by("-revision").first()
            next_rev = (revision.revision + 1) if revision else 1
            BlueprintRevision.objects.create(
                blueprint=blueprint,
                revision=next_rev,
                spec_json=payload.get("spec_json"),
                blueprint_kind=payload.get("blueprint_kind", "solution"),
                created_by=request.user,
            )
        return JsonResponse({"id": str(blueprint.id)})
    if request.method == "DELETE":
        blueprint.status = "archived"
        blueprint.archived_at = timezone.now()
        blueprint.updated_by = request.user
        blueprint.save(update_fields=["status", "archived_at", "updated_by", "updated_at"])
        return JsonResponse({"status": "archived"})

    latest = blueprint.revisions.order_by("-revision").first()
    return JsonResponse(
        {
            "id": str(blueprint.id),
            "name": blueprint.name,
            "namespace": blueprint.namespace,
            "description": blueprint.description,
            "status": blueprint.status,
            "archived_at": blueprint.archived_at,
            "deprovisioned_at": blueprint.deprovisioned_at,
            "deprovision_last_run_id": str(blueprint.deprovision_last_run_id) if blueprint.deprovision_last_run_id else None,
            "spec_text": blueprint.spec_text,
            "metadata_json": blueprint.metadata_json,
            "created_at": blueprint.created_at,
            "updated_at": blueprint.updated_at,
            "latest_revision": latest.revision if latest else None,
            "spec_json": latest.spec_json if latest else None,
        }
    )


@csrf_exempt
@login_required
def blueprint_archive(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    blueprint = get_object_or_404(Blueprint, id=blueprint_id)
    blueprint.status = "archived"
    blueprint.archived_at = timezone.now()
    blueprint.updated_by = request.user
    blueprint.save(update_fields=["status", "archived_at", "updated_by", "updated_at"])
    return JsonResponse(
        {
            "status": blueprint.status,
            "id": str(blueprint.id),
            "archived_at": blueprint.archived_at.isoformat() if blueprint.archived_at else None,
        }
    )


@login_required
def blueprint_deprovision_plan(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    blueprint = get_object_or_404(Blueprint, id=blueprint_id)
    release_targets = list(ReleaseTarget.objects.filter(blueprint=blueprint).order_by("name"))
    target_ids = [value for value in request.GET.getlist("release_target_id") if value]
    if target_ids:
        release_targets = [target for target in release_targets if str(target.id) in set(target_ids)]
    stop_services = (request.GET.get("mode") or "").strip().lower() in {"stop_services", "force"}
    delete_dns = _parse_bool_param(request.GET.get("delete_dns"), default=True)
    remove_runtime_markers = _parse_bool_param(request.GET.get("remove_runtime_markers"), default=True)
    force_mode = (request.GET.get("mode") or "").strip().lower() == "force"
    plan = _build_blueprint_deprovision_plan(
        blueprint,
        release_targets,
        stop_services=stop_services,
        delete_dns=delete_dns,
        remove_runtime_markers=remove_runtime_markers,
        force_mode=force_mode,
    )
    return JsonResponse(plan)


@csrf_exempt
@login_required
def blueprint_deprovision(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    blueprint = get_object_or_404(Blueprint, id=blueprint_id)
    payload = _parse_json(request)
    confirm_text = str(payload.get("confirm_text") or "").strip()
    expected = _blueprint_identifier(blueprint)
    if confirm_text not in {expected, blueprint.name, str(blueprint.id)}:
        return JsonResponse(
            {
                "error": "confirm_text mismatch",
                "expected": expected,
                "guidance": "Type blueprint identifier exactly to continue.",
            },
            status=400,
        )
    mode = str(payload.get("mode") or "safe").strip().lower()
    if mode not in {"safe", "stop_services", "force"}:
        return JsonResponse({"error": "mode must be safe, stop_services, or force"}, status=400)
    target_ids = payload.get("release_target_ids") if isinstance(payload.get("release_target_ids"), list) else []
    release_targets = list(ReleaseTarget.objects.filter(blueprint=blueprint).order_by("name"))
    if target_ids:
        target_id_set = {str(value) for value in target_ids}
        release_targets = [target for target in release_targets if str(target.id) in target_id_set]
    stop_services = bool(payload.get("stop_services")) or mode in {"stop_services", "force"}
    delete_dns = bool(payload.get("delete_dns", True))
    remove_runtime_markers = bool(payload.get("remove_runtime_markers", True))
    plan = _build_blueprint_deprovision_plan(
        blueprint,
        release_targets,
        stop_services=stop_services,
        delete_dns=delete_dns,
        remove_runtime_markers=remove_runtime_markers,
        force_mode=(mode == "force"),
    )
    if not plan["flags"].get("can_execute") and mode != "force":
        return JsonResponse(
            {
                "error": "deprovision_plan_not_executable",
                "warnings": plan.get("warnings", []),
                "plan": plan,
            },
            status=400,
        )
    dry_run = bool(payload.get("dry_run", False))
    run = Run.objects.create(
        entity_type="blueprint",
        entity_id=blueprint.id,
        status="running",
        summary=f"Deprovision {expected}",
        log_text="Starting blueprint deprovision\n",
        metadata_json={
            "operation": "blueprint_deprovision",
            "mode": mode,
            "dry_run": dry_run,
            "release_target_ids": [str(target.id) for target in release_targets],
        },
        created_by=request.user,
        started_at=timezone.now(),
    )
    _write_run_artifact(run, "deprovision_plan.json", plan, "deprovision")
    implementation_plan = {
        "schema_version": "implementation_plan.v1",
        "blueprint_id": str(blueprint.id),
        "blueprint_name": expected,
        "generated_at": timezone.now().isoformat(),
        "work_items": [entry.get("work_item", {}) for entry in plan.get("steps", []) if isinstance(entry, dict)],
        "tasks": [
            {
                "task_type": "codegen",
                "title": f"Deprovision: {entry.get('title')}",
                "context_purpose": "operator",
                "work_item_id": str((entry.get("work_item") or {}).get("id") or ""),
            }
            for entry in plan.get("steps", [])
            if isinstance(entry, dict)
        ],
    }
    _write_run_artifact(run, "implementation_plan.json", implementation_plan, "implementation_plan")
    _write_run_artifact(run, "implementation_plan.md", "# Deprovision Plan\n\nGenerated by lifecycle action.", "implementation_plan")
    created_tasks: List[DevTask] = []
    if not dry_run:
        for item in implementation_plan.get("work_items", []):
            if not isinstance(item, dict):
                continue
            config = item.get("config") if isinstance(item.get("config"), dict) else {}
            target_instance = None
            target_instance_id = str(config.get("target_instance_id") or "").strip()
            if target_instance_id:
                target_instance = ProvisionedInstance.objects.filter(id=target_instance_id).first()
            task = DevTask.objects.create(
                title=f"Deprovision: {item.get('title') or item.get('id') or 'step'}",
                task_type="codegen",
                status="queued",
                priority=0,
                source_entity_type="blueprint",
                source_entity_id=blueprint.id,
                source_run=run,
                input_artifact_key="implementation_plan.json",
                work_item_id=str(item.get("id") or ""),
                context_purpose="operator",
                target_instance=target_instance,
                created_by=request.user,
                updated_by=request.user,
            )
            created_tasks.append(task)
            _enqueue_job("xyn_orchestrator.worker_tasks.run_dev_task", str(task.id), "worker")
        if created_tasks:
            blueprint.status = "deprovisioning"
        else:
            blueprint.status = "deprovisioned"
            blueprint.deprovisioned_at = timezone.now()
        blueprint.deprovision_last_run = run
        blueprint.updated_by = request.user
        blueprint.save(
            update_fields=["status", "deprovisioned_at", "deprovision_last_run", "updated_by", "updated_at"]
        )
        run.log_text += f"Queued {len(created_tasks)} deprovision task(s)\n"
    else:
        run.log_text += "Dry-run only; no deprovision tasks queued\n"
    run.status = "succeeded"
    run.finished_at = timezone.now()
    run.save(update_fields=["status", "finished_at", "log_text", "updated_at"])
    _write_run_summary(run)
    return JsonResponse(
        {
            "run_id": str(run.id),
            "status": run.status,
            "blueprint_status": blueprint.status,
            "task_count": len(created_tasks),
            "dry_run": dry_run,
        }
    )


@csrf_exempt
@login_required
def blueprint_submit(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    return instantiate_blueprint(request, blueprint_id)


@login_required
def blueprint_runs(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    runs = Run.objects.filter(entity_type="blueprint", entity_id=blueprint_id).order_by("-created_at")
    data = [
        {
            "id": str(run.id),
            "status": run.status,
            "summary": run.summary,
            "created_at": run.created_at,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
        }
        for run in runs
    ]
    return _paginate(request, data, "runs")


@csrf_exempt
@login_required
def blueprint_draft_sessions(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    blueprint = get_object_or_404(Blueprint, id=blueprint_id)
    if request.method == "POST":
        payload = _parse_json(request)
        title = (payload.get("title") or payload.get("name") or "").strip() or "Untitled draft"
        draft_kind = str(payload.get("kind") or payload.get("draft_kind") or "blueprint").strip().lower()
        if draft_kind not in {"blueprint", "solution"}:
            return JsonResponse({"error": "kind must be blueprint or solution"}, status=400)
        blueprint_kind = str(payload.get("blueprint_kind") or "solution")
        namespace = (payload.get("namespace") or blueprint.namespace or "").strip()
        project_key = (payload.get("project_key") or f"{blueprint.namespace}.{blueprint.name}").strip()
        generate_code = bool(payload.get("generate_code", False))
        context_pack_ids = payload.get("selected_context_pack_ids")
        if context_pack_ids is None:
            context_pack_ids = payload.get("context_pack_ids")
        if context_pack_ids is None:
            context_pack_ids = _recommended_context_pack_ids(
                draft_kind=draft_kind,
                namespace=namespace or None,
                project_key=project_key or None,
                generate_code=generate_code,
            )
        if not isinstance(context_pack_ids, list):
            return JsonResponse({"error": "context_pack_ids must be a list"}, status=400)
        session = BlueprintDraftSession.objects.create(
            name=title,
            title=title,
            blueprint=blueprint,
            draft_kind=draft_kind,
            blueprint_kind=blueprint_kind,
            namespace=namespace,
            project_key=project_key,
            initial_prompt=(payload.get("initial_prompt") or "").strip(),
            revision_instruction=(payload.get("revision_instruction") or "").strip(),
            selected_context_pack_ids=context_pack_ids,
            context_pack_ids=context_pack_ids,
            source_artifacts=payload.get("source_artifacts") if isinstance(payload.get("source_artifacts"), list) else [],
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse(
            {
                "session_id": str(session.id),
                "title": session.title or session.name,
                "kind": session.draft_kind,
                "selected_context_pack_ids": session.selected_context_pack_ids or session.context_pack_ids or [],
            }
        )
    sessions = BlueprintDraftSession.objects.filter(blueprint=blueprint).order_by("-created_at")
    data = [
        {
            "id": str(session.id),
            "name": session.title or session.name,
            "title": session.title or session.name,
            "kind": session.draft_kind,
            "status": session.status,
            "blueprint_kind": session.blueprint_kind,
            "created_at": session.created_at,
            "updated_at": session.updated_at,
        }
        for session in sessions
    ]
    return JsonResponse({"sessions": data})


@login_required
def blueprint_voice_notes(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    sessions = BlueprintDraftSession.objects.filter(blueprint_id=blueprint_id)
    links = DraftSessionVoiceNote.objects.filter(draft_session__in=sessions).select_related(
        "voice_note", "voice_note__transcript"
    )
    data = []
    for link in links:
        note = link.voice_note
        transcript = getattr(note, "transcript", None)
        data.append(
            {
                "id": str(note.id),
                "title": note.title,
                "status": note.status,
                "created_at": note.created_at,
                "session_id": str(link.draft_session_id),
                "job_id": note.job_id,
                "last_error": note.error,
                "transcript_text": transcript.transcript_text if transcript else None,
                "transcript_confidence": transcript.confidence if transcript else None,
            }
        )
    return JsonResponse({"voice_notes": data})


@csrf_exempt
@login_required
def modules_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name")
        namespace = payload.get("namespace")
        module_type = payload.get("type")
        if not name or not namespace or not module_type:
            return JsonResponse({"error": "name, namespace, and type are required"}, status=400)
        fqn = f"{namespace}.{name}"
        module, _ = Module.objects.get_or_create(
            fqn=fqn,
            defaults={
                "name": name,
                "namespace": namespace,
                "type": module_type,
                "current_version": payload.get("current_version", "0.1.0"),
                "latest_module_spec_json": payload.get("latest_module_spec_json"),
                "created_by": request.user,
                "updated_by": request.user,
            },
        )
        if payload.get("latest_module_spec_json"):
            module.latest_module_spec_json = payload.get("latest_module_spec_json")
            module.updated_by = request.user
            module.save(update_fields=["latest_module_spec_json", "updated_by", "updated_at"])
        return JsonResponse({"id": str(module.id), "fqn": module.fqn})
    maybe_sync_modules_from_registry()
    qs = Module.objects.all().order_by("namespace", "name")
    if query := request.GET.get("q"):
        qs = qs.filter(models.Q(name__icontains=query) | models.Q(fqn__icontains=query))
    data = [
        {
            "id": str(module.id),
            "name": module.name,
            "namespace": module.namespace,
            "fqn": module.fqn,
            "type": module.type,
            "current_version": module.current_version,
            "status": module.status,
            "created_at": module.created_at,
            "updated_at": module.updated_at,
        }
        for module in qs
    ]
    return _paginate(request, data, "modules")


@csrf_exempt
@login_required
def module_detail(request: HttpRequest, module_ref: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "GET":
        maybe_sync_modules_from_registry()
    try:
        module = Module.objects.get(id=module_ref)
    except (Module.DoesNotExist, ValueError):
        module = get_object_or_404(Module, fqn=module_ref)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["name", "namespace", "type", "current_version", "status", "latest_module_spec_json"]:
            if field in payload:
                setattr(module, field, payload[field])
        if "name" in payload or "namespace" in payload:
            module.fqn = f"{module.namespace}.{module.name}"
        module.updated_by = request.user
        module.save()
        return JsonResponse({"id": str(module.id)})
    if request.method == "DELETE":
        module.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(
        {
            "id": str(module.id),
            "name": module.name,
            "namespace": module.namespace,
            "fqn": module.fqn,
            "type": module.type,
            "current_version": module.current_version,
            "status": module.status,
            "latest_module_spec_json": module.latest_module_spec_json,
            "created_at": module.created_at,
            "updated_at": module.updated_at,
        }
    )


@csrf_exempt
@login_required
def bundles_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name")
        namespace = payload.get("namespace")
        if name and namespace:
            fqn = f"{namespace}.{name}"
            bundle, _ = Bundle.objects.get_or_create(
                fqn=fqn,
                defaults={
                    "name": name,
                    "namespace": namespace,
                    "current_version": payload.get("current_version", "0.1.0"),
                    "bundle_spec_json": payload.get("bundle_spec_json"),
                    "created_by": request.user,
                    "updated_by": request.user,
                },
            )
            return JsonResponse({"id": str(bundle.id), "fqn": bundle.fqn})
    qs = Bundle.objects.all().order_by("namespace", "name")
    data = [
        {
            "id": str(bundle.id),
            "name": bundle.name,
            "namespace": bundle.namespace,
            "fqn": bundle.fqn,
            "current_version": bundle.current_version,
            "status": bundle.status,
            "created_at": bundle.created_at,
            "updated_at": bundle.updated_at,
        }
        for bundle in qs
    ]
    return _paginate(request, data, "bundles")


@csrf_exempt
@login_required
def bundle_detail(request: HttpRequest, bundle_ref: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    try:
        bundle = Bundle.objects.get(id=bundle_ref)
    except (Bundle.DoesNotExist, ValueError):
        bundle = get_object_or_404(Bundle, fqn=bundle_ref)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["name", "namespace", "current_version", "status", "bundle_spec_json"]:
            if field in payload:
                setattr(bundle, field, payload[field])
        if "name" in payload or "namespace" in payload:
            bundle.fqn = f"{bundle.namespace}.{bundle.name}"
        bundle.updated_by = request.user
        bundle.save()
        return JsonResponse({"id": str(bundle.id)})
    if request.method == "DELETE":
        bundle.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(
        {
            "id": str(bundle.id),
            "name": bundle.name,
            "namespace": bundle.namespace,
            "fqn": bundle.fqn,
            "current_version": bundle.current_version,
            "status": bundle.status,
            "bundle_spec_json": bundle.bundle_spec_json,
            "created_at": bundle.created_at,
            "updated_at": bundle.updated_at,
        }
    )


@csrf_exempt
@login_required
def release_targets_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        blueprint_id = payload.get("blueprint_id")
        if not blueprint_id:
            return JsonResponse({"error": "blueprint_id is required"}, status=400)
        blueprint = get_object_or_404(Blueprint, id=blueprint_id)
        normalized = _normalize_release_target_payload(payload, str(blueprint.id))
        errors = _validate_release_target_payload(normalized)
        if errors:
            return JsonResponse({"error": "Invalid ReleaseTarget", "details": errors}, status=400)
        target_instance = None
        if normalized.get("target_instance_id"):
            target_instance = ProvisionedInstance.objects.filter(id=normalized["target_instance_id"]).first()
        target = ReleaseTarget.objects.create(
            blueprint=blueprint,
            name=normalized["name"],
            environment=normalized.get("environment", ""),
            target_instance_ref=normalized.get("target_instance_id", ""),
            target_instance=target_instance,
            fqdn=normalized["fqdn"],
            dns_json=normalized.get("dns"),
            runtime_json=normalized.get("runtime"),
            tls_json=normalized.get("tls"),
            env_json=normalized.get("env"),
            secret_refs_json=normalized.get("secret_refs"),
            config_json=normalized,
            auto_generated=bool(normalized.get("auto_generated", False)),
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse({"id": str(target.id)})
    qs = ReleaseTarget.objects.all()
    if blueprint_id := request.GET.get("blueprint_id"):
        qs = qs.filter(blueprint_id=blueprint_id)
    data = [_serialize_release_target(target) for target in qs.order_by("-created_at")]
    return JsonResponse({"release_targets": data})


@csrf_exempt
@login_required
def release_target_detail(request: HttpRequest, target_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    target = get_object_or_404(ReleaseTarget, id=target_id)
    if request.method == "GET":
        return JsonResponse(_serialize_release_target(target))
    if request.method == "DELETE":
        target.delete()
        return JsonResponse({}, status=204)
    if request.method != "PATCH":
        return JsonResponse({"error": "PATCH required"}, status=405)
    payload = _parse_json(request)
    base = _serialize_release_target(target)
    for key, value in payload.items():
        if key in {"dns", "runtime", "tls", "env"} and isinstance(value, dict):
            merged = dict(base.get(key) or {})
            merged.update(value)
            base[key] = merged
        else:
            base[key] = value
    normalized = _normalize_release_target_payload(base, str(target.blueprint_id), str(target.id))
    normalized["updated_at"] = timezone.now().isoformat()
    errors = _validate_release_target_payload(normalized)
    if errors:
        return JsonResponse({"error": "Invalid ReleaseTarget", "details": errors}, status=400)
    target_instance = None
    if normalized.get("target_instance_id"):
        target_instance = ProvisionedInstance.objects.filter(id=normalized["target_instance_id"]).first()
    target.name = normalized["name"]
    target.environment = normalized.get("environment", "")
    target.target_instance_ref = normalized.get("target_instance_id", "")
    target.target_instance = target_instance
    target.fqdn = normalized["fqdn"]
    target.dns_json = normalized.get("dns")
    target.runtime_json = normalized.get("runtime")
    target.tls_json = normalized.get("tls")
    target.env_json = normalized.get("env")
    target.secret_refs_json = normalized.get("secret_refs")
    target.config_json = normalized
    target.auto_generated = bool(normalized.get("auto_generated", False))
    target.updated_by = request.user
    target.save()
    return JsonResponse({"id": str(target.id)})


@login_required
def map_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)

    blueprint_id = (request.GET.get("blueprint_id") or "").strip()
    environment_id = (request.GET.get("environment_id") or "").strip()
    tenant_id = (request.GET.get("tenant_id") or "").strip()
    include_runs = _parse_bool_param(request.GET.get("include_runs"), default=True)
    include_instances = _parse_bool_param(request.GET.get("include_instances"), default=True)
    include_drafts = _parse_bool_param(request.GET.get("include_drafts"), default=False)
    latest_per_blueprint = 10

    is_platform_admin = _is_platform_admin(identity)
    allowed_tenant_ids = set(
        str(value)
        for value in TenantMembership.objects.filter(user_identity=identity, status="active").values_list("tenant_id", flat=True)
    )
    if tenant_id and not is_platform_admin and tenant_id not in allowed_tenant_ids:
        return JsonResponse({"error": "forbidden"}, status=403)

    blueprints = list(Blueprint.objects.all().order_by("namespace", "name"))
    if blueprint_id:
        blueprints = [b for b in blueprints if str(b.id) == blueprint_id]

    def _blueprint_allowed(blueprint: Blueprint) -> bool:
        hinted_tenant = _extract_tenant_hint(blueprint.metadata_json)
        if tenant_id:
            return hinted_tenant == tenant_id
        if is_platform_admin:
            return True
        if not hinted_tenant:
            return False
        return hinted_tenant in allowed_tenant_ids

    blueprints = [b for b in blueprints if _blueprint_allowed(b)]
    blueprint_ids = [b.id for b in blueprints]

    environments = list(Environment.objects.all().order_by("name"))
    env = next((item for item in environments if str(item.id) == environment_id), None) if environment_id else None

    release_plans_qs = ReleasePlan.objects.filter(blueprint_id__in=blueprint_ids).select_related("last_run", "environment")
    if environment_id:
        release_plans_qs = release_plans_qs.filter(environment_id=environment_id)
    release_plans = list(release_plans_qs.order_by("-created_at"))

    releases_qs = Release.objects.filter(blueprint_id__in=blueprint_ids).select_related("release_plan", "created_from_run")
    if not include_drafts:
        releases_qs = releases_qs.exclude(status="draft")
    if environment_id:
        releases_qs = releases_qs.filter(release_plan__environment_id=environment_id)
    releases = list(releases_qs.order_by("-created_at"))
    release_counts: Dict[str, int] = {}
    filtered_releases: List[Release] = []
    for release in releases:
        key = str(release.blueprint_id)
        release_counts[key] = release_counts.get(key, 0) + 1
        if release_counts[key] <= latest_per_blueprint:
            filtered_releases.append(release)
    releases = filtered_releases

    targets_qs = ReleaseTarget.objects.filter(blueprint_id__in=blueprint_ids).select_related("target_instance", "blueprint")
    if environment_id:
        env_matches = {environment_id}
        if env:
            env_matches.add(env.slug)
            env_matches.add(env.name)
        targets_qs = targets_qs.filter(environment__in=env_matches)
    targets = list(targets_qs.order_by("name"))

    def _target_allowed(target: ReleaseTarget) -> bool:
        hinted_tenant = _extract_tenant_hint(target.config_json) or _extract_tenant_hint(target.blueprint.metadata_json)
        if tenant_id:
            return hinted_tenant == tenant_id
        if is_platform_admin:
            return True
        if not hinted_tenant:
            return False
        return hinted_tenant in allowed_tenant_ids

    targets = [t for t in targets if _target_allowed(t)]
    target_ids = [str(target.id) for target in targets]

    instances: Dict[str, ProvisionedInstance] = {}
    if include_instances:
        instance_ids = [target.target_instance_id for target in targets if target.target_instance_id]
        if instance_ids:
            instance_qs = ProvisionedInstance.objects.filter(id__in=instance_ids).select_related("environment")
            instances = {str(instance.id): instance for instance in instance_qs}

    latest_deploy_by_target: Dict[str, Run] = {}
    latest_success_by_target: Dict[str, Run] = {}
    active_run_by_target: Dict[str, Run] = {}
    if include_runs and target_ids:
        deploy_runs = list(
            Run.objects.filter(metadata_json__release_target_id__in=target_ids)
            .order_by("-created_at")
        )
        for run in deploy_runs:
            rt_id = str((run.metadata_json or {}).get("release_target_id") or "")
            if not rt_id:
                continue
            if rt_id not in latest_deploy_by_target:
                latest_deploy_by_target[rt_id] = run
            if rt_id not in latest_success_by_target and (run.metadata_json or {}).get("deploy_outcome") in {"succeeded", "noop"}:
                latest_success_by_target[rt_id] = run
            if rt_id not in active_run_by_target and run.status in {"pending", "running"}:
                active_run_by_target[rt_id] = run

    run_ids_from_releases = [release.created_from_run_id for release in releases if release.created_from_run_id]
    release_runs: Dict[str, Run] = {}
    if include_runs and run_ids_from_releases:
        release_runs = {str(run.id): run for run in Run.objects.filter(id__in=run_ids_from_releases)}

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes: set[str] = set()
    seen_edges: set[str] = set()

    def _add_node(payload: Dict[str, Any]) -> None:
        node_id = payload["id"]
        if node_id in seen_nodes:
            return
        seen_nodes.add(node_id)
        nodes.append(payload)

    def _add_edge(from_id: str, to_id: str, kind: str) -> None:
        edge_id = f"{kind}:{from_id}:{to_id}"
        if edge_id in seen_edges:
            return
        seen_edges.add(edge_id)
        edges.append({"id": edge_id, "from": from_id, "to": to_id, "kind": kind})

    blueprint_by_id = {str(blueprint.id): blueprint for blueprint in blueprints}
    for blueprint in blueprints:
        _add_node(
            {
                "id": f"blueprint:{blueprint.id}",
                "kind": "blueprint",
                "ref": {"id": str(blueprint.id), "kind": "blueprint"},
                "label": f"{blueprint.namespace}.{blueprint.name}",
                "status": "ok",
                "badges": [],
                "metrics": {
                    "description": blueprint.description or "",
                    "updated_at": blueprint.updated_at.isoformat() if blueprint.updated_at else None,
                },
                "links": {"detail": "/app/blueprints"},
            }
        )

    for plan in release_plans:
        node_id = f"release_plan:{plan.id}"
        _add_node(
            {
                "id": node_id,
                "kind": "release_plan",
                "ref": {"id": str(plan.id), "kind": "release_plan"},
                "label": plan.name,
                "status": _status_from_run(plan.last_run),
                "badges": [plan.target_kind],
                "metrics": {
                    "target_fqn": plan.target_fqn,
                    "environment_id": str(plan.environment_id) if plan.environment_id else None,
                    "last_run_id": str(plan.last_run_id) if plan.last_run_id else None,
                    "to_version": plan.to_version,
                },
                "links": {"detail": "/app/release-plans"},
            }
        )
        if plan.blueprint_id:
            _add_edge(f"blueprint:{plan.blueprint_id}", node_id, "plans")

    releases_by_blueprint: Dict[str, List[Release]] = {}
    for release in releases:
        bp_key = str(release.blueprint_id) if release.blueprint_id else ""
        if bp_key:
            releases_by_blueprint.setdefault(bp_key, []).append(release)
        release_node_id = f"release:{release.id}"
        run = release_runs.get(str(release.created_from_run_id)) if release.created_from_run_id else None
        badges = [release.status]
        if release.build_state:
            badges.append(release.build_state)
        _add_node(
            {
                "id": release_node_id,
                "kind": "release",
                "ref": {"id": str(release.id), "kind": "release"},
                "label": release.version,
                "status": _status_from_release(release),
                "badges": badges,
                "metrics": {
                    "blueprint_id": str(release.blueprint_id) if release.blueprint_id else None,
                    "release_plan_id": str(release.release_plan_id) if release.release_plan_id else None,
                    "created_from_run_id": str(release.created_from_run_id) if release.created_from_run_id else None,
                    "build_state": release.build_state,
                    "release_status": release.status,
                },
                "links": {"detail": "/app/releases"},
            }
        )
        if release.release_plan_id:
            _add_edge(f"release_plan:{release.release_plan_id}", release_node_id, "produces")
        elif release.blueprint_id:
            _add_edge(f"blueprint:{release.blueprint_id}", release_node_id, "publishes")
        if include_runs and run:
            run_node_id = f"run:{run.id}"
            _add_node(
                {
                    "id": run_node_id,
                    "kind": "run",
                    "ref": {"id": str(run.id), "kind": "run"},
                    "label": run.summary or f"Run {str(run.id)[:8]}",
                    "status": _status_from_run(run),
                    "badges": [run.entity_type],
                    "metrics": {
                        "entity_type": run.entity_type,
                        "entity_id": str(run.entity_id),
                        "run_status": run.status,
                        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                    },
                    "links": {"detail": f"/app/runs?run={run.id}"},
                }
            )
            _add_edge(release_node_id, run_node_id, "built_by")

    for target in targets:
        target_node_id = f"release_target:{target.id}"
        latest = latest_deploy_by_target.get(str(target.id))
        latest_success = latest_success_by_target.get(str(target.id))
        active = active_run_by_target.get(str(target.id))
        metrics = {
            "environment": target.environment or "",
            "fqdn": target.fqdn,
            "target_instance_id": str(target.target_instance_id) if target.target_instance_id else None,
            "current_release_id": (latest_success.metadata_json or {}).get("release_uuid") if latest_success else None,
            "current_release_version": (latest_success.metadata_json or {}).get("release_version") if latest_success else None,
            "drift_state": "unknown",
            "lock_state": "running" if active else "unlocked",
            "last_deploy_outcome": (latest.metadata_json or {}).get("deploy_outcome") if latest else None,
            "last_deploy_at": latest.finished_at.isoformat() if latest and latest.finished_at else None,
            "last_deploy_run_id": str(latest.id) if latest else None,
        }
        badges: List[str] = []
        if metrics["lock_state"] == "running":
            badges.append("locked")
        if metrics["current_release_id"]:
            badges.append("published")
        status = "warn" if active else "ok"
        if latest and latest.status == "failed":
            status = "error"
        _add_node(
            {
                "id": target_node_id,
                "kind": "release_target",
                "ref": {"id": str(target.id), "kind": "release_target"},
                "label": target.name,
                "status": status,
                "badges": badges,
                "metrics": metrics,
                "links": {
                    "detail": "/app/release-plans",
                    "runs": f"/app/runs?q={target.id}",
                },
            }
        )
        blueprint_releases = releases_by_blueprint.get(str(target.blueprint_id), [])
        for release in blueprint_releases:
            _add_edge(f"release:{release.id}", target_node_id, "deployed_to")
        if include_instances and target.target_instance_id:
            instance = instances.get(str(target.target_instance_id))
            if instance:
                instance_node_id = f"instance:{instance.id}"
                _add_node(
                    {
                        "id": instance_node_id,
                        "kind": "instance",
                        "ref": {"id": str(instance.id), "kind": "instance"},
                        "label": instance.name,
                        "status": "ok" if instance.status in {"running", "ready"} else "warn",
                        "badges": [instance.status, instance.health_status],
                        "metrics": {
                            "status": instance.status,
                            "health_status": instance.health_status,
                            "environment_id": str(instance.environment_id) if instance.environment_id else None,
                            "public_ip": instance.public_ip,
                            "private_ip": instance.private_ip,
                            "last_deploy_run_id": str(instance.last_deploy_run_id) if instance.last_deploy_run_id else None,
                        },
                        "links": {"detail": "/app/instances"},
                    }
                )
                _add_edge(target_node_id, instance_node_id, "runs_on")
        if include_runs and latest:
            run_node_id = f"run:{latest.id}"
            _add_node(
                {
                    "id": run_node_id,
                    "kind": "run",
                    "ref": {"id": str(latest.id), "kind": "run"},
                    "label": latest.summary or f"Run {str(latest.id)[:8]}",
                    "status": _status_from_run(latest),
                    "badges": [latest.entity_type],
                    "metrics": {
                        "entity_type": latest.entity_type,
                        "entity_id": str(latest.entity_id),
                        "run_status": latest.status,
                        "finished_at": latest.finished_at.isoformat() if latest.finished_at else None,
                    },
                    "links": {"detail": f"/app/runs?run={latest.id}"},
                }
            )
            _add_edge(target_node_id, run_node_id, "latest_deploy_run")

    tenant_options: List[Dict[str, str]] = []
    if is_platform_admin:
        tenant_options = [{"id": str(t.id), "name": t.name} for t in Tenant.objects.all().order_by("name")]
    else:
        tenant_options = [
            {"id": str(m.tenant_id), "name": m.tenant.name}
            for m in TenantMembership.objects.filter(
                user_identity=identity,
                status="active",
            ).select_related("tenant").order_by("tenant__name")
        ]

    return JsonResponse(
        {
            "meta": {
                "generated_at": timezone.now().isoformat(),
                "filters": {
                    "blueprint_id": blueprint_id or None,
                    "environment_id": environment_id or None,
                    "tenant_id": tenant_id or None,
                    "include_runs": include_runs,
                    "include_instances": include_instances,
                    "include_drafts": include_drafts,
                },
                "options": {
                    "blueprints": [{"id": str(b.id), "label": f"{b.namespace}.{b.name}"} for b in blueprints],
                    "environments": [{"id": str(item.id), "name": item.name} for item in environments],
                    "tenants": tenant_options,
                },
            },
            "nodes": nodes,
            "edges": edges,
            "suggested_layout": "layered_lr",
        }
    )


@csrf_exempt
@login_required
def release_target_deploy_latest_action(request: HttpRequest, target_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    token = os.environ.get("XYENCE_INTERNAL_TOKEN", "").strip()
    if not token:
        return JsonResponse({"error": "Internal token not configured"}, status=500)
    internal_request = HttpRequest()
    internal_request.method = "POST"
    internal_request.META["HTTP_X_INTERNAL_TOKEN"] = token
    return internal_release_target_deploy_latest(internal_request, target_id)


@csrf_exempt
@login_required
def release_target_rollback_last_success_action(request: HttpRequest, target_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    token = os.environ.get("XYENCE_INTERNAL_TOKEN", "").strip()
    if not token:
        return JsonResponse({"error": "Internal token not configured"}, status=500)
    internal_request = HttpRequest()
    internal_request.method = "POST"
    internal_request.META["HTTP_X_INTERNAL_TOKEN"] = token
    return internal_release_target_rollback_last_success(internal_request, target_id)


@login_required
def release_target_check_drift_action(request: HttpRequest, target_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    token = os.environ.get("XYENCE_INTERNAL_TOKEN", "").strip()
    if not token:
        return JsonResponse({"error": "Internal token not configured"}, status=500)
    internal_request = HttpRequest()
    internal_request.method = "GET"
    internal_request.META["HTTP_X_INTERNAL_TOKEN"] = token
    return internal_release_target_check_drift(internal_request, target_id)


@csrf_exempt
@login_required
def registries_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name")
        registry_type = payload.get("registry_type")
        if not name or not registry_type:
            return JsonResponse({"error": "name and registry_type required"}, status=400)
        registry = Registry.objects.create(
            name=name,
            registry_type=registry_type,
            description=payload.get("description", ""),
            url=payload.get("url", ""),
            status=payload.get("status", "active"),
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse({"id": str(registry.id)})
    qs = Registry.objects.all().order_by("name")
    data = [
        {
            "id": str(registry.id),
            "name": registry.name,
            "registry_type": registry.registry_type,
            "status": registry.status,
            "last_sync_at": registry.last_sync_at,
            "created_at": registry.created_at,
            "updated_at": registry.updated_at,
        }
        for registry in qs
    ]
    return _paginate(request, data, "registries")


@csrf_exempt
@login_required
def registry_detail(request: HttpRequest, registry_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    registry = get_object_or_404(Registry, id=registry_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["name", "registry_type", "description", "url", "status"]:
            if field in payload:
                setattr(registry, field, payload[field])
        registry.updated_by = request.user
        registry.save()
        return JsonResponse({"id": str(registry.id)})
    if request.method == "DELETE":
        registry.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(
        {
            "id": str(registry.id),
            "name": registry.name,
            "registry_type": registry.registry_type,
            "description": registry.description,
            "url": registry.url,
            "status": registry.status,
            "last_sync_at": registry.last_sync_at,
            "created_at": registry.created_at,
            "updated_at": registry.updated_at,
        }
    )


@csrf_exempt
@login_required
def registry_sync(request: HttpRequest, registry_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    registry = get_object_or_404(Registry, id=registry_id)
    run = Run.objects.create(
        entity_type="registry",
        entity_id=registry.id,
        status="pending",
        summary=f"Sync registry {registry.name}",
        created_by=request.user,
        started_at=timezone.now(),
    )
    mode = _async_mode()
    if mode == "redis":
        _enqueue_job("xyn_orchestrator.worker_tasks.sync_registry", str(registry.id), str(run.id))
        return JsonResponse({"status": "queued", "run_id": str(run.id)})
    registry.last_sync_at = timezone.now()
    registry.updated_by = request.user
    registry.save(update_fields=["last_sync_at", "updated_by", "updated_at"])
    run.status = "succeeded"
    run.finished_at = timezone.now()
    run.save(update_fields=["status", "finished_at", "updated_at"])
    _write_run_summary(run)
    return JsonResponse({"status": "synced", "last_sync_at": registry.last_sync_at, "run_id": str(run.id)})


@csrf_exempt
@login_required
def release_plans_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        identity = _require_authenticated(request)
        if not identity:
            return JsonResponse({"error": "not authenticated"}, status=401)
        payload = _parse_json(request)
        name = payload.get("name")
        target_kind = payload.get("target_kind")
        target_fqn = payload.get("target_fqn")
        to_version = payload.get("to_version")
        if not name or not target_kind or not target_fqn or not to_version:
            return JsonResponse({"error": "name, target_kind, target_fqn, to_version required"}, status=400)
        if not payload.get("environment_id"):
            return JsonResponse({"error": "environment_id required"}, status=400)
        target_fqn = str(payload.get("target_fqn") or "")
        if target_fqn in _control_plane_app_ids() and not _is_platform_architect(identity):
            return JsonResponse({"error": "platform_architect role required for control plane plans"}, status=403)
        plan = ReleasePlan.objects.create(
            name=name,
            target_kind=target_kind,
            target_fqn=target_fqn,
            from_version=payload.get("from_version", ""),
            to_version=to_version,
            milestones_json=payload.get("milestones_json"),
            blueprint_id=payload.get("blueprint_id"),
            environment_id=payload.get("environment_id"),
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse({"id": str(plan.id)})
    qs = ReleasePlan.objects.all().select_related("blueprint").order_by("-created_at")
    if env_id := request.GET.get("environment_id"):
        qs = qs.filter(environment_id=env_id)
    plans = list(qs)
    for plan in plans:
        _reconcile_release_plan_alignment(plan)
    data = [
        {
            "id": str(plan.id),
            "name": plan.name,
            "target_kind": plan.target_kind,
            "target_fqn": plan.target_fqn,
            "from_version": plan.from_version,
            "to_version": plan.to_version,
            "blueprint_id": str(plan.blueprint_id) if plan.blueprint_id else None,
            "environment_id": str(plan.environment_id) if plan.environment_id else None,
            "last_run": str(plan.last_run_id) if plan.last_run_id else None,
            "created_at": plan.created_at,
            "updated_at": plan.updated_at,
        }
        for plan in plans
    ]
    return _paginate(request, data, "release_plans")


@csrf_exempt
@login_required
def release_plan_detail(request: HttpRequest, plan_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    plan = get_object_or_404(ReleasePlan, id=plan_id)
    if request.method == "PATCH":
        identity = _require_authenticated(request)
        if not identity:
            return JsonResponse({"error": "not authenticated"}, status=401)
        payload = _parse_json(request)
        target_fqn = str(payload.get("target_fqn") or plan.target_fqn or "")
        if target_fqn in _control_plane_app_ids() and not _is_platform_architect(identity):
            return JsonResponse({"error": "platform_architect role required for control plane plans"}, status=403)
        if "environment_id" in payload and not payload.get("environment_id"):
            return JsonResponse({"error": "environment_id required"}, status=400)
        explicit_release_id = payload.get("release_id") or payload.get("selected_release_id")
        for field in ["name", "target_kind", "target_fqn", "from_version", "to_version", "milestones_json"]:
            if field in payload:
                setattr(plan, field, payload[field])
        if "blueprint_id" in payload:
            plan.blueprint_id = payload.get("blueprint_id")
        if "environment_id" in payload:
            plan.environment_id = payload.get("environment_id")
        if plan.environment_id is None:
            return JsonResponse({"error": "environment_id required"}, status=400)
        plan.updated_by = request.user
        plan.save()
        _reconcile_release_plan_alignment(
            plan,
            explicit_release_id=str(explicit_release_id) if explicit_release_id else None,
            updated_by=request.user,
            allow_state_fallback=False,
        )
        return JsonResponse({"id": str(plan.id)})
    if request.method == "DELETE":
        plan.delete()
        return JsonResponse({"status": "deleted"})
    current_release, _ = _reconcile_release_plan_alignment(plan)
    deployments = [
        {
            "instance_id": str(dep.instance_id),
            "instance_name": dep.instance.name,
            "last_applied_hash": dep.last_applied_hash,
            "last_applied_at": dep.last_applied_at,
        }
        for dep in plan.deployments.select_related("instance").order_by("-last_applied_at", "-updated_at")
    ]
    return JsonResponse(
        {
            "id": str(plan.id),
            "name": plan.name,
            "target_kind": plan.target_kind,
            "target_fqn": plan.target_fqn,
            "from_version": plan.from_version,
            "to_version": plan.to_version,
            "milestones_json": plan.milestones_json,
            "blueprint_id": str(plan.blueprint_id) if plan.blueprint_id else None,
            "environment_id": str(plan.environment_id) if plan.environment_id else None,
            "current_release_id": str(current_release.id) if current_release else None,
            "current_release_version": current_release.version if current_release else None,
            "last_run": str(plan.last_run_id) if plan.last_run_id else None,
            "deployments": deployments,
            "created_at": plan.created_at,
            "updated_at": plan.updated_at,
        }
    )


@csrf_exempt
@login_required
def release_plan_reconcile(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = _parse_json(request)
    dry_run = _parse_bool_param(str(payload.get("dry_run")) if payload.get("dry_run") is not None else None, False)
    qs = ReleasePlan.objects.all().select_related("blueprint").order_by("-updated_at")
    if plan_id := payload.get("plan_id"):
        qs = qs.filter(id=plan_id)
    if blueprint_id := payload.get("blueprint_id"):
        qs = qs.filter(blueprint_id=blueprint_id)
    plans = list(qs)
    changed: List[Dict[str, Any]] = []
    for plan in plans:
        release, did_change = _reconcile_release_plan_alignment(
            plan,
            updated_by=request.user,
            apply_changes=not dry_run,
        )
        if did_change:
            changed.append(
                {
                    "plan_id": str(plan.id),
                    "name": plan.name,
                    "to_version": plan.to_version,
                    "release_id": str(release.id) if release else None,
                    "release_version": release.version if release else None,
                }
            )
    return JsonResponse(
        {
            "status": "dry_run" if dry_run else "ok",
            "total": len(plans),
            "changed": len(changed),
            "plans": changed,
        }
    )


@csrf_exempt
@login_required
def release_plan_generate(request: HttpRequest, plan_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    plan = get_object_or_404(ReleasePlan, id=plan_id)
    run = Run.objects.create(
        entity_type="release_plan",
        entity_id=plan.id,
        status="pending",
        summary=f"Generate release plan {plan.name}",
        created_by=request.user,
        started_at=timezone.now(),
    )
    mode = _async_mode()
    if mode == "redis":
        _enqueue_job("xyn_orchestrator.worker_tasks.generate_release_plan", str(plan.id), str(run.id))
        return JsonResponse({"run_id": str(run.id), "status": "queued"})
    if not plan.milestones_json:
        plan.milestones_json = {"status": "placeholder", "notes": "Generation not implemented yet"}
        plan.save(update_fields=["milestones_json", "updated_at"])
    run.status = "succeeded"
    run.finished_at = timezone.now()
    run.save(update_fields=["status", "finished_at", "updated_at"])
    _write_run_summary(run)
    return JsonResponse({"run_id": str(run.id), "status": run.status})


@csrf_exempt
@login_required
def release_plan_deployments(request: HttpRequest, plan_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    plan = get_object_or_404(ReleasePlan, id=plan_id)
    if _is_control_plane_plan(plan):
        identity = _require_authenticated(request)
        if not identity:
            return JsonResponse({"error": "not authenticated"}, status=401)
        if not _is_platform_architect(identity):
            return JsonResponse({"error": "platform_architect role required for control plane deploys"}, status=403)
    payload = _parse_json(request)
    instance_id = payload.get("instance_id")
    if not instance_id:
        return JsonResponse({"error": "instance_id required"}, status=400)
    instance = get_object_or_404(ProvisionedInstance, id=instance_id)
    if not plan.environment_id:
        return JsonResponse({"error": "release plan missing environment"}, status=400)
    if not instance.environment_id:
        return JsonResponse({"error": "instance missing environment"}, status=400)
    if str(plan.environment_id) != str(instance.environment_id):
        return JsonResponse({"error": "instance environment does not match release plan"}, status=400)
    deployment, _ = ReleasePlanDeployment.objects.get_or_create(
        release_plan=plan, instance=instance
    )
    if payload.get("last_applied_hash") is not None:
        deployment.last_applied_hash = payload.get("last_applied_hash", "")
    applied_at = payload.get("last_applied_at")
    if applied_at:
        deployment.last_applied_at = parse_datetime(applied_at)
    if not deployment.last_applied_at:
        deployment.last_applied_at = timezone.now()
    deployment.save()
    _audit_action(
        f"Release plan deployment marker updated for {plan.id}",
        {"release_plan_id": str(plan.id), "instance_id": str(instance.id)},
        request,
    )
    return JsonResponse({"status": "ok"})


def _preferred_release_for_plan(plan: ReleasePlan, explicit_release_id: Optional[str] = None) -> Optional[Release]:
    if explicit_release_id:
        release = Release.objects.filter(id=explicit_release_id).first()
        if not release:
            return None
        if plan.blueprint_id and release.blueprint_id and str(release.blueprint_id) != str(plan.blueprint_id):
            return None
        return release
    if not plan.blueprint_id or not plan.to_version:
        return None
    return (
        Release.objects.filter(blueprint_id=plan.blueprint_id, version=plan.to_version)
        .order_by(models.Case(models.When(status="published", then=0), default=1), "-updated_at", "-created_at")
        .first()
    )


def _preferred_release_for_plan_from_environment_state(plan: ReleasePlan) -> Optional[Release]:
    if not plan.environment_id:
        return None
    app_candidates: List[str] = []
    if plan.target_fqn:
        app_candidates.append(str(plan.target_fqn).strip())
    if plan.blueprint_id and plan.blueprint:
        app_candidates.append(f"{plan.blueprint.namespace}.{plan.blueprint.name}")
    app_candidates = [candidate for candidate in app_candidates if candidate]
    if not app_candidates:
        return None
    state = (
        EnvironmentAppState.objects.filter(environment_id=plan.environment_id, app_id__in=app_candidates)
        .select_related("current_release")
        .order_by(
            models.Case(
                *[models.When(app_id=app_id, then=idx) for idx, app_id in enumerate(app_candidates)],
                default=len(app_candidates),
            )
        )
        .first()
    )
    if not state or not state.current_release_id or not state.current_release:
        return None
    release = state.current_release
    if plan.blueprint_id and release.blueprint_id and str(release.blueprint_id) != str(plan.blueprint_id):
        return None
    return release


def _reconcile_release_plan_alignment(
    plan: ReleasePlan,
    *,
    explicit_release_id: Optional[str] = None,
    updated_by=None,
    allow_state_fallback: bool = True,
    apply_changes: bool = True,
) -> Tuple[Optional[Release], bool]:
    preferred = _preferred_release_for_plan(plan, explicit_release_id=explicit_release_id)
    if not preferred and allow_state_fallback:
        preferred = _preferred_release_for_plan_from_environment_state(plan)
    selected_release_id = str(preferred.id) if preferred else (str(explicit_release_id) if explicit_release_id else None)
    to_version_changed = bool(preferred and plan.to_version != preferred.version)
    if preferred:
        stale_exists = Release.objects.filter(release_plan_id=plan.id).exclude(id=preferred.id).exists()
        relink_needed = preferred.release_plan_id != plan.id
    else:
        stale_exists = Release.objects.filter(release_plan_id=plan.id).exclude(version=plan.to_version).exists()
        relink_needed = False
    changed = to_version_changed or stale_exists or relink_needed
    if not apply_changes:
        return preferred, changed
    if to_version_changed and preferred:
        plan.to_version = preferred.version
        if updated_by is not None:
            plan.updated_by = updated_by
            plan.save(update_fields=["to_version", "updated_by", "updated_at"])
        else:
            plan.save(update_fields=["to_version", "updated_at"])
    synced = _sync_release_plan_release_link(
        plan,
        explicit_release_id=selected_release_id,
        updated_by=updated_by,
    )
    return synced or preferred, changed


def _sync_release_plan_release_link(
    plan: ReleasePlan,
    *,
    explicit_release_id: Optional[str] = None,
    updated_by=None,
) -> Optional[Release]:
    preferred = _preferred_release_for_plan(plan, explicit_release_id=explicit_release_id)
    if preferred:
        stale_qs = Release.objects.filter(release_plan_id=plan.id).exclude(id=preferred.id)
    else:
        stale_qs = Release.objects.filter(release_plan_id=plan.id).exclude(version=plan.to_version)
    if stale_qs.exists():
        stale_qs.update(release_plan_id=None)
    if preferred and preferred.release_plan_id != plan.id:
        preferred.release_plan_id = plan.id
        if updated_by is not None:
            preferred.updated_by = updated_by
            preferred.save(update_fields=["release_plan_id", "updated_by", "updated_at"])
        else:
            preferred.save(update_fields=["release_plan_id", "updated_at"])
    return preferred


def _build_release_plan_match_index(blueprint_ids: Set[str], versions: Set[str]) -> Dict[tuple[str, str], ReleasePlan]:
    if not blueprint_ids or not versions:
        return {}
    plans = (
        ReleasePlan.objects.filter(blueprint_id__in=blueprint_ids, to_version__in=versions)
        .order_by("-updated_at", "-created_at")
    )
    index: Dict[tuple[str, str], ReleasePlan] = {}
    for plan in plans:
        key = (str(plan.blueprint_id), str(plan.to_version))
        if key not in index:
            index[key] = plan
    return index


def _resolved_release_plan_for_release(
    release: Release,
    *,
    plan_index: Optional[Dict[tuple[str, str], ReleasePlan]] = None,
) -> Optional[ReleasePlan]:
    if release.release_plan_id and release.release_plan:
        linked = release.release_plan
        if (
            linked.to_version == release.version
            and (not linked.blueprint_id or not release.blueprint_id or str(linked.blueprint_id) == str(release.blueprint_id))
        ):
            return linked
    if not release.blueprint_id:
        return None
    key = (str(release.blueprint_id), str(release.version))
    if plan_index is not None:
        return plan_index.get(key)
    return (
        ReleasePlan.objects.filter(blueprint_id=release.blueprint_id, to_version=release.version)
        .order_by("-updated_at", "-created_at")
        .first()
    )


@csrf_exempt
@login_required
def releases_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        version = payload.get("version")
        if not version:
            return JsonResponse({"error": "version required"}, status=400)
        release = Release.objects.create(
            blueprint_id=payload.get("blueprint_id"),
            release_plan_id=payload.get("release_plan_id"),
            created_from_run_id=payload.get("created_from_run_id"),
            version=version,
            status=payload.get("status", "draft"),
            build_state=payload.get("build_state", "draft"),
            artifacts_json=payload.get("artifacts_json"),
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse({"id": str(release.id)})
    qs = Release.objects.all().select_related("release_plan").order_by("-created_at")
    if blueprint_id := request.GET.get("blueprint_id"):
        qs = qs.filter(blueprint_id=blueprint_id)
    if status := request.GET.get("status"):
        qs = qs.filter(status=status)
    releases = list(qs)
    blueprint_ids = {str(release.blueprint_id) for release in releases if release.blueprint_id}
    versions = {str(release.version) for release in releases if release.version}
    plan_index = _build_release_plan_match_index(blueprint_ids, versions)
    data = []
    for release in releases:
        resolved_plan = _resolved_release_plan_for_release(release, plan_index=plan_index)
        data.append(
            {
                "id": str(release.id),
                "version": release.version,
                "status": release.status,
                "build_state": release.build_state,
                "blueprint_id": str(release.blueprint_id) if release.blueprint_id else None,
                "release_plan_id": str(resolved_plan.id) if resolved_plan else None,
                "created_from_run_id": str(release.created_from_run_id) if release.created_from_run_id else None,
                "created_at": release.created_at,
                "updated_at": release.updated_at,
            }
        )
    return _paginate(request, data, "releases")


@csrf_exempt
@login_required
def releases_bulk_delete(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = _parse_json(request)
    release_ids = payload.get("release_ids")
    if not isinstance(release_ids, list) or not release_ids:
        return JsonResponse({"error": "release_ids list is required"}, status=400)
    if len(release_ids) > 200:
        return JsonResponse({"error": "at most 200 releases can be deleted per request"}, status=400)

    ordered_ids: List[str] = []
    seen: Set[str] = set()
    for value in release_ids:
        rid = str(value).strip()
        if not rid or rid in seen:
            continue
        seen.add(rid)
        ordered_ids.append(rid)

    releases_by_id = {
        str(release.id): release for release in Release.objects.filter(id__in=ordered_ids)
    }
    deleted: List[str] = []
    skipped: List[Dict[str, str]] = []
    image_cleanup: Dict[str, Any] = {}

    for rid in ordered_ids:
        release = releases_by_id.get(rid)
        if not release:
            skipped.append({"id": rid, "reason": "not_found"})
            continue
        resolved_plan = _resolved_release_plan_for_release(release)
        if release.status == "published" and resolved_plan:
            skipped.append({"id": rid, "reason": "published_with_release_plan"})
            continue
        cleanup = _delete_release_images(release)
        image_cleanup[rid] = cleanup
        release.delete()
        deleted.append(rid)

    status_code = 200 if not skipped else 207
    return JsonResponse(
        {
            "status": "ok",
            "requested_count": len(ordered_ids),
            "deleted_count": len(deleted),
            "skipped_count": len(skipped),
            "deleted": deleted,
            "skipped": skipped,
            "image_cleanup": image_cleanup,
        },
        status=status_code,
    )


@csrf_exempt
@login_required
def release_detail(request: HttpRequest, release_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    release = get_object_or_404(Release, id=release_id)
    if request.method == "PATCH":
        identity = _require_authenticated(request)
        if not identity:
            return JsonResponse({"error": "not authenticated"}, status=401)
        payload = _parse_json(request)
        prev_status = release.status
        next_status = payload.get("status", release.status)
        if (
            _is_control_plane_release(release)
            and str(next_status) == "published"
            and not _is_platform_architect(identity)
        ):
            return JsonResponse({"error": "platform_architect role required for control plane release publish"}, status=403)
        for field in ["version", "status", "build_state", "artifacts_json", "release_plan_id", "blueprint_id"]:
            if field in payload:
                setattr(release, field, payload[field])
        release.updated_by = request.user
        release.save()
        build_run_id = None
        if payload.get("status") == "published" and prev_status != "published":
            release.build_state = "building"
            release.save(update_fields=["build_state", "updated_at"])
            _audit_action(
                f"Release {release.id} published",
                {"release_id": str(release.id), "version": release.version},
                request,
            )
            build_result = _enqueue_release_build(release, request.user)
            build_run_id = build_result.get("run_id")
            if not build_result.get("ok"):
                release.build_state = "failed"
                release.save(update_fields=["build_state", "updated_at"])
            elif not build_result.get("queued"):
                release.build_state = "ready"
                release.save(update_fields=["build_state", "updated_at"])
        return JsonResponse({"id": str(release.id), "build_run_id": build_run_id})
    if request.method == "DELETE":
        if release.status == "published" and _resolved_release_plan_for_release(release):
            return JsonResponse(
                {"error": "published releases linked to a release plan cannot be deleted"},
                status=400,
            )
        cleanup = _delete_release_images(release)
        release.delete()
        return JsonResponse({"status": "deleted", "image_cleanup": cleanup})
    resolved_plan = _resolved_release_plan_for_release(release)
    return JsonResponse(
        {
            "id": str(release.id),
            "version": release.version,
            "status": release.status,
            "build_state": release.build_state,
            "blueprint_id": str(release.blueprint_id) if release.blueprint_id else None,
            "release_plan_id": str(resolved_plan.id) if resolved_plan else None,
            "created_from_run_id": str(release.created_from_run_id) if release.created_from_run_id else None,
            "artifacts_json": release.artifacts_json,
            "created_at": release.created_at,
            "updated_at": release.updated_at,
        }
    )


@csrf_exempt
@login_required
def environments_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name")
        slug = payload.get("slug")
        if not name or not slug:
            return JsonResponse({"error": "name and slug required"}, status=400)
        environment = Environment.objects.create(
            name=name,
            slug=slug,
            base_domain=payload.get("base_domain", ""),
            aws_region=payload.get("aws_region", ""),
        )
        return JsonResponse({"id": str(environment.id)})
    qs = Environment.objects.all().order_by("name")
    data = [
        {
            "id": str(env.id),
            "name": env.name,
            "slug": env.slug,
            "base_domain": env.base_domain,
            "aws_region": env.aws_region,
            "created_at": env.created_at,
            "updated_at": env.updated_at,
        }
        for env in qs
    ]
    return _paginate(request, data, "environments")


@csrf_exempt
@login_required
def environment_detail(request: HttpRequest, env_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    environment = get_object_or_404(Environment, id=env_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["name", "slug", "base_domain", "aws_region"]:
            if field in payload:
                setattr(environment, field, payload[field])
        environment.save()
        return JsonResponse({"id": str(environment.id)})
    if request.method == "DELETE":
        environment.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(
        {
            "id": str(environment.id),
            "name": environment.name,
            "slug": environment.slug,
            "base_domain": environment.base_domain,
            "aws_region": environment.aws_region,
            "created_at": environment.created_at,
            "updated_at": environment.updated_at,
        }
    )


@login_required
def control_plane_state(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    app_registry = [
        {
            "app_id": "xyn-api",
            "display_name": "Xyn API",
            "category": "control-plane",
            "default_health_checks": ["https://<fqdn>/health"],
        },
        {
            "app_id": "xyn-ui",
            "display_name": "Xyn UI",
            "category": "control-plane",
            "default_health_checks": ["https://<fqdn>/", "https://<fqdn>/auth/login"],
        },
    ]
    env_qs = Environment.objects.all().order_by("name")
    if env_id := request.GET.get("environment_id"):
        env_qs = env_qs.filter(id=env_id)
    environments = list(env_qs)
    states_payload: List[Dict[str, Any]] = []
    for env in environments:
        for app in app_registry:
            app_id = app["app_id"]
            state = (
                EnvironmentAppState.objects.filter(environment=env, app_id=app_id)
                .select_related("current_release", "last_good_release", "last_deploy_run")
                .first()
            )
            last_deployment = (
                Deployment.objects.filter(environment=env, app_id=app_id)
                .order_by("-created_at")
                .first()
            )
            states_payload.append(
                {
                    "environment_id": str(env.id),
                    "environment_name": env.name,
                    "app_id": app_id,
                    "display_name": app["display_name"],
                    "category": app["category"],
                    "current_release_id": str(state.current_release_id) if state and state.current_release_id else None,
                    "current_release_version": state.current_release.version if state and state.current_release else None,
                    "last_good_release_id": str(state.last_good_release_id) if state and state.last_good_release_id else None,
                    "last_good_release_version": (
                        state.last_good_release.version if state and state.last_good_release else None
                    ),
                    "last_deploy_run_id": str(state.last_deploy_run_id) if state and state.last_deploy_run_id else None,
                    "last_deployed_at": state.last_deployed_at if state else None,
                    "last_good_at": state.last_good_at if state else None,
                    "last_deployment_id": str(last_deployment.id) if last_deployment else None,
                    "last_deployment_status": last_deployment.status if last_deployment else None,
                    "last_deployment_error": last_deployment.error_message if last_deployment else "",
                }
            )
    release_options: List[Dict[str, Any]] = []
    for release in Release.objects.filter(status="published", build_state="ready").select_related("blueprint", "release_plan"):
        release_app_id = infer_app_id(release, release.release_plan)
        if release_app_id not in {"xyn-api", "xyn-ui", "core.xyn-api", "core.xyn-ui"}:
            continue
        release_options.append(
            {
                "id": str(release.id),
                "app_id": "xyn-api" if release_app_id in {"xyn-api", "core.xyn-api"} else "xyn-ui",
                "version": release.version,
                "release_plan_id": str(release.release_plan_id) if release.release_plan_id else None,
            }
        )
    instance_options = [
        {
            "id": str(instance.id),
            "name": instance.name,
            "environment_id": str(instance.environment_id) if instance.environment_id else None,
            "status": instance.status,
        }
        for instance in ProvisionedInstance.objects.order_by("name")
    ]
    return JsonResponse(
        {
            "app_registry": app_registry,
            "states": states_payload,
            "releases": release_options,
            "instances": instance_options,
        }
    )


@csrf_exempt
@login_required
def control_plane_deploy(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if architect_error := _require_platform_architect(request):
        return architect_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = _parse_json(request)
    environment_id = payload.get("environment_id")
    app_id = payload.get("app_id")
    release_id = payload.get("release_id")
    instance_id = payload.get("instance_id")
    if not environment_id or not app_id or not release_id:
        return JsonResponse({"error": "environment_id, app_id, and release_id required"}, status=400)
    environment = get_object_or_404(Environment, id=environment_id)
    release = get_object_or_404(Release, id=release_id)
    if release.status != "published":
        return JsonResponse({"error": "release must be published"}, status=400)
    if release.build_state != "ready":
        return JsonResponse({"error": "release build must be ready"}, status=400)
    release_plan = release.release_plan
    if release_plan and release_plan.environment_id and str(release_plan.environment_id) != str(environment.id):
        return JsonResponse({"error": "release plan environment mismatch"}, status=400)
    inferred = infer_app_id(release, release_plan)
    canonical_requested = "xyn-api" if app_id in {"xyn-api", "core.xyn-api"} else "xyn-ui"
    canonical_release = "xyn-api" if inferred in {"xyn-api", "core.xyn-api"} else "xyn-ui"
    if canonical_requested != canonical_release:
        return JsonResponse({"error": "release does not belong to requested app"}, status=400)
    if instance_id:
        instance = get_object_or_404(ProvisionedInstance, id=instance_id)
    else:
        instance = (
            ProvisionedInstance.objects.filter(environment=environment, status__in=["running", "ready"])
            .order_by("-updated_at")
            .first()
        )
        if not instance:
            return JsonResponse({"error": "no eligible instance found for environment"}, status=400)
    if str(instance.environment_id) != str(environment.id):
        return JsonResponse({"error": "instance environment mismatch"}, status=400)
    if not instance.instance_id or not instance.aws_region:
        return JsonResponse({"error": "instance missing runtime identity"}, status=400)
    deploy_kind = "release_plan" if release_plan else "release"
    base_key = compute_idempotency_base(release, instance, release_plan, deploy_kind)
    deployment = Deployment.objects.create(
        idempotency_key=hashlib.sha256(f"{base_key}:{uuid.uuid4()}".encode("utf-8")).hexdigest(),
        idempotency_base=base_key,
        app_id=canonical_requested,
        environment=environment,
        release=release,
        instance=instance,
        release_plan=release_plan,
        deploy_kind=deploy_kind,
        submitted_by="platform_architect",
        status="queued",
    )
    plan_json = load_release_plan_json(release, release_plan)
    if not plan_json:
        deployment.status = "failed"
        deployment.error_message = "release_plan.json not found for deployment"
        deployment.finished_at = timezone.now()
        deployment.save(update_fields=["status", "error_message", "finished_at", "updated_at"])
        return JsonResponse({"deployment_id": str(deployment.id), "status": deployment.status}, status=400)
    execute_release_plan_deploy(deployment, release, instance, release_plan, plan_json)
    rollback = maybe_trigger_rollback(deployment)
    _audit_action(
        f"Control plane deploy requested for {canonical_requested}",
        {
            "deployment_id": str(deployment.id),
            "environment_id": str(environment.id),
            "release_id": str(release.id),
            "rollback_deployment_id": str(rollback.id) if rollback else None,
        },
        request,
    )
    return JsonResponse(
        {
            "deployment_id": str(deployment.id),
            "status": deployment.status,
            "rollback_deployment_id": str(rollback.id) if rollback else None,
            "rollback_status": rollback.status if rollback else None,
        }
    )


@csrf_exempt
@login_required
def control_plane_rollback(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if architect_error := _require_platform_architect(request):
        return architect_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = _parse_json(request)
    deployment_id = payload.get("deployment_id")
    if deployment_id:
        deployment = get_object_or_404(Deployment, id=deployment_id)
    else:
        environment_id = payload.get("environment_id")
        app_id = payload.get("app_id")
        if not environment_id or not app_id:
            return JsonResponse({"error": "deployment_id or environment_id+app_id required"}, status=400)
        deployment = (
            Deployment.objects.filter(environment_id=environment_id, app_id=app_id)
            .exclude(status="succeeded")
            .order_by("-created_at")
            .first()
        )
        if not deployment:
            return JsonResponse({"error": "no failed deployment found"}, status=404)
    rollback = maybe_trigger_rollback(deployment)
    if not rollback:
        return JsonResponse({"error": "rollback unavailable"}, status=400)
    _audit_action(
        "Manual rollback triggered",
        {
            "deployment_id": str(deployment.id),
            "rollback_deployment_id": str(rollback.id),
            "app_id": deployment.app_id,
            "environment_id": str(deployment.environment_id) if deployment.environment_id else None,
        },
        request,
    )
    return JsonResponse(
        {
            "deployment_id": str(deployment.id),
            "rollback_deployment_id": str(rollback.id),
            "rollback_status": rollback.status,
        }
    )


@login_required
def runs_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    qs = Run.objects.all()
    if entity_type := request.GET.get("entity"):
        qs = qs.filter(entity_type=entity_type)
    if entity_id := request.GET.get("id"):
        qs = qs.filter(entity_id=entity_id)
    if status := request.GET.get("status"):
        qs = qs.filter(status=status)
    if query := request.GET.get("q"):
        qs = qs.filter(
            models.Q(summary__icontains=query)
            | models.Q(entity_type__icontains=query)
            | models.Q(entity_id__icontains=query)
        )
    data = [
        {
            "id": str(run.id),
            "entity_type": run.entity_type,
            "entity_id": str(run.entity_id),
            "status": run.status,
            "summary": run.summary,
            "created_at": run.created_at,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
        }
        for run in qs.order_by("-created_at")
    ]
    return _paginate(request, data, "runs")


@login_required
def run_detail(request: HttpRequest, run_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    run = get_object_or_404(Run, id=run_id)
    return JsonResponse(
        {
            "id": str(run.id),
            "entity_type": run.entity_type,
            "entity_id": str(run.entity_id),
            "status": run.status,
            "summary": run.summary,
            "created_at": run.created_at,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "error": run.error,
            "log_text": run.log_text,
            "metadata": run.metadata_json,
            "context_pack_refs": run.context_pack_refs_json,
        }
    )


@login_required
def run_logs(request: HttpRequest, run_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    run = get_object_or_404(Run, id=run_id)
    return JsonResponse({"log": run.log_text, "error": run.error})


@login_required
def run_artifacts(request: HttpRequest, run_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    run = get_object_or_404(Run, id=run_id)
    artifacts = [
        {
            "id": str(artifact.id),
            "name": artifact.name,
            "kind": artifact.kind,
            "url": artifact.url,
            "metadata": artifact.metadata_json,
            "created_at": artifact.created_at,
        }
        for artifact in run.artifacts.all()
    ]
    return JsonResponse({"artifacts": artifacts})


@login_required
def run_commands(request: HttpRequest, run_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    run = get_object_or_404(Run, id=run_id)
    commands = [
        {
            "id": str(cmd.id),
            "step_name": cmd.step_name,
            "command_index": cmd.command_index,
            "shell": cmd.shell,
            "status": cmd.status,
            "exit_code": cmd.exit_code,
            "started_at": cmd.started_at,
            "finished_at": cmd.finished_at,
            "ssm_command_id": cmd.ssm_command_id,
            "stdout": cmd.stdout,
            "stderr": cmd.stderr,
        }
        for cmd in run.command_executions.all()
    ]
    return JsonResponse({"commands": commands})


@csrf_exempt
@login_required
def dev_tasks_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        title = payload.get("title")
        task_type = payload.get("task_type")
        if not title or not task_type:
            return JsonResponse({"error": "title and task_type required"}, status=400)
        if task_type == "deploy_release_plan" and not payload.get("target_instance_id"):
            return JsonResponse({"error": "target_instance_id required for deploy_release_plan"}, status=400)
        release = None
        if payload.get("release_id"):
            release = get_object_or_404(Release, id=payload["release_id"])
        target_instance = None
        if payload.get("target_instance_id"):
            target_instance = get_object_or_404(ProvisionedInstance, id=payload["target_instance_id"])
            if release:
                target_instance.desired_release = release
                target_instance.save(update_fields=["desired_release", "updated_at"])
        dev_task = DevTask.objects.create(
            title=title,
            task_type=task_type,
            status=payload.get("status", "queued"),
            priority=payload.get("priority", 0),
            max_attempts=payload.get("max_attempts", 3),
            source_entity_type=payload.get("source_entity_type", "manual"),
            source_entity_id=payload.get("source_entity_id") or uuid.uuid4(),
            source_run_id=payload.get("source_run_id") or None,
            input_artifact_key=payload.get("input_artifact_key", ""),
            work_item_id=payload.get("work_item_id", ""),
            context_purpose=payload.get("context_purpose", "any"),
            target_instance=target_instance,
            force=bool(payload.get("force")),
            created_by=request.user,
            updated_by=request.user,
        )
        if pack_ids := payload.get("context_pack_ids"):
            packs = ContextPack.objects.filter(id__in=pack_ids)
            dev_task.context_packs.add(*packs)
        return JsonResponse({"id": str(dev_task.id)})
    qs = DevTask.objects.all()
    if status := request.GET.get("status"):
        qs = qs.filter(status=status)
    if task_type := request.GET.get("task_type"):
        qs = qs.filter(task_type=task_type)
    if source_entity_type := request.GET.get("source_entity_type"):
        qs = qs.filter(source_entity_type=source_entity_type)
    if source_entity_id := request.GET.get("source_entity_id"):
        qs = qs.filter(source_entity_id=source_entity_id)
    if target_instance_id := request.GET.get("target_instance_id"):
        qs = qs.filter(target_instance_id=target_instance_id)
    if query := request.GET.get("q"):
        qs = qs.filter(
            models.Q(title__icontains=query)
            | models.Q(task_type__icontains=query)
            | models.Q(work_item_id__icontains=query)
            | models.Q(last_error__icontains=query)
        )
    data = [
        {
            "id": str(task.id),
            "title": task.title,
            "task_type": task.task_type,
            "status": task.status,
            "priority": task.priority,
            "attempts": task.attempts,
            "max_attempts": task.max_attempts,
            "locked_by": task.locked_by,
            "locked_at": task.locked_at,
            "source_entity_type": task.source_entity_type,
            "source_entity_id": str(task.source_entity_id),
            "source_run": str(task.source_run_id) if task.source_run_id else None,
            "result_run": str(task.result_run_id) if task.result_run_id else None,
            "work_item_id": task.work_item_id,
            "context_purpose": task.context_purpose,
            "target_instance_id": str(task.target_instance_id) if task.target_instance_id else None,
            "force": task.force,
            "created_at": task.created_at,
            "updated_at": task.updated_at,
        }
        for task in qs.order_by("-created_at")
    ]
    return _paginate(request, data, "dev_tasks")


@login_required
def dev_task_detail(request: HttpRequest, task_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    task = get_object_or_404(DevTask, id=task_id)
    result_run = task.result_run
    run_payload = None
    artifacts_payload = []
    commands_payload = []
    if result_run:
        run_payload = {
            "id": str(result_run.id),
            "status": result_run.status,
            "summary": result_run.summary,
            "error": result_run.error,
            "log_text": result_run.log_text,
            "started_at": result_run.started_at,
            "finished_at": result_run.finished_at,
        }
        artifacts_payload = [
            {
                "id": str(artifact.id),
                "name": artifact.name,
                "kind": artifact.kind,
                "url": artifact.url,
                "metadata": artifact.metadata_json,
                "created_at": artifact.created_at,
            }
            for artifact in result_run.artifacts.all().order_by("created_at")
        ]
        commands_payload = [
            {
                "id": str(cmd.id),
                "step_name": cmd.step_name,
                "command_index": cmd.command_index,
                "shell": cmd.shell,
                "status": cmd.status,
                "exit_code": cmd.exit_code,
                "started_at": cmd.started_at,
                "finished_at": cmd.finished_at,
                "ssm_command_id": cmd.ssm_command_id,
                "stdout": cmd.stdout,
                "stderr": cmd.stderr,
            }
            for cmd in result_run.command_executions.all().order_by("created_at")
        ]
    return JsonResponse(
        {
            "id": str(task.id),
            "title": task.title,
            "task_type": task.task_type,
            "status": task.status,
            "priority": task.priority,
            "attempts": task.attempts,
            "max_attempts": task.max_attempts,
            "locked_by": task.locked_by,
            "locked_at": task.locked_at,
            "source_entity_type": task.source_entity_type,
            "source_entity_id": str(task.source_entity_id),
            "source_run": str(task.source_run_id) if task.source_run_id else None,
            "result_run": str(task.result_run_id) if task.result_run_id else None,
            "input_artifact_key": task.input_artifact_key,
            "work_item_id": task.work_item_id,
            "last_error": task.last_error,
            "context_purpose": task.context_purpose,
            "target_instance_id": str(task.target_instance_id) if task.target_instance_id else None,
            "force": task.force,
            "context_packs": [
                {
                    "id": str(pack.id),
                    "name": pack.name,
                    "purpose": pack.purpose,
                    "scope": pack.scope,
                    "version": pack.version,
                }
                for pack in task.context_packs.all()
            ],
            "result_run_detail": run_payload,
            "result_run_artifacts": artifacts_payload,
            "result_run_commands": commands_payload,
            "created_at": task.created_at,
            "updated_at": task.updated_at,
        }
    )


@csrf_exempt
@login_required
def dev_task_run(request: HttpRequest, task_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    task = get_object_or_404(DevTask, id=task_id)
    if task.status == "running":
        return JsonResponse({"error": "Task already running"}, status=409)
    if task.task_type == "deploy_release_plan" and not task.target_instance_id:
        return JsonResponse({"error": "target_instance_id required for deploy_release_plan"}, status=400)
    if request.GET.get("force") == "1":
        task.force = True
    task.force = bool(task.force)
    task.status = "queued"
    task.updated_by = request.user
    task.save(update_fields=["status", "updated_by", "updated_at", "force"])
    run = Run.objects.create(
        entity_type="dev_task",
        entity_id=task.id,
        status="pending",
        summary=f"Run dev task {task.title}",
        created_by=request.user,
        started_at=timezone.now(),
    )
    task.result_run = run
    task.save(update_fields=["result_run", "updated_at"])
    resolved = _resolve_context_pack_list(list(task.context_packs.all()))
    run.context_pack_refs_json = resolved.get("refs", [])
    run.context_hash = resolved.get("hash", "")
    _build_context_artifacts(run, resolved)
    run.save(update_fields=["context_pack_refs_json", "context_hash", "updated_at"])
    mode = _async_mode()
    if mode == "redis":
        _enqueue_job("xyn_orchestrator.worker_tasks.run_dev_task", str(task.id), "worker")
        return JsonResponse({"run_id": str(run.id), "status": "queued"})
    return JsonResponse({"run_id": str(run.id), "status": "pending"})


@csrf_exempt
@login_required
def dev_task_retry(request: HttpRequest, task_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    task = get_object_or_404(DevTask, id=task_id)
    if task.status not in {"failed", "canceled"}:
        return JsonResponse({"error": "Task not retryable"}, status=409)
    task.status = "queued"
    task.updated_by = request.user
    task.save(update_fields=["status", "updated_by", "updated_at"])
    run = Run.objects.create(
        entity_type="dev_task",
        entity_id=task.id,
        status="pending",
        summary=f"Retry dev task {task.title}",
        created_by=request.user,
        started_at=timezone.now(),
    )
    task.result_run = run
    task.save(update_fields=["result_run", "updated_at"])
    resolved = _resolve_context_pack_list(list(task.context_packs.all()))
    run.context_pack_refs_json = resolved.get("refs", [])
    run.context_hash = resolved.get("hash", "")
    _build_context_artifacts(run, resolved)
    run.save(update_fields=["context_pack_refs_json", "context_hash", "updated_at"])
    mode = _async_mode()
    if mode == "redis":
        _enqueue_job("xyn_orchestrator.worker_tasks.run_dev_task", str(task.id), "worker")
        return JsonResponse({"run_id": str(run.id), "status": "queued"})
    return JsonResponse({"run_id": str(run.id), "status": "pending"})


@csrf_exempt
@login_required
def dev_task_cancel(request: HttpRequest, task_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    task = get_object_or_404(DevTask, id=task_id)
    if task.status in {"succeeded", "failed", "canceled"}:
        return JsonResponse({"status": task.status})
    task.status = "canceled"
    task.updated_by = request.user
    task.save(update_fields=["status", "updated_by", "updated_at"])
    return JsonResponse({"status": "canceled"})


@login_required
def blueprint_dev_tasks(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    tasks = DevTask.objects.filter(source_entity_type="blueprint", source_entity_id=blueprint_id).order_by(
        "-created_at"
    )
    data = [
        {
            "id": str(task.id),
            "title": task.title,
            "task_type": task.task_type,
            "status": task.status,
            "priority": task.priority,
            "attempts": task.attempts,
            "max_attempts": task.max_attempts,
            "result_run": str(task.result_run_id) if task.result_run_id else None,
            "created_at": task.created_at,
        }
        for task in tasks
    ]
    return JsonResponse({"dev_tasks": data})
logger = logging.getLogger(__name__)
