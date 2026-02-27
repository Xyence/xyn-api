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
from markdownify import markdownify as _markdownify_html
from django.conf import settings
from django.core.exceptions import ValidationError
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
    _require_internal_token,
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
    ArticleCategory,
    Artifact,
    ArtifactRevision,
    ArtifactEvent,
    ArtifactLink,
    ArtifactExternalRef,
    ArtifactReaction,
    ArtifactComment,
    PublishBinding,
    VideoRender,
    WorkflowRun,
    WorkflowRunEvent,
    IntentScript,
    LedgerEvent,
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
from .ai_compat import compute_effective_params
from .video_explainer import (
    default_video_spec,
    validate_video_spec,
    sanitize_payload,
    render_video,
    export_package_text,
    deterministic_scene_scaffold,
    normalize_video_scene,
)
from .access_explorer import (
    canonical_registry as access_canonical_registry,
    search_users as access_search_users,
    user_roles as access_user_roles_data,
    compute_effective_permissions as access_compute_effective_permissions,
    role_detail as access_role_detail_data,
)
from .seeds import (
    apply_seed_packs,
    get_seed_pack_status,
    list_seed_packs_status,
)
from .artifact_links import (
    ensure_blueprint_artifact,
    ensure_context_pack_artifact,
    ensure_draft_session_artifact,
    ensure_module_artifact,
    get_current_canonical,
    _default_workspace,
)
from .ledger import (
    compute_artifact_diff,
    emit_ledger_event,
    make_dedupe_key,
)
from .intent_engine import (
    DraftIntakeContractRegistry,
    IntentResolutionEngine,
    ResolutionContext,
    LlmIntentProposalProvider,
    PatchValidationError,
    apply_patch as intent_apply_patch,
)
from .intent_engine.patch_service import apply_context_pack_patch as intent_apply_context_pack_patch
from .intent_engine.patch_service import to_internal_format as intent_to_internal_format
from .intent_engine.telemetry import increment as intent_telemetry_increment

PLATFORM_ROLE_IDS = {"platform_owner", "platform_admin", "platform_architect", "platform_operator", "app_user"}
PREVIEW_SESSION_KEY = "xyn.preview.v1"
PREVIEW_TTL_SECONDS = 60 * 60
PREVIEW_ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
    "platform_owner": {"platform_owner", "platform_admin", "platform_architect", "platform_operator", "app_user"},
    "platform_admin": {"platform_architect", "platform_operator", "app_user"},
    "platform_architect": {"platform_operator", "app_user"},
}
DOC_ARTIFACT_TYPE_SLUG = "doc_page"
ARTICLE_ARTIFACT_TYPE_SLUG = "article"
CONTEXT_PACK_ARTIFACT_TYPE_SLUG = "context_pack"
WORKFLOW_ARTIFACT_TYPE_SLUG = "workflow"
ARTICLE_CATEGORIES = {"web", "guide", "core-concepts", "release-note", "internal", "tutorial"}
GUIDE_ARTICLE_CATEGORIES = {"guide", "core-concepts", "tutorial"}
ARTICLE_VISIBILITY_TYPES = {"public", "authenticated", "role_based", "private"}
ARTICLE_STATUS_CHOICES = {"draft", "reviewed", "ratified", "published", "deprecated"}
ARTICLE_FORMAT_TYPES = {"standard", "video_explainer"}
WORKFLOW_PROFILE_TYPES = {"tour"}
WORKFLOW_SCHEMA_VERSION = 1
WORKFLOW_DEFAULT_CATEGORY = "xyn_usage"
VIDEO_CONTEXT_PACK_PURPOSE = "video_explainer"
EXPLAINER_PURPOSES: Dict[str, Dict[str, str]] = {
    "explainer_script": {"name": "Script", "description": "Generate explainer narration scripts."},
    "explainer_storyboard": {"name": "Storyboard", "description": "Generate storyboard scene structures."},
    "explainer_visual_prompts": {"name": "Visual Prompts", "description": "Generate visual prompt sets per scene."},
    "explainer_narration": {"name": "Narration", "description": "Refine narration for spoken delivery."},
    "explainer_title_description": {"name": "Title/Description", "description": "Generate title and description options."},
}
ARTICLE_CATEGORY_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
PUBLISH_BINDING_TARGET_TYPES = {"xyn_ui_route", "public_web_path", "external_url"}
ARTICLE_TRANSITIONS = {
    "draft": {"reviewed", "published", "deprecated"},
    "reviewed": {"ratified", "published", "deprecated"},
    "ratified": {"published", "deprecated"},
    "published": {"deprecated"},
    "deprecated": set(),
}
WORKSPACE_ROLE_SLUGS = {"reader", "contributor", "publisher", "moderator", "admin"}
PURPOSE_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")


def _artifact_state_for_status(status: str) -> str:
    value = str(status or "").strip().lower()
    if value == "deprecated":
        return "deprecated"
    if value == "published":
        return "canonical"
    return "provisional"


def _truthy_env(value: Any, *, default: bool) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _intent_engine_enabled() -> bool:
    if "XYN_INTENT_ENGINE_V1" in os.environ:
        return _truthy_env(os.environ.get("XYN_INTENT_ENGINE_V1"), default=False)
    return bool(getattr(settings, "DEBUG", False))


def _intent_category_options() -> List[Dict[str, str]]:
    _ensure_default_article_categories_and_bindings()
    rows = ArticleCategory.objects.filter(enabled=True).order_by("name")
    return [{"slug": str(row.slug), "name": str(row.name)} for row in rows]


def _intent_contract_registry() -> DraftIntakeContractRegistry:
    return DraftIntakeContractRegistry(category_options_provider=_intent_category_options)


def _intent_engine() -> IntentResolutionEngine:
    return IntentResolutionEngine(
        proposal_provider=LlmIntentProposalProvider(),
        contracts=_intent_contract_registry(),
        context_pack_target_lookup=_lookup_context_pack_artifact_for_intent,
    )


def _intent_context_pack_audit(force_refresh: bool = False) -> Dict[str, Any]:
    try:
        meta = LlmIntentProposalProvider().context_pack_meta(force_refresh=force_refresh)
        return {
            "context_pack_slug": str(meta.get("slug") or ""),
            "context_pack_version": str(meta.get("version") or ""),
            "context_pack_hash": str(meta.get("hash") or ""),
        }
    except Exception:
        return {
            "context_pack_slug": LlmIntentProposalProvider.CONTEXT_PACK_SLUG,
            "context_pack_version": "",
            "context_pack_hash": "",
        }


def _audit_intent_event(
    *,
    message: str,
    identity: Optional[UserIdentity],
    request_id: str,
    artifact_id: Optional[str],
    proposal: Dict[str, Any],
    resolution: Dict[str, Any],
) -> None:
    AuditLog.objects.create(
        message=message,
        metadata_json={
            "request_id": request_id,
            "actor_identity_id": str(identity.id) if identity else None,
            "artifact_id": artifact_id,
            "proposal": proposal,
            "resolution": resolution,
        },
    )


def _utc_now_ts() -> int:
    return int(time.time())


def _preview_allowed_roles_for_actor(actor_roles: List[str]) -> Set[str]:
    allowed: Set[str] = set()
    for role in actor_roles:
        allowed.update(PREVIEW_ALLOWED_TRANSITIONS.get(role, set()))
    return allowed


def _load_preview_state(request: HttpRequest, actor_roles: List[str]) -> Dict[str, Any]:
    raw = request.session.get(PREVIEW_SESSION_KEY)
    if not isinstance(raw, dict):
        return {"enabled": False, "roles": [], "read_only": True, "expires_at": None, "started_at": None}
    enabled = bool(raw.get("enabled"))
    read_only = bool(raw.get("read_only", True))
    expires_at = int(raw.get("expires_at") or 0)
    roles = [str(role or "").strip() for role in (raw.get("roles") or []) if str(role or "").strip()]
    roles = [role for role in roles if role in PLATFORM_ROLE_IDS]
    now_ts = _utc_now_ts()
    allowed_targets = _preview_allowed_roles_for_actor(actor_roles)
    invalid_roles = [role for role in roles if role not in allowed_targets]
    if not enabled:
        return {"enabled": False, "roles": [], "read_only": read_only, "expires_at": None, "started_at": None}
    if not roles or expires_at <= now_ts or invalid_roles:
        request.session.pop(PREVIEW_SESSION_KEY, None)
        request.session.modified = True
        return {"enabled": False, "roles": [], "read_only": True, "expires_at": None, "started_at": None}
    return {
        "enabled": True,
        "roles": roles,
        "read_only": read_only,
        "expires_at": expires_at,
        "started_at": int(raw.get("started_at") or now_ts),
    }


def _set_preview_state(request: HttpRequest, *, roles: List[str], read_only: bool) -> Dict[str, Any]:
    now_ts = _utc_now_ts()
    state = {
        "enabled": True,
        "roles": roles,
        "read_only": bool(read_only),
        "started_at": now_ts,
        "expires_at": now_ts + PREVIEW_TTL_SECONDS,
    }
    request.session[PREVIEW_SESSION_KEY] = state
    request.session.modified = True
    return state


def _clear_preview_state(request: HttpRequest) -> None:
    request.session.pop(PREVIEW_SESSION_KEY, None)
    request.session.modified = True


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
    identity = UserIdentity.objects.filter(id=identity_id).first()
    if not identity:
        return None
    actor_roles = list(
        RoleBinding.objects.filter(user_identity=identity, scope_kind="platform")
        .values_list("role", flat=True)
    )
    preview = _load_preview_state(request, actor_roles)
    effective_roles = preview.get("roles") if preview.get("enabled") else actor_roles
    setattr(identity, "_xyn_actor_roles", actor_roles)
    setattr(identity, "_xyn_effective_roles", list(effective_roles or []))
    setattr(identity, "_xyn_preview", preview)
    setattr(request, "actor_roles", actor_roles)
    setattr(request, "effective_roles", list(effective_roles or []))
    setattr(request, "preview_state", preview)
    return identity


def _require_platform_architect(request: HttpRequest) -> Optional[JsonResponse]:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _is_platform_architect(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    request.user_identity = identity  # type: ignore[attr-defined]
    return None


def _get_roles(identity: UserIdentity) -> List[str]:
    effective_roles = getattr(identity, "_xyn_effective_roles", None)
    if isinstance(effective_roles, list):
        return [str(role or "") for role in effective_roles if str(role or "")]
    return list(
        RoleBinding.objects.filter(user_identity=identity)
        .values_list("role", flat=True)
    )


def _is_platform_admin(identity: UserIdentity) -> bool:
    effective = set(_get_roles(identity))
    return bool(effective.intersection({"platform_owner", "platform_admin"}))


def _has_platform_role(identity: UserIdentity, roles: List[str]) -> bool:
    effective = set(_get_roles(identity))
    expanded = set(roles)
    if "platform_admin" in expanded:
        expanded.add("platform_owner")
    if "platform_architect" in expanded:
        expanded.update({"platform_admin", "platform_owner"})
    return bool(effective.intersection(expanded))


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


def _ensure_article_artifact_type() -> ArtifactType:
    artifact_type, _ = ArtifactType.objects.get_or_create(
        slug=ARTICLE_ARTIFACT_TYPE_SLUG,
        defaults={
            "name": "Article",
            "description": "Governed knowledge artifact for web pages, guides, and documentation",
            "icon": "BookOpen",
            "schema_json": {
                "category": sorted(ARTICLE_CATEGORIES),
                "visibility_type": sorted(ARTICLE_VISIBILITY_TYPES),
                "status": sorted(ARTICLE_STATUS_CHOICES),
                "format": sorted(ARTICLE_FORMAT_TYPES),
            },
        },
    )
    _ensure_default_article_categories_and_bindings()
    return artifact_type


def _ensure_default_workflow_categories() -> None:
    ArticleCategory.objects.get_or_create(
        slug=WORKFLOW_DEFAULT_CATEGORY,
        defaults={"name": "Xyn Usage", "description": "Guided tours for Xyn usage and onboarding", "enabled": True},
    )


def _ensure_workflow_artifact_type() -> ArtifactType:
    artifact_type, _ = ArtifactType.objects.get_or_create(
        slug=WORKFLOW_ARTIFACT_TYPE_SLUG,
        defaults={
            "name": "Workflow",
            "description": "Governed workflow artifacts (tour profile)",
            "icon": "Route",
            "schema_json": {
                "profile": sorted(WORKFLOW_PROFILE_TYPES),
                "status": sorted(ARTICLE_STATUS_CHOICES),
                "category": [WORKFLOW_DEFAULT_CATEGORY],
            },
        },
    )
    _ensure_default_workflow_categories()
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


def _normalize_role_slugs(raw: Any) -> list[str]:
    values: list[str] = []
    if not isinstance(raw, list):
        return values
    seen: set[str] = set()
    for entry in raw:
        role = str(entry or "").strip().lower()
        if not role:
            continue
        if role in seen:
            continue
        seen.add(role)
        values.append(role)
    return values


def _normalize_article_category(raw: Any, *, fallback: str = "web") -> str:
    value = str(raw or "").strip().lower()
    if value in ARTICLE_CATEGORIES or ARTICLE_CATEGORY_SLUG_PATTERN.match(value):
        return value
    return fallback


def _ensure_default_article_categories_and_bindings() -> None:
    guide, _ = ArticleCategory.objects.get_or_create(
        slug="guide",
        defaults={"name": "Guide", "description": "Guides and route-bound in-app docs", "enabled": True},
    )
    web, _ = ArticleCategory.objects.get_or_create(
        slug="web",
        defaults={"name": "Web", "description": "Public website articles", "enabled": True},
    )
    PublishBinding.objects.get_or_create(
        scope_type="category",
        scope_id=guide.id,
        target_type="xyn_ui_route",
        target_value="/app/guides",
        defaults={"label": "Guides", "enabled": True},
    )
    PublishBinding.objects.get_or_create(
        scope_type="category",
        scope_id=web.id,
        target_type="public_web_path",
        target_value="/articles",
        defaults={"label": "Public Website", "enabled": True},
    )


def _resolve_article_category_slug(slug: str, *, allow_disabled: bool = True) -> Optional[ArticleCategory]:
    qs = ArticleCategory.objects.filter(slug=slug)
    if not allow_disabled:
        qs = qs.filter(enabled=True)
    return qs.first()


def _article_category_record(artifact: Artifact) -> Optional[ArticleCategory]:
    if artifact.article_category_id:
        return ArticleCategory.objects.filter(id=artifact.article_category_id).first()
    scope = dict(artifact.scope_json or {})
    legacy = _normalize_article_category(scope.get("category"), fallback="web")
    category = _resolve_article_category_slug(legacy, allow_disabled=True)
    if category:
        return category
    if legacy:
        return ArticleCategory.objects.create(slug=legacy, name=legacy.replace("-", " ").title(), enabled=True)
    return None


def _serialize_article_category_ref(artifact: Artifact) -> Dict[str, Any]:
    category = _article_category_record(artifact)
    if not category:
        return {"id": None, "slug": "web", "name": "Web", "enabled": True}
    return {"id": str(category.id), "slug": category.slug, "name": category.name, "enabled": bool(category.enabled)}


def _normalize_article_visibility_type(raw: Any, *, fallback: str = "private") -> str:
    value = str(raw or "").strip().lower()
    if value in ARTICLE_VISIBILITY_TYPES:
        return value
    return fallback


def _normalize_article_format(raw: Any, *, fallback: str = "standard") -> str:
    value = str(raw or "").strip().lower()
    if value in ARTICLE_FORMAT_TYPES:
        return value
    return fallback


def _artifact_visibility_for_article_type(visibility_type: str) -> str:
    if visibility_type == "public":
        return "public"
    if visibility_type in {"authenticated", "role_based"}:
        return "team"
    return "private"


def _article_visibility_type_from_artifact(artifact: Artifact) -> str:
    scope = dict(artifact.scope_json or {})
    value = str(scope.get("visibility_type") or "").strip().lower()
    if value in ARTICLE_VISIBILITY_TYPES:
        return value
    if artifact.visibility == "public":
        return "public"
    if artifact.visibility == "team":
        return "authenticated"
    return "private"


def _article_allowed_roles(artifact: Artifact) -> list[str]:
    scope = dict(artifact.scope_json or {})
    return _normalize_role_slugs(scope.get("allowed_roles"))


def _article_category(artifact: Artifact) -> str:
    scope = dict(artifact.scope_json or {})
    if artifact.type.slug == DOC_ARTIFACT_TYPE_SLUG:
        tags = _normalize_doc_tags((scope or {}).get("tags"))
        if "core-concepts" in tags:
            return "core-concepts"
        if "tutorial" in tags:
            return "tutorial"
        return "guide"
    category = _article_category_record(artifact)
    if category:
        return category.slug
    return _normalize_article_category(scope.get("category"), fallback="web")


def _article_format(artifact: Artifact) -> str:
    return _normalize_article_format(getattr(artifact, "format", None), fallback="standard")


def _derive_guide_category(tags: list[str]) -> str:
    normalized = {str(tag).strip().lower() for tag in tags if str(tag).strip()}
    if "core-concepts" in normalized:
        return "core-concepts"
    if "tutorial" in normalized:
        return "tutorial"
    return "guide"


def _is_valid_binding_target(target_type: str, target_value: str) -> bool:
    if target_type not in PUBLISH_BINDING_TARGET_TYPES:
        return False
    value = str(target_value or "").strip()
    if not value:
        return False
    if target_type in {"xyn_ui_route", "public_web_path"}:
        return value.startswith("/")
    if target_type == "external_url":
        return value.startswith("http://") or value.startswith("https://")
    return False


def _resolve_article_published_to(artifact: Artifact) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    category = _article_category_record(artifact)
    if category:
        for binding in PublishBinding.objects.filter(scope_type="category", scope_id=category.id, enabled=True).order_by("label", "target_value"):
            key = (binding.label, binding.target_type, binding.target_value)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "label": binding.label,
                    "target_type": binding.target_type,
                    "target_value": binding.target_value,
                    "source": "category",
                }
            )
    for binding in PublishBinding.objects.filter(scope_type="article", scope_id=artifact.id, enabled=True).order_by("label", "target_value"):
        key = (binding.label, binding.target_type, binding.target_value)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "label": binding.label,
                "target_type": binding.target_type,
                "target_value": binding.target_value,
                "source": "article",
            }
        )
    # Compatibility fallback for pre-binding route metadata.
    if not rows:
        scope = dict(artifact.scope_json or {})
        for value in _normalize_doc_route_bindings(scope.get("route_bindings")):
            key = ("Route", "xyn_ui_route", value)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"label": "Route", "target_type": "xyn_ui_route", "target_value": value, "source": "article"})
    return rows


def _article_route_bindings(artifact: Artifact) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for row in _resolve_article_published_to(artifact):
        if row.get("target_type") != "xyn_ui_route":
            continue
        value = str(row.get("target_value") or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        values.append(value)
    return values


def _article_content(artifact: Artifact, revision: Optional[ArtifactRevision] = None) -> Dict[str, Any]:
    latest = revision or _latest_artifact_revision(artifact)
    content = dict((latest.content_json if latest else {}) or {})
    scope = dict(artifact.scope_json or {})
    tags = _normalize_doc_tags(content.get("tags") if "tags" in content else scope.get("tags"))
    summary = str(content.get("summary") or scope.get("summary") or "")
    body_markdown = str(content.get("body_markdown") or "")
    body_html = str(content.get("body_html") or "")
    return {
        "title": str(content.get("title") or artifact.title),
        "summary": summary,
        "body_markdown": body_markdown,
        "body_html": body_html,
        "tags": tags,
        "latest_revision": latest,
    }


def _default_video_spec_for_artifact(artifact: Artifact, revision: Optional[ArtifactRevision] = None) -> Dict[str, Any]:
    content = _article_content(artifact, revision)
    if artifact.format == "video_explainer":
        spec, _ = _build_explainer_video_spec(
            title=str(content.get("title") or artifact.title),
            summary=str(content.get("summary") or ""),
            intent=str(content.get("summary") or artifact.title),
            description=str(content.get("body_markdown") or content.get("summary") or ""),
        )
        return spec
    return default_video_spec(title=str(content.get("title") or artifact.title), summary=str(content.get("summary") or ""))


def _video_spec(artifact: Artifact, revision: Optional[ArtifactRevision] = None) -> Dict[str, Any]:
    if isinstance(artifact.video_spec_json, dict):
        return dict(artifact.video_spec_json)
    return _default_video_spec_for_artifact(artifact, revision)


def _minutes_to_seconds(value: str) -> Optional[int]:
    raw = str(value or "").strip().lower()
    match = re.fullmatch(r"([0-9]{1,2})m", raw)
    if not match:
        return None
    return max(30, int(match.group(1)) * 60)


_INSTRUCTIONY_PREFIX_RE = re.compile(
    r"^\s*(intent\s*:\s*)?(create|write|make|generate|draft)\b",
    re.IGNORECASE,
)


def _looks_like_instruction_text(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if _INSTRUCTIONY_PREFIX_RE.search(text):
        return True
    lowered = text.lower()
    return "the title is" in lowered or "create it in the" in lowered or "ground it in" in lowered


def _extract_explainer_generation_fields(
    *,
    title: str,
    intent: str,
    summary: str,
    description: str,
    audience: str,
    category: str,
) -> Dict[str, str]:
    source = " ".join([str(intent or ""), str(description or ""), str(summary or "")]).strip()
    lowered_source = source.lower()
    extracted_topic = ""
    extracted_grounding = ""
    extracted_audience = str(audience or "").strip()

    about_match = re.search(r"\babout\s+(.+?)(?:[.;]|$)", source, re.IGNORECASE)
    if about_match:
        extracted_topic = re.sub(r"\s+", " ", about_match.group(1)).strip(" \"'")

    if not extracted_audience:
        audience_match = re.search(r"\bfor\s+(.+?)(?:[.;]|$)", source, re.IGNORECASE)
        if audience_match:
            extracted_audience = re.sub(r"\s+", " ", audience_match.group(1)).strip(" \"'")

    grounding_match = re.search(r"\bground(?:ed)?\s+(?:it\s+)?in\s+(.+?)(?:[.;]|$)", source, re.IGNORECASE)
    if grounding_match:
        extracted_grounding = re.sub(r"\s+", " ", grounding_match.group(1)).strip(" \"'")

    if not extracted_topic:
        if _looks_like_instruction_text(source):
            extracted_topic = str(title or "").strip()
        else:
            extracted_topic = source
    if not extracted_topic:
        extracted_topic = str(title or "Explainer Video").strip() or "Explainer Video"

    clean_topic = extracted_topic
    for marker in ["the title is", "create it in the", "category:", "intent:"]:
        marker_index = clean_topic.lower().find(marker)
        if marker_index > 0:
            clean_topic = clean_topic[:marker_index]
    clean_topic = re.sub(r"\s+", " ", clean_topic).strip(" \"'.")
    if not clean_topic:
        clean_topic = str(title or "Explainer Video").strip() or "Explainer Video"

    normalized_category = str(category or "").strip().lower()
    if not extracted_grounding and "biology" in lowered_source and "salamander" in clean_topic.lower():
        extracted_grounding = "actual biology"

    return {
        "title": str(title or "").strip(),
        "topic": clean_topic,
        "grounding": str(extracted_grounding or "").strip(),
        "category": normalized_category,
        "audience": str(extracted_audience or "").strip(),
    }


def _storyboard_from_scenes(scenes: List[Dict[str, Any]], *, duration_seconds_target: int) -> List[Dict[str, Any]]:
    if not scenes:
        return []
    per_scene = max(8, int(duration_seconds_target / max(len(scenes), 1)))
    rows: List[Dict[str, Any]] = []
    start_seconds = 0
    for index, scene in enumerate(scenes, start=1):
        end_seconds = start_seconds + per_scene
        title = str(scene.get("title") or f"Scene {index}")
        rows.append(
            {
                "scene": index,
                "time_range": f"{start_seconds // 60}:{start_seconds % 60:02d}-{end_seconds // 60}:{end_seconds % 60:02d}",
                "on_screen_text": str(scene.get("on_screen") or "")[:120] or title[:120],
                "visual_description": title[:200],
                "motion": "subtle camera move",
                "assets": [],
                "narration": str(scene.get("voiceover") or title),
            }
        )
        start_seconds = end_seconds
    return rows


def _parse_scene_scaffold_response(content: str) -> Optional[List[Dict[str, Any]]]:
    try:
        parsed = json.loads(_strip_code_fence(content))
    except Exception:
        return None
    rows = parsed.get("scenes") if isinstance(parsed, dict) and isinstance(parsed.get("scenes"), list) else None
    if not rows:
        return None
    normalized: List[Dict[str, Any]] = []
    for idx, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        normalized.append(normalize_video_scene(row, index=idx))
    if len(normalized) < 3:
        return None
    return normalized[:7]


def _generate_explainer_scene_scaffold(
    *,
    title: str,
    topic: str,
    grounding: str = "",
    category: str = "",
    audience: str = "",
    description: str = "",
) -> Tuple[List[Dict[str, Any]], str]:
    base_title = str(title or "Explainer Video").strip() or "Explainer Video"
    base_topic = str(topic or base_title).strip() or base_title
    base_audience = str(audience or "").strip()
    base_description = str(description or "").strip()
    default_count = 5 if len(base_description) < 2500 else 6
    scene_count = max(3, min(default_count, 7))
    plan_rows = deterministic_scene_scaffold(
        title=base_title,
        topic=base_topic,
        audience=base_audience,
        description=base_description,
        scene_count=scene_count,
    )
    plan = [
        {
            "id": row["id"],
            "title": row["title"],
            "purpose": "Populate with grounded content from title/topic/description only.",
            "on_screen_hint": row["on_screen"],
        }
        for row in plan_rows
    ]
    payload = {
        "title": base_title,
        "topic": base_topic,
        "grounding": str(grounding or "").strip(),
        "category": str(category or "").strip(),
        "audience": base_audience,
        "description": base_description,
        "scene_plan": plan,
        "constraints": [
            "Use only title/topic/grounding/category/audience/description.",
            "Do not mention routes, ids, lifecycle state, validation, hash, owner, schema, lineage, timestamps.",
            "Do not repeat or summarize the instruction itself.",
            "Do not use placeholder titles like Hook / Premise or Setup / Context.",
            "Return strict JSON only.",
        ],
        "output_schema": {"scenes": [{"id": "s1", "title": "string", "voiceover": "string", "on_screen": "string"}]},
    }
    try:
        try:
            resolved = resolve_ai_config(purpose_slug="explainer_storyboard")
        except AiConfigError:
            resolved = resolve_ai_config(purpose_slug="documentation")
        response = invoke_model(
            resolved_config=resolved,
            messages=[
                {"role": "system", "content": "Return strict JSON only."},
                {
                    "role": "developer",
                    "content": (
                        "You are generating a scene-based explainer video about the provided topic. "
                        "Do NOT repeat or summarize the instruction. Interpret the topic and produce original content. "
                        "Do NOT reference the existence of an instruction. Fill the scene plan in order. "
                        "Every line must be grounded in supplied topic data. "
                        "For biology topics, include concrete biological details."
                    ),
                },
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
        )
        scenes = _parse_scene_scaffold_response(str(response.get("content") or ""))
        if scenes:
            return scenes, "model"
        repaired = invoke_model(
            resolved_config=resolved,
            messages=[
                {"role": "system", "content": "Repair previous output and return strict JSON only."},
                {"role": "developer", "content": "Return {\"scenes\": [...]} and no prose."},
                {
                    "role": "user",
                    "content": json.dumps(
                        {"payload": payload, "invalid_output": str(response.get("content") or "")},
                        ensure_ascii=False,
                    ),
                },
            ],
        )
        scenes = _parse_scene_scaffold_response(str(repaired.get("content") or ""))
        if scenes:
            return scenes, "model_repair"
    except Exception:
        pass
    return plan_rows, "fallback"


def _build_explainer_video_spec(
    *,
    title: str,
    summary: str,
    intent: str = "",
    topic: str = "",
    grounding: str = "",
    category: str = "",
    duration: str = "",
    audience: str = "",
    description: str = "",
    existing_scenes: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Dict[str, Any], str]:
    quality = "provided"
    if existing_scenes and len(existing_scenes) >= 3:
        scenes = [normalize_video_scene(item, index=idx) for idx, item in enumerate(existing_scenes, start=1)]
    else:
        scenes, quality = _generate_explainer_scene_scaffold(
            title=title,
            topic=topic or intent or title,
            grounding=grounding,
            category=category,
            audience=audience,
            description=description or summary,
        )
    spec = default_video_spec(title=title, summary=summary, scenes=scenes)
    intent_base = str(intent or topic or summary or title).strip()
    if grounding:
        intent_base = f"{intent_base}. Grounding: {str(grounding).strip()}".strip(". ")
    spec["intent"] = intent_base
    if duration:
        spec["duration"] = duration
        seconds = _minutes_to_seconds(duration)
        if seconds:
            spec["duration_seconds_target"] = seconds
    duration_seconds_target = int(spec.get("duration_seconds_target") or 150)
    spec["script"] = {
        **(spec.get("script") if isinstance(spec.get("script"), dict) else {}),
        "draft": "\n\n".join([str(scene.get("voiceover") or "").strip() for scene in scenes if str(scene.get("voiceover") or "").strip()]),
    }
    spec["storyboard"] = {
        **(spec.get("storyboard") if isinstance(spec.get("storyboard"), dict) else {}),
        "draft": _storyboard_from_scenes(scenes, duration_seconds_target=duration_seconds_target),
    }
    return spec, quality


def _derive_explainer_initial_content(
    *,
    title: str,
    summary: str,
    body_markdown: str,
    scenes: List[Dict[str, Any]],
) -> Tuple[str, str]:
    normalized_summary = str(summary or "").strip()
    normalized_body = str(body_markdown or "").strip()
    if _looks_like_instruction_text(normalized_summary):
        normalized_summary = ""
    if _looks_like_instruction_text(normalized_body):
        normalized_body = ""
    if normalized_summary and normalized_body:
        return normalized_summary, normalized_body
    fallback_lines = [str(scene.get("voiceover") or "").strip() for scene in (scenes or []) if str(scene.get("voiceover") or "").strip()]
    if not normalized_summary:
        normalized_summary = fallback_lines[0] if fallback_lines else f"Explainer draft for {str(title or 'this topic').strip() or 'this topic'}."
    if not normalized_body:
        normalized_body = "\n\n".join(fallback_lines) if fallback_lines else normalized_summary
    return normalized_summary, normalized_body


def _normalize_pack_markdown(value: str) -> str:
    return re.sub(r"\r\n?", "\n", str(value or "")).strip()


def _context_pack_content_hash(pack: ContextPack) -> str:
    normalized = _normalize_pack_markdown(pack.content_markdown)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest() if normalized else ""


def _serialize_video_context_pack(pack: Optional[ContextPack]) -> Optional[Dict[str, Any]]:
    if not pack:
        return None
    return {
        "id": str(pack.id),
        "name": pack.name,
        "purpose": pack.purpose,
        "scope": pack.scope,
        "version": pack.version,
        "updated_at": pack.updated_at.isoformat() if pack.updated_at else None,
        "content_hash": _context_pack_content_hash(pack),
    }


def _resolve_video_context_pack_for_article(
    artifact: Optional[Artifact],
    raw_pack_id: Any,
    *,
    allow_clear: bool = True,
) -> tuple[Optional[ContextPack], Optional[JsonResponse]]:
    def _default_video_context_pack() -> Optional[ContextPack]:
        preferred = (
            ContextPack.objects.filter(
                name="explainer-video-default",
                purpose=VIDEO_CONTEXT_PACK_PURPOSE,
                is_active=True,
            )
            .order_by("-updated_at")
            .first()
        )
        if preferred:
            return preferred
        if ContextPack.objects.filter(
            name="explainer-video-default",
            purpose=VIDEO_CONTEXT_PACK_PURPOSE,
            is_active=False,
        ).exists():
            logging.getLogger(__name__).warning(
                "explainer-video-default context pack exists but is inactive; skipping auto-bind"
            )
        return (
            ContextPack.objects.filter(purpose=VIDEO_CONTEXT_PACK_PURPOSE, is_active=True, is_default=True)
            .order_by("-updated_at")
            .first()
        )

    if raw_pack_id is None:
        if artifact and artifact.video_context_pack_id:
            attached = ContextPack.objects.filter(id=artifact.video_context_pack_id).first()
            if attached and attached.purpose != VIDEO_CONTEXT_PACK_PURPOSE:
                return None, JsonResponse({"error": f"context pack purpose must be {VIDEO_CONTEXT_PACK_PURPOSE}"}, status=400)
            return attached, None
        return _default_video_context_pack(), None
    pack_id = str(raw_pack_id or "").strip()
    if not pack_id:
        if allow_clear:
            return None, None
        if artifact and artifact.video_context_pack_id:
            return ContextPack.objects.filter(id=artifact.video_context_pack_id).first(), None
        return None, None
    pack = ContextPack.objects.filter(id=pack_id).first()
    if not pack:
        return None, JsonResponse({"error": "context pack not found"}, status=404)
    if pack.purpose != VIDEO_CONTEXT_PACK_PURPOSE:
        return None, JsonResponse({"error": f"context pack purpose must be {VIDEO_CONTEXT_PACK_PURPOSE}"}, status=400)
    return pack, None


def _video_context_prompt(pack: Optional[ContextPack]) -> str:
    if not pack:
        return ""
    return f"### Context Pack: {pack.name} (v{pack.version})\n{_normalize_pack_markdown(pack.content_markdown)}".strip()


def _video_context_metadata(pack: Optional[ContextPack]) -> Dict[str, Any]:
    if not pack:
        return {}
    return {
        "id": str(pack.id),
        "name": pack.name,
        "purpose": pack.purpose,
        "scope": pack.scope,
        "version": pack.version,
        "updated_at": pack.updated_at.isoformat() if pack.updated_at else None,
        "hash": _context_pack_content_hash(pack),
    }


def _article_video_ai_config(artifact: Artifact) -> Dict[str, Any]:
    raw = artifact.video_ai_config_json if isinstance(artifact.video_ai_config_json, dict) else {}
    agents = raw.get("agents") if isinstance(raw.get("agents"), dict) else {}
    raw_context = raw.get("context_packs") if isinstance(raw.get("context_packs"), dict) else {}
    normalized_context: Dict[str, Dict[str, Any]] = {}
    for purpose_slug, entry in raw_context.items():
        if purpose_slug not in EXPLAINER_PURPOSES:
            continue
        if isinstance(entry, dict):
            mode = str(entry.get("mode") or entry.get("override_mode") or "extend").strip().lower()
            if mode not in {"extend", "replace"}:
                mode = "extend"
            refs = entry.get("context_pack_refs")
            if refs is None:
                refs = entry.get("refs")
            if refs is None:
                refs = entry.get("context_packs")
            if refs is None:
                refs = entry.get("packs")
            refs = refs if isinstance(refs, list) else []
            normalized_context[purpose_slug] = {"mode": mode, "context_pack_refs": refs}
            continue
        # Backward compatibility: legacy list-only overrides imply replace behavior.
        refs = entry if isinstance(entry, list) else ([entry] if entry else [])
        normalized_context[purpose_slug] = {"mode": "replace", "context_pack_refs": refs}
    return {"agents": agents, "context_packs": normalized_context}


def _resolve_agent_value(value: Any) -> Optional[AgentDefinition]:
    raw = str(value or "").strip()
    if not raw:
        return None
    by_slug = AgentDefinition.objects.select_related("model_config__provider").filter(slug=raw, enabled=True).first()
    if by_slug:
        return by_slug
    try:
        return AgentDefinition.objects.select_related("model_config__provider").filter(id=raw, enabled=True).first()
    except (ValidationError, ValueError):
        return None


def _is_agent_linked_to_purpose(agent: AgentDefinition, purpose_slug: str) -> bool:
    return AgentDefinitionPurpose.objects.filter(agent_definition_id=agent.id, purpose__slug=purpose_slug).exists()


def _resolve_agent_for_purpose(
    artifact: Artifact,
    purpose_slug: str,
    explicit_override: Any = None,
) -> Tuple[Optional[AgentDefinition], str, Optional[str]]:
    if purpose_slug not in EXPLAINER_PURPOSES:
        return None, "fallback", f"unknown purpose: {purpose_slug}"
    if explicit_override is not None:
        explicit_agent = _resolve_agent_value(explicit_override)
        if not explicit_agent:
            return None, "override", "override agent not found or disabled"
        if not _is_agent_linked_to_purpose(explicit_agent, purpose_slug):
            return None, "override", "override agent is not linked to purpose"
        return explicit_agent, "override", None

    config = _article_video_ai_config(artifact)
    override_value = config["agents"].get(purpose_slug)
    if override_value is not None:
        override_agent = _resolve_agent_value(override_value)
        if override_agent and _is_agent_linked_to_purpose(override_agent, purpose_slug):
            return override_agent, "override", None
        return None, "override", "configured override agent is invalid"

    link_default = (
        AgentDefinitionPurpose.objects.select_related("agent_definition", "agent_definition__model_config__provider")
        .filter(purpose__slug=purpose_slug, is_default_for_purpose=True, agent_definition__enabled=True)
        .order_by("agent_definition__name", "agent_definition__slug")
        .first()
    )
    if link_default:
        return link_default.agent_definition, "purpose_default", None

    fallback = (
        AgentDefinition.objects.select_related("model_config__provider")
        .filter(enabled=True, purposes__slug=purpose_slug)
        .order_by("-updated_at", "name", "slug")
        .first()
    )
    if fallback:
        logger.warning("No purpose default configured for %s; using fallback agent %s", purpose_slug, fallback.slug)
        return fallback, "fallback", None
    return None, "fallback", f"no enabled agent linked to purpose {purpose_slug}"


def _resolve_context_pack_ref(ref: Any) -> Optional[ContextPack]:
    if isinstance(ref, dict):
        for key in ("id", "context_pack_id"):
            value = str(ref.get(key) or "").strip()
            if value:
                row = ContextPack.objects.filter(id=value).order_by("-is_active", "-updated_at").first()
                if row:
                    return row
        for key in ("slug", "name"):
            value = str(ref.get(key) or "").strip()
            if value:
                row = ContextPack.objects.filter(name=value).order_by("-is_active", "-updated_at").first()
                if row:
                    return row
        return None
    raw = str(ref or "").strip()
    if not raw:
        return None
    by_id = ContextPack.objects.filter(id=raw).order_by("-is_active", "-updated_at").first()
    if by_id:
        return by_id
    return ContextPack.objects.filter(name=raw).order_by("-is_active", "-updated_at").first()


def _validate_pack_purpose_for_explainer(pack: ContextPack, purpose_slug: str) -> bool:
    return pack.purpose in {purpose_slug, "any", VIDEO_CONTEXT_PACK_PURPOSE}


def _normalize_pack_refs_input(raw: Any) -> List[Any]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    return [raw]


def _resolve_context_packs_for_purpose(
    artifact: Artifact,
    purpose_slug: str,
    agent: Optional[AgentDefinition],
    *,
    explicit_override: Any = None,
) -> Tuple[List[ContextPack], str, str, Optional[str], str, List[Dict[str, Any]]]:
    config = _article_video_ai_config(artifact)
    override_present = explicit_override is not None or purpose_slug in config["context_packs"]
    raw_override = explicit_override if explicit_override is not None else config["context_packs"].get(purpose_slug)
    override_mode = "extend"

    def _resolve_many(raw_refs: Any) -> Tuple[List[ContextPack], Optional[str]]:
        rows: List[ContextPack] = []
        seen: set[str] = set()
        for ref in _normalize_pack_refs_input(raw_refs):
            pack = _resolve_context_pack_ref(ref)
            if not pack:
                return [], "context pack ref not found"
            if not _validate_pack_purpose_for_explainer(pack, purpose_slug):
                return [], f"context pack '{pack.name}' purpose '{pack.purpose}' does not match {purpose_slug}"
            key = str(pack.id)
            if key in seen:
                continue
            seen.add(key)
            rows.append(pack)
        return rows, None

    def _dedupe(rows: List[ContextPack]) -> List[ContextPack]:
        deduped: List[ContextPack] = []
        seen: set[str] = set()
        for row in rows:
            key = str(row.id)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(row)
        return deduped

    default_rows: List[ContextPack] = []
    if agent and isinstance(agent.context_pack_refs_json, list):
        default_rows, default_err = _resolve_many(agent.context_pack_refs_json)
        if default_err:
            return [], "agent_default", "", default_err, "extend", []

    if override_present:
        override_refs = raw_override
        if isinstance(raw_override, dict):
            mode_value = str(raw_override.get("mode") or raw_override.get("override_mode") or "extend").strip().lower()
            if mode_value not in {"extend", "replace"}:
                return [], "override", "", "context pack override mode must be 'extend' or 'replace'", "extend", []
            override_mode = mode_value
            override_refs = raw_override.get("context_pack_refs")
            if override_refs is None:
                override_refs = raw_override.get("refs")
            if override_refs is None:
                override_refs = raw_override.get("context_packs")
            if override_refs is None:
                override_refs = raw_override.get("packs")
        rows, err = _resolve_many(override_refs)
        if err:
            return [], "override", "", err, override_mode, []
        if override_mode == "replace":
            merged_rows = _dedupe(rows)
        else:
            merged_rows = _dedupe(default_rows + rows)
        resolved = _resolve_context_pack_list(merged_rows)
        refs_with_source: List[Dict[str, Any]] = []
        override_ids = {str(item.id) for item in rows}
        for ref in resolved.get("refs", []):
            source = "override" if str(ref.get("id") or "") in override_ids else "agent_default"
            refs_with_source.append({**ref, "source": source})
        return merged_rows, "override", resolved.get("hash", ""), None, override_mode, refs_with_source

    resolved = _resolve_context_pack_list(default_rows)
    refs_with_source = [{**ref, "source": "agent_default"} for ref in resolved.get("refs", [])]
    return default_rows, "agent_default", resolved.get("hash", ""), None, "extend", refs_with_source


def _effective_video_ai_config(artifact: Artifact) -> Dict[str, Any]:
    effective: Dict[str, Any] = {}
    for purpose_slug, meta in EXPLAINER_PURPOSES.items():
        agent, agent_source, agent_error = _resolve_agent_for_purpose(artifact, purpose_slug)
        packs: List[ContextPack] = []
        pack_source = "fallback"
        pack_hash = ""
        pack_error: Optional[str] = None
        override_mode = "extend"
        pack_refs_with_source: List[Dict[str, Any]] = []
        if agent:
            packs, pack_source, pack_hash, pack_error, override_mode, pack_refs_with_source = _resolve_context_packs_for_purpose(
                artifact,
                purpose_slug,
                agent,
            )
        deprecated_packs = [pack.name for pack in packs if not pack.is_active]
        warnings: List[str] = []
        if agent_error:
            warnings.append(agent_error)
        if pack_error:
            warnings.append(pack_error)
        if deprecated_packs:
            warnings.append(f"deprecated context packs in use: {', '.join(sorted(set(deprecated_packs)))}")
        effective[purpose_slug] = {
            "purpose_slug": purpose_slug,
            "purpose_name": meta["name"],
            "description": meta["description"],
            "agent": (
                {
                    "id": str(agent.id),
                    "slug": agent.slug,
                    "name": agent.name,
                    "model_provider": agent.model_config.provider.slug if agent.model_config_id else None,
                    "model_name": agent.model_config.model_name if agent.model_config_id else None,
                    "model_config_id": str(agent.model_config_id) if agent.model_config_id else None,
                }
                if agent
                else None
            ),
            "context_packs": [_serialize_video_context_pack(pack) for pack in packs],
            "context_pack_hash": pack_hash,
            "effective_model_config_id": str(agent.model_config_id) if agent and agent.model_config_id else None,
            "effective_context_pack_refs": pack_refs_with_source,
            "context_pack_override_mode": override_mode,
            "source": "override" if agent_source == "override" or pack_source == "override" else (agent_source if agent_source != "fallback" else pack_source),
            "agent_source": agent_source,
            "context_source": pack_source,
            "warning": " | ".join(warnings) if warnings else None,
        }
    return effective


def _normalize_context_pack_override_refs(purpose_slug: str, raw_value: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    refs: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for raw_ref in _normalize_pack_refs_input(raw_value):
        pack = _resolve_context_pack_ref(raw_ref)
        if not pack:
            return [], "context pack ref not found"
        if not _validate_pack_purpose_for_explainer(pack, purpose_slug):
            return [], f"context pack '{pack.name}' purpose '{pack.purpose}' does not match {purpose_slug}"
        key = str(pack.id)
        if key in seen:
            continue
        seen.add(key)
        refs.append(
            {
                "id": str(pack.id),
                "name": pack.name,
                "purpose": pack.purpose,
                "scope": pack.scope,
                "version": pack.version,
            }
        )
    return refs, None

def _normalized_json_hash(value: Any) -> str:
    try:
        encoded = json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except TypeError:
        encoded = json.dumps(str(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _video_input_snapshot_hash(spec_hash: str, context_hash: str, provider: str, model_name: str) -> str:
    payload = {
        "spec_hash": spec_hash,
        "context_pack_hash": context_hash,
        "provider": provider,
        "model_name": model_name,
    }
    return _normalized_json_hash(payload)


def _serialize_video_render(render: VideoRender) -> Dict[str, Any]:
    return {
        "id": str(render.id),
        "article_id": str(render.article_id),
        "provider": render.provider,
        "model_name": render.model_name or "",
        "status": render.status,
        "requested_at": render.requested_at.isoformat() if render.requested_at else None,
        "started_at": render.started_at.isoformat() if render.started_at else None,
        "completed_at": render.completed_at.isoformat() if render.completed_at else None,
        "request_payload_json": sanitize_payload(render.request_payload_json or {}),
        "result_payload_json": sanitize_payload(render.result_payload_json or {}),
        "output_assets": render.output_assets or [],
        "context_pack_id": str(render.context_pack_id) if render.context_pack_id else None,
        "context_pack_name": render.context_pack.name if getattr(render, "context_pack", None) else None,
        "context_pack_version": render.context_pack_version or "",
        "context_pack_updated_at": render.context_pack_updated_at.isoformat() if render.context_pack_updated_at else None,
        "context_pack_hash": render.context_pack_hash or "",
        "spec_snapshot_hash": render.spec_snapshot_hash or "",
        "input_snapshot_hash": render.input_snapshot_hash or "",
        "error_message": render.error_message or "",
        "error_details_json": sanitize_payload(render.error_details_json or {}),
    }


def _convert_article_html_to_markdown(value: str) -> str:
    source = str(value or "").strip()
    if not source:
        return ""
    converted = _markdownify_html(source, heading_style="ATX", bullets="-")
    return str(converted or "").strip()


def _can_manage_articles(identity: UserIdentity) -> bool:
    return _has_platform_role(identity, ["platform_architect", "platform_admin"])


def _can_edit_article(identity: UserIdentity, artifact: Artifact) -> bool:
    if _can_manage_articles(identity):
        return True
    if artifact.status != "draft":
        return False
    return artifact.author_id and str(artifact.author_id) == str(identity.id)


def _can_view_article(identity: UserIdentity, artifact: Artifact) -> bool:
    if _can_manage_articles(identity):
        return True
    if artifact.status != "published":
        return bool(artifact.author_id and str(artifact.author_id) == str(identity.id))
    visibility_type = _article_visibility_type_from_artifact(artifact)
    if visibility_type == "public":
        return True
    if visibility_type == "authenticated":
        return identity is not None
    if visibility_type == "private":
        return bool(artifact.author_id and str(artifact.author_id) == str(identity.id))
    allowed = set(_article_allowed_roles(artifact))
    if not allowed:
        return False
    user_roles = set(_get_roles(identity))
    return bool(user_roles.intersection(allowed))


def _serialize_article_summary(artifact: Artifact, revision: Optional[ArtifactRevision] = None) -> Dict[str, Any]:
    content = _article_content(artifact, revision)
    category_ref = _serialize_article_category_ref(artifact)
    return {
        "id": str(artifact.id),
        "workspace_id": str(artifact.workspace_id),
        "type": artifact.type.slug,
        "format": _article_format(artifact),
        "video_context_pack_id": str(artifact.video_context_pack_id) if artifact.video_context_pack_id else None,
        "title": artifact.title,
        "slug": _artifact_slug(artifact),
        "status": artifact.status,
        "version": artifact.version,
        "published_at": artifact.published_at,
        "updated_at": artifact.updated_at,
        "category": category_ref.get("slug"),
        "category_name": category_ref.get("name"),
        "category_id": category_ref.get("id"),
        "visibility_type": _article_visibility_type_from_artifact(artifact),
        "allowed_roles": _article_allowed_roles(artifact),
        "route_bindings": _article_route_bindings(artifact),
        "tags": content.get("tags") or [],
        "summary": content.get("summary") or "",
        "cover_image_url": str((artifact.scope_json or {}).get("cover_image_url") or ""),
        "canonical_url": str((artifact.scope_json or {}).get("canonical_url") or ""),
    }


def _serialize_article_detail(artifact: Artifact, revision: Optional[ArtifactRevision] = None) -> Dict[str, Any]:
    latest = revision or _latest_artifact_revision(artifact)
    content = _article_content(artifact, latest)
    payload = _serialize_article_summary(artifact, latest)
    reaction_counts = {"endorse": 0, "oppose": 0, "neutral": 0}
    for row in ArtifactReaction.objects.filter(artifact=artifact).values("value").annotate(count=models.Count("id")):
        reaction_counts[str(row["value"])] = int(row["count"])
    comments = ArtifactComment.objects.filter(artifact=artifact).order_by("created_at")
    payload.update(
        {
            "body_markdown": content.get("body_markdown") or "",
            "body_html": content.get("body_html") or "",
            "format": _article_format(artifact),
            "video_spec_json": _video_spec(artifact, latest),
            "video_ai_config_json": _article_video_ai_config(artifact),
            "video_context_pack_id": str(artifact.video_context_pack_id) if artifact.video_context_pack_id else None,
            "video_context_pack": _serialize_video_context_pack(getattr(artifact, "video_context_pack", None)),
            "video_latest_render_id": str(artifact.video_latest_render_id) if artifact.video_latest_render_id else None,
            "provenance_json": artifact.provenance_json or {},
            "license_json": (artifact.scope_json or {}).get("license_json") or {},
            "category_ref": _serialize_article_category_ref(artifact),
            "published_to": _resolve_article_published_to(artifact),
            "reactions": reaction_counts,
            "comments": [_serialize_comment(comment) for comment in comments],
            "created_at": artifact.created_at,
            "created_by": str(artifact.author_id) if artifact.author_id else None,
            "updated_by": str(latest.created_by_id) if latest and latest.created_by_id else None,
            "updated_by_email": latest.created_by.email if latest and latest.created_by else None,
        }
    )
    return payload


def _normalize_workflow_profile(raw: Any, *, fallback: str = "tour") -> str:
    value = str(raw or "").strip().lower()
    return value if value in WORKFLOW_PROFILE_TYPES else fallback


def _normalize_workflow_spec(spec: Dict[str, Any], *, profile: str, title: str, category_slug: str) -> Dict[str, Any]:
    steps = spec.get("steps") if isinstance(spec.get("steps"), list) else []
    normalized_steps: List[Dict[str, Any]] = []
    for idx, raw_step in enumerate(steps):
        if not isinstance(raw_step, dict):
            continue
        step_id = str(raw_step.get("id") or f"step-{idx+1}").strip()
        if not step_id:
            step_id = f"step-{idx+1}"
        normalized_steps.append(
            {
                "id": step_id,
                "title": str(raw_step.get("title") or step_id).strip(),
                "body_md": str(raw_step.get("body_md") or "").strip(),
                "type": str(raw_step.get("type") or "callout").strip().lower(),
                "route": str(raw_step.get("route") or "").strip(),
                "anchor": raw_step.get("anchor") if isinstance(raw_step.get("anchor"), dict) else {},
                "gating": raw_step.get("gating") if isinstance(raw_step.get("gating"), dict) else {},
                "next": raw_step.get("next") if isinstance(raw_step.get("next"), dict) else {},
                "ui": raw_step.get("ui") if isinstance(raw_step.get("ui"), dict) else {},
                "clipboard_text": str(raw_step.get("clipboard_text") or "").strip(),
                "toast_on_copy": str(raw_step.get("toast_on_copy") or "").strip(),
                "action_id": str(raw_step.get("action_id") or "").strip(),
                "params": raw_step.get("params") if isinstance(raw_step.get("params"), dict) else {},
                "success_toast": str(raw_step.get("success_toast") or "").strip(),
            }
        )
    settings = spec.get("settings") if isinstance(spec.get("settings"), dict) else {}
    return {
        "profile": profile,
        "schema_version": int(spec.get("schema_version") or WORKFLOW_SCHEMA_VERSION),
        "title": str(spec.get("title") or title).strip(),
        "description": str(spec.get("description") or "").strip(),
        "category_slug": str(spec.get("category_slug") or category_slug).strip().lower() or category_slug,
        "entry": spec.get("entry") if isinstance(spec.get("entry"), dict) else {},
        "steps": normalized_steps,
        "settings": {
            "allow_skip": bool(settings.get("allow_skip", True)),
            "show_progress": bool(settings.get("show_progress", True)),
        },
    }


def _validate_workflow_spec(spec: Any, *, profile: str) -> List[str]:
    errors: List[str] = []
    if not isinstance(spec, dict):
        return ["workflow_spec_json must be an object"]
    if str(spec.get("profile") or profile).strip().lower() != profile:
        errors.append(f"profile must be '{profile}'")
    steps = spec.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("steps must be a non-empty array")
        return errors
    seen_ids: Set[str] = set()
    valid_step_types = {"callout", "modal", "check", "action", "copy"}
    valid_placements = {"top", "right", "bottom", "left"}
    valid_check_kinds = {"entity_exists", "field_nonempty", "route_is"}
    for idx, step in enumerate(steps):
        path = f"steps[{idx}]"
        if not isinstance(step, dict):
            errors.append(f"{path} must be an object")
            continue
        step_id = str(step.get("id") or "").strip()
        if not step_id:
            errors.append(f"{path}.id is required")
        elif step_id in seen_ids:
            errors.append(f"{path}.id must be unique")
        else:
            seen_ids.add(step_id)
        step_type = str(step.get("type") or "").strip().lower()
        if step_type not in valid_step_types:
            errors.append(f"{path}.type must be one of {', '.join(sorted(valid_step_types))}")
        title = str(step.get("title") or "").strip()
        if not title:
            errors.append(f"{path}.title is required")
        anchor = step.get("anchor")
        if anchor is not None and not isinstance(anchor, dict):
            errors.append(f"{path}.anchor must be an object")
        elif isinstance(anchor, dict):
            anchor_refs = [str(anchor.get("selector") or "").strip(), str(anchor.get("test_id") or "").strip(), str(anchor.get("anchor_id") or "").strip()]
            if any(anchor_refs):
                pass
            placement = str(anchor.get("placement") or "").strip().lower()
            if placement and placement not in valid_placements:
                errors.append(f"{path}.anchor.placement is invalid")
        if step_type == "copy" and not str(step.get("clipboard_text") or "").strip():
            errors.append(f"{path}.clipboard_text is required for copy step")
        if step_type == "action":
            if not str(step.get("action_id") or "").strip():
                errors.append(f"{path}.action_id is required for action step")
            params = step.get("params")
            if params is not None and not isinstance(params, dict):
                errors.append(f"{path}.params must be an object")
        gating = step.get("gating")
        if gating is not None:
            if not isinstance(gating, dict):
                errors.append(f"{path}.gating must be an object")
            else:
                requires = gating.get("requires")
                if requires is not None:
                    if not isinstance(requires, list):
                        errors.append(f"{path}.gating.requires must be an array")
                    else:
                        for ridx, check in enumerate(requires):
                            cpath = f"{path}.gating.requires[{ridx}]"
                            if not isinstance(check, dict):
                                errors.append(f"{cpath} must be an object")
                                continue
                            if not str(check.get("id") or "").strip():
                                errors.append(f"{cpath}.id is required")
                            kind = str(check.get("kind") or "").strip().lower()
                            if kind not in valid_check_kinds:
                                errors.append(f"{cpath}.kind must be one of {', '.join(sorted(valid_check_kinds))}")
                            params = check.get("params")
                            if params is not None and not isinstance(params, dict):
                                errors.append(f"{cpath}.params must be an object")
    return errors


def _workflow_visibility_type_from_artifact(artifact: Artifact) -> str:
    return _normalize_article_visibility_type((artifact.scope_json or {}).get("visibility_type"), fallback="private")


def _workflow_allowed_roles(artifact: Artifact) -> List[str]:
    return _normalize_role_slugs((artifact.scope_json or {}).get("allowed_roles"))


def _can_edit_workflow(identity: UserIdentity, artifact: Artifact) -> bool:
    return _can_edit_article(identity, artifact)


def _can_view_workflow(identity: UserIdentity, artifact: Artifact) -> bool:
    if _can_manage_articles(identity):
        return True
    if artifact.status != "published":
        return bool(artifact.author_id and str(artifact.author_id) == str(identity.id))
    visibility_type = _workflow_visibility_type_from_artifact(artifact)
    if visibility_type == "public":
        return True
    if visibility_type == "authenticated":
        return identity is not None
    if visibility_type == "private":
        return bool(artifact.author_id and str(artifact.author_id) == str(identity.id))
    allowed = set(_workflow_allowed_roles(artifact))
    return bool(set(_get_roles(identity)).intersection(allowed))


def _serialize_workflow_summary(artifact: Artifact) -> Dict[str, Any]:
    spec = artifact.workflow_spec_json if isinstance(artifact.workflow_spec_json, dict) else {}
    category = _article_category_record(artifact)
    return {
        "id": str(artifact.id),
        "workspace_id": str(artifact.workspace_id),
        "type": artifact.type.slug,
        "format": artifact.format,
        "profile": str(artifact.workflow_profile or spec.get("profile") or "tour"),
        "title": artifact.title,
        "slug": _artifact_slug(artifact),
        "description": str(spec.get("description") or ""),
        "status": artifact.status,
        "version": artifact.version,
        "visibility_type": _workflow_visibility_type_from_artifact(artifact),
        "allowed_roles": _workflow_allowed_roles(artifact),
        "category": category.slug if category else "",
        "category_name": category.name if category else "",
        "category_id": str(category.id) if category else None,
        "updated_at": artifact.updated_at,
        "published_at": artifact.published_at,
    }


def _serialize_workflow_detail(artifact: Artifact) -> Dict[str, Any]:
    payload = _serialize_workflow_summary(artifact)
    payload.update(
        {
            "workflow_profile": artifact.workflow_profile or "tour",
            "workflow_spec_json": artifact.workflow_spec_json if isinstance(artifact.workflow_spec_json, dict) else {},
            "workflow_state_schema_version": artifact.workflow_state_schema_version,
            "created_at": artifact.created_at,
            "created_by": str(artifact.author_id) if artifact.author_id else None,
        }
    )
    return payload


def _serialize_article_revision(revision: ArtifactRevision) -> Dict[str, Any]:
    content = dict(revision.content_json or {})
    return {
        "id": str(revision.id),
        "article_id": str(revision.artifact_id),
        "revision_number": revision.revision_number,
        "body_markdown": str(content.get("body_markdown") or ""),
        "body_html": str(content.get("body_html") or ""),
        "summary": str(content.get("summary") or ""),
        "created_by": str(revision.created_by_id) if revision.created_by_id else None,
        "created_by_email": revision.created_by.email if revision.created_by else None,
        "created_at": revision.created_at,
        "provenance_json": dict(content.get("provenance_json") or {}),
    }


def _article_to_doc_page_payload(artifact: Artifact, revision: Optional[ArtifactRevision] = None) -> Dict[str, Any]:
    serialized = _serialize_article_detail(artifact, revision)
    return {
        "id": serialized["id"],
        "artifact_id": serialized["id"],
        "workspace_id": serialized["workspace_id"],
        "type": "article",
        "format": serialized.get("format") or "standard",
        "title": serialized["title"],
        "slug": serialized["slug"],
        "status": serialized["status"],
        "visibility": artifact.visibility,
        "route_bindings": serialized["route_bindings"],
        "tags": serialized["tags"],
        "body_markdown": serialized["body_markdown"],
        "summary": serialized["summary"],
        "version": serialized["version"],
        "created_at": serialized["created_at"],
        "updated_at": serialized["updated_at"],
        "published_at": serialized["published_at"],
        "created_by": serialized["created_by"],
        "updated_by": serialized["updated_by"],
        "updated_by_email": serialized["updated_by_email"],
    }


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


def _identity_from_user(user) -> Optional[UserIdentity]:
    if not user or not getattr(user, "is_authenticated", False):
        return None
    email = str(getattr(user, "email", "") or "").strip()
    if not email:
        return None
    return UserIdentity.objects.filter(email__iexact=email).order_by("-updated_at").first()


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
        "video_generation": {
            "enabled": True,
            "provider": os.environ.get("XYENCE_VIDEO_PROVIDER", "export_package") or "export_package",
            "http": {
                "endpoint_url": "",
                "timeout_seconds": 90,
            },
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

    video_generation = payload.get("video_generation") if isinstance(payload.get("video_generation"), dict) else {}
    if video_generation:
        enabled = bool(video_generation.get("enabled", True))
        provider = str(video_generation.get("provider") or "").strip().lower()
        http_cfg = video_generation.get("http") if isinstance(video_generation.get("http"), dict) else {}
        if enabled and provider in {"http", "http_adapter"}:
            if not str(http_cfg.get("endpoint_url") or "").strip():
                errors.append("video_generation.http.endpoint_url is required when provider is http")
        timeout_seconds = http_cfg.get("timeout_seconds")
        if timeout_seconds is not None:
            try:
                timeout = int(timeout_seconds)
                if timeout < 5 or timeout > 600:
                    errors.append("video_generation.http.timeout_seconds must be between 5 and 600")
            except (TypeError, ValueError):
                errors.append("video_generation.http.timeout_seconds must be an integer")
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
            if role not in set(_get_roles(identity)):
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
            if not set(_get_roles(identity)).intersection(role_set):
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
            "is_staff": bool(set(roles).intersection({"platform_owner", "platform_admin", "platform_architect"})),
            "is_active": True,
        },
    )
    if email and user.email != email:
        user.email = email
    user.is_staff = bool(set(roles).intersection({"platform_owner", "platform_admin", "platform_architect"}))
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
            "is_staff": bool(set(roles).intersection({"platform_owner", "platform_admin", "platform_architect"})),
            "is_active": True,
        },
    )
    if email and user.email != email:
        user.email = email
    user.is_staff = bool(set(roles).intersection({"platform_owner", "platform_admin", "platform_architect"}))
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


def _serialize_preview_status(identity: UserIdentity, request: HttpRequest) -> Dict[str, Any]:
    actor_roles = getattr(request, "actor_roles", None)
    if not isinstance(actor_roles, list):
        actor_roles = list(
            RoleBinding.objects.filter(user_identity=identity, scope_kind="platform").values_list("role", flat=True)
        )
    preview = getattr(request, "preview_state", None)
    if not isinstance(preview, dict):
        preview = _load_preview_state(request, actor_roles)
    effective_roles = getattr(request, "effective_roles", None)
    if not isinstance(effective_roles, list):
        effective_roles = preview.get("roles") if preview.get("enabled") else actor_roles
    return {
        "enabled": bool(preview.get("enabled")),
        "roles": list(preview.get("roles") or []),
        "read_only": bool(preview.get("read_only", True)),
        "started_at": preview.get("started_at"),
        "expires_at": preview.get("expires_at"),
        "actor_roles": actor_roles,
        "effective_roles": list(effective_roles or []),
    }


@csrf_exempt
def preview_enable(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    actor_roles = getattr(request, "actor_roles", None) or []
    payload = _parse_json(request)
    requested_roles = [str(role or "").strip() for role in (payload.get("roles") or []) if str(role or "").strip()]
    requested_roles = [role for role in requested_roles if role in PLATFORM_ROLE_IDS]
    read_only = bool(payload.get("readOnly", payload.get("read_only", True)))
    allowed_targets = _preview_allowed_roles_for_actor(actor_roles)
    if not requested_roles or any(role not in allowed_targets for role in requested_roles):
        _audit_action(
            "PreviewRejected",
            metadata={
                "actor_id": str(identity.id),
                "actor_roles": actor_roles,
                "requested_roles": requested_roles,
                "reason": "requested roles not allowed",
                "ip": request.META.get("REMOTE_ADDR", ""),
                "user_agent": request.META.get("HTTP_USER_AGENT", "")[:512],
            },
            request=request,
        )
        return JsonResponse({"error": "forbidden"}, status=403)
    state = _set_preview_state(request, roles=requested_roles, read_only=read_only)
    _audit_action(
        "PreviewEnabled",
        metadata={
            "actor_id": str(identity.id),
            "actor_roles": actor_roles,
            "preview_roles": requested_roles,
            "read_only": bool(state.get("read_only", True)),
            "started_at": state.get("started_at"),
            "expires_at": state.get("expires_at"),
            "ip": request.META.get("REMOTE_ADDR", ""),
            "user_agent": request.META.get("HTTP_USER_AGENT", "")[:512],
        },
        request=request,
    )
    # Refresh request-scoped attrs immediately for current response consistency.
    _require_authenticated(request)
    return JsonResponse({"preview": _serialize_preview_status(identity, request)})


@csrf_exempt
def preview_disable(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    current = _serialize_preview_status(identity, request)
    _clear_preview_state(request)
    _audit_action(
        "PreviewDisabled",
        metadata={
            "actor_id": str(identity.id),
            "preview_roles": current.get("roles") or [],
            "ended_at": _utc_now_ts(),
            "ip": request.META.get("REMOTE_ADDR", ""),
            "user_agent": request.META.get("HTTP_USER_AGENT", "")[:512],
        },
        request=request,
    )
    _require_authenticated(request)
    return JsonResponse({"preview": _serialize_preview_status(identity, request)})


@csrf_exempt
def preview_status(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    return JsonResponse({"preview": _serialize_preview_status(identity, request)})


@csrf_exempt
@require_any_role("platform_owner", "platform_admin")
def access_registry(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = getattr(request, "user_identity", None)
    _audit_action(
        "AccessExplorerViewed",
        metadata={"endpoint": "registry", "actor_id": str(identity.id) if identity else ""},
        request=request,
    )
    return JsonResponse(access_canonical_registry())


@csrf_exempt
@require_any_role("platform_owner", "platform_admin")
def access_users_collection(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = getattr(request, "user_identity", None)
    query = str(request.GET.get("query") or "").strip()
    _audit_action(
        "AccessExplorerViewed",
        metadata={"endpoint": "users", "query": query, "actor_id": str(identity.id) if identity else ""},
        request=request,
    )
    return JsonResponse({"users": access_search_users(query=query)})


@csrf_exempt
@require_any_role("platform_owner", "platform_admin")
def access_user_roles(request: HttpRequest, user_id: str) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = getattr(request, "user_identity", None)
    _audit_action(
        "AccessExplorerViewed",
        metadata={"endpoint": "user_roles", "target_user_id": str(user_id), "actor_id": str(identity.id) if identity else ""},
        request=request,
    )
    return JsonResponse({"roles": access_user_roles_data(str(user_id))})


@csrf_exempt
@require_any_role("platform_owner", "platform_admin")
def access_user_effective(request: HttpRequest, user_id: str) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = getattr(request, "user_identity", None)
    _audit_action(
        "AccessExplorerViewed",
        metadata={"endpoint": "user_effective", "target_user_id": str(user_id), "actor_id": str(identity.id) if identity else ""},
        request=request,
    )
    return JsonResponse(access_compute_effective_permissions(str(user_id)))


@csrf_exempt
@require_any_role("platform_owner", "platform_admin")
def access_role_detail(request: HttpRequest, role_id: str) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = getattr(request, "user_identity", None)
    _audit_action(
        "AccessExplorerViewed",
        metadata={"endpoint": "role_detail", "target_role_id": str(role_id), "actor_id": str(identity.id) if identity else ""},
        request=request,
    )
    try:
        return JsonResponse(access_role_detail_data(role_id))
    except KeyError:
        return JsonResponse({"error": "role not found"}, status=404)


@csrf_exempt
@require_any_role("platform_owner", "platform_admin")
def seed_packs_collection(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    include_items = str(request.GET.get("include_items") or "").strip().lower() in {"1", "true", "yes"}
    rows = list_seed_packs_status(include_items=include_items)
    return JsonResponse({"packs": rows})


@csrf_exempt
@require_any_role("platform_owner", "platform_admin")
def seed_pack_detail(request: HttpRequest, slug: str) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    row = get_seed_pack_status(slug)
    if not row:
        return JsonResponse({"error": "seed pack not found"}, status=404)
    return JsonResponse({"pack": row})


@csrf_exempt
@require_any_role("platform_owner", "platform_admin")
def seed_apply(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid json body"}, status=400)
    raw_slugs = payload.get("pack_slugs")
    pack_slugs = [str(value).strip() for value in raw_slugs] if isinstance(raw_slugs, list) else None
    apply_core = bool(payload.get("apply_core"))
    dry_run = bool(payload.get("dry_run"))
    identity = getattr(request, "user_identity", None)
    result = apply_seed_packs(
        pack_slugs=pack_slugs or None,
        apply_core=apply_core,
        dry_run=dry_run,
        applied_by=identity,
    )
    return JsonResponse(result)


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
            "actor_roles": list(getattr(request, "actor_roles", []) or roles),
            "preview": _serialize_preview_status(identity, request),
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
        "artifact_state": artifact.artifact_state,
        "schema_version": artifact.schema_version or "",
        "family_id": artifact.family_id or "",
        "content_hash": artifact.content_hash or "",
        "validation_status": artifact.validation_status or "unknown",
        "validation_errors": artifact.validation_errors_json or [],
        "created_via": _artifact_created_via(artifact),
        "last_touched_by_agent": _artifact_last_touched_by_agent(artifact),
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


def _artifact_owner_payload(artifact: Artifact) -> Optional[Dict[str, Any]]:
    if not artifact.author_id:
        return None
    return {
        "id": str(artifact.author_id),
        "email": artifact.author.email,
        "display_name": artifact.author.display_name,
    }


def _artifact_created_via(artifact: Artifact) -> str:
    provenance = artifact.provenance_json if isinstance(artifact.provenance_json, dict) else {}
    created_via = str(provenance.get("created_via") or "").strip()
    if created_via:
        return created_via
    source_system = str(provenance.get("source_system") or "").strip()
    if source_system:
        return source_system
    return "ui"


def _artifact_last_touched_by_agent(artifact: Artifact) -> Optional[str]:
    provenance = artifact.provenance_json if isinstance(artifact.provenance_json, dict) else {}
    value = str(provenance.get("last_touched_by_agent") or "").strip()
    return value or None


def _serialize_blueprint_source(blueprint: Blueprint) -> Dict[str, Any]:
    return {
        "id": str(blueprint.id),
        "name": blueprint.name,
        "namespace": blueprint.namespace,
        "status": blueprint.status,
        "description": blueprint.description,
        "created_at": blueprint.created_at,
        "updated_at": blueprint.updated_at,
        "artifact_id": str(blueprint.artifact_id) if blueprint.artifact_id else None,
    }


def _serialize_draft_session_source(session: BlueprintDraftSession) -> Dict[str, Any]:
    return {
        "id": str(session.id),
        "name": session.name,
        "title": session.title or session.name,
        "status": session.status,
        "kind": session.draft_kind,
        "blueprint_kind": session.blueprint_kind,
        "namespace": session.namespace or None,
        "project_key": session.project_key or None,
        "blueprint_id": str(session.blueprint_id) if session.blueprint_id else None,
        "linked_blueprint_id": str(session.linked_blueprint_id) if session.linked_blueprint_id else None,
        "created_at": session.created_at,
        "updated_at": session.updated_at,
        "artifact_id": str(session.artifact_id) if session.artifact_id else None,
    }


def _serialize_unified_artifact(artifact: Artifact, source_record: Any = None) -> Dict[str, Any]:
    payload = {
        "id": str(artifact.id),
        "artifact_id": str(artifact.id),
        "artifact_type": artifact.type.slug,
        "artifact_state": artifact.artifact_state,
        "title": artifact.title,
        "summary": artifact.summary or "",
        "schema_version": artifact.schema_version or "",
        "content_hash": artifact.content_hash or "",
        "validation_status": artifact.validation_status or "unknown",
        "validation_errors": artifact.validation_errors_json or [],
        "owner": _artifact_owner_payload(artifact),
        "created_via": _artifact_created_via(artifact),
        "last_touched_by_agent": _artifact_last_touched_by_agent(artifact),
        "source_ref_type": artifact.source_ref_type or "",
        "source_ref_id": artifact.source_ref_id or "",
        "family_id": artifact.family_id or "",
        "parent_artifact_id": str(artifact.parent_artifact_id) if artifact.parent_artifact_id else None,
        "lineage_root_id": str(artifact.lineage_root_id) if artifact.lineage_root_id else None,
        "tags": artifact.tags_json or [],
        "created_at": artifact.created_at,
        "updated_at": artifact.updated_at,
    }
    if source_record is not None:
        if isinstance(source_record, Blueprint):
            payload["source"] = _serialize_blueprint_source(source_record)
        elif isinstance(source_record, BlueprintDraftSession):
            payload["source"] = _serialize_draft_session_source(source_record)
        else:
            payload["source"] = source_record
    return payload


def _serialize_ledger_event(event: LedgerEvent) -> Dict[str, Any]:
    artifact = event.artifact
    return {
        "ledger_event_id": str(event.id),
        "created_at": event.created_at,
        "actor_user_id": str(event.actor_user_id),
        "actor": {
            "id": str(event.actor_user_id),
            "email": event.actor_user.email or "",
            "display_name": event.actor_user.display_name or "",
        }
        if event.actor_user_id
        else None,
        "action": event.action,
        "artifact_id": str(event.artifact_id),
        "artifact_type": event.artifact_type or "",
        "artifact_state": event.artifact_state or "",
        "parent_artifact_id": str(event.parent_artifact_id) if event.parent_artifact_id else None,
        "lineage_root_id": str(event.lineage_root_id) if event.lineage_root_id else None,
        "summary": event.summary or "",
        "metadata_json": event.metadata_json or {},
        "dedupe_key": event.dedupe_key or "",
        "source_ref_type": event.source_ref_type or "",
        "source_ref_id": event.source_ref_id or "",
        "artifact_title": artifact.title if artifact else "",
        "artifact_slug": _artifact_slug(artifact) if artifact else "",
        "artifact_workspace_id": str(artifact.workspace_id) if artifact and artifact.workspace_id else "",
    }


def _serialize_intent_script(script: IntentScript) -> Dict[str, Any]:
    return {
        "intent_script_id": str(script.id),
        "title": script.title,
        "scope_type": script.scope_type,
        "scope_ref_id": script.scope_ref_id,
        "format_version": script.format_version,
        "script_json": script.script_json if isinstance(script.script_json, dict) else {},
        "script_text": script.script_text or "",
        "status": script.status,
        "created_by": str(script.created_by_id) if script.created_by_id else None,
        "created_at": script.created_at,
        "updated_at": script.updated_at,
        "artifact_id": str(script.artifact_id) if script.artifact_id else None,
    }


def _can_view_generic_artifact(identity: UserIdentity, artifact: Artifact) -> bool:
    slug = str(artifact.type.slug or "").strip()
    if slug == "article":
        return _can_view_article(identity, artifact)
    if slug == "workflow":
        return _can_view_workflow(identity, artifact)
    if slug == DOC_ARTIFACT_TYPE_SLUG:
        return _can_view_doc(identity, artifact)
    if _is_platform_admin(identity):
        return True
    if artifact.visibility == "public":
        return True
    if artifact.visibility == "team":
        return True
    return bool(artifact.author_id and str(artifact.author_id) == str(identity.id))


def _intent_scene(scene_id: str, title: str, *, body: str = "", outcome: str = "") -> Dict[str, Any]:
    return {
        "id": scene_id,
        "title": title,
        "voiceover": outcome or body or title,
        "on_screen": body or title,
    }


def _compose_intent_text(title: str, scenes: List[Dict[str, Any]]) -> str:
    lines: List[str] = [f"# {title}", ""]
    for idx, scene in enumerate(scenes, start=1):
        lines.append(f"{idx}. {scene.get('title') or f'Scene {idx}'}")
        lines.append(f"   Voiceover: {scene.get('voiceover') or ''}")
        lines.append(f"   On-screen: {scene.get('on_screen') or ''}")
        lines.append("")
    return "\n".join(lines).strip()


def _generate_intent_script_for_tour(artifact: Artifact, *, audience: str, tone: str, length_target: str) -> Tuple[Dict[str, Any], str]:
    spec = artifact.workflow_spec_json if isinstance(artifact.workflow_spec_json, dict) else {}
    steps = spec.get("steps") if isinstance(spec.get("steps"), list) else []
    scenes: List[Dict[str, Any]] = []
    for idx, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            continue
        scene = _intent_scene(
            f"s{idx}",
            str(step.get("title") or f"Step {idx}"),
            body=str(step.get("body_md") or ""),
            outcome=f"Guide the viewer through {str(step.get('title') or '').strip().lower() or 'the current step'} with clear expected outcome.",
        )
        scenes.append(scene)
    if not scenes:
        scenes.append(
            _intent_scene(
                "s1",
                artifact.title,
                outcome="Introduce the tour objective and expected result.",
            )
        )
    script_json = {
        "scenes": scenes,
        "metadata": {
            "audience": audience,
            "tone": tone,
            "length_target": length_target,
            "dependencies": ["xyn-ui", "workflow_runner"],
        },
        "duration_hint": "60-90s",
    }
    return script_json, _compose_intent_text(f"{artifact.title} Intent Script", scenes)


def _article_content_payload_for_intent_script(artifact: Artifact) -> Dict[str, Any]:
    latest = _latest_artifact_revision(artifact)
    content = latest.content_json if latest and isinstance(latest.content_json, dict) else {}
    fallback_tags = artifact.tags_json if isinstance(getattr(artifact, "tags_json", None), list) else []
    return {
        "title": str(content.get("title") or artifact.title or "").strip(),
        "summary": str(content.get("summary") or artifact.summary or "").strip(),
        "body": str(content.get("body_markdown") or "").strip(),
        "tags": [str(tag).strip() for tag in (content.get("tags") or fallback_tags) if str(tag).strip()],
    }


def _explainer_scenes_payload_for_intent_script(artifact: Artifact) -> List[Dict[str, Any]]:
    spec = artifact.video_spec_json if isinstance(artifact.video_spec_json, dict) else {}
    rows = spec.get("scenes") if isinstance(spec.get("scenes"), list) else []
    normalized: List[Dict[str, Any]] = []
    for idx, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        normalized.append(normalize_video_scene(row, index=idx))
    return normalized


def _intent_script_from_existing_scenes(title: str, scenes: List[Dict[str, Any]], *, audience: str, tone: str, length_target: str) -> Tuple[Dict[str, Any], str]:
    script_title = f"{str(title or 'Explainer').strip() or 'Explainer'} Intent Script"
    normalized = [normalize_video_scene(scene, index=idx) for idx, scene in enumerate(scenes, start=1)]
    script_json = {
        "title": script_title,
        "scenes": normalized,
        "duration_hint": "60-90s",
        "metadata": {
            "audience": audience,
            "tone": tone,
            "length_target": length_target,
            "dependencies": [],
        },
    }
    return script_json, _compose_intent_text(script_title, normalized)


def _article_intent_script_validation_error(payload: Dict[str, Any]) -> Optional[str]:
    summary = str(payload.get("summary") or "").strip()
    body = str(payload.get("body") or "").strip()
    if summary:
        return None
    if len(body) >= 80:
        return None
    return "Add a summary or body to generate an intent script."


def _sentence_chunks(value: str, *, limit: int = 3) -> List[str]:
    text = str(value or "").strip()
    if not text:
        return []
    chunks = [part.strip() for part in re.split(r"(?<=[.!?])\s+", text) if part.strip()]
    if chunks:
        return chunks[:limit]
    return [text[:320]]


def _on_screen_text(value: str) -> str:
    words = [w for w in str(value or "").strip().split() if w]
    if not words:
        return ""
    return " ".join(words[:12])


def _article_story_kind(payload: Dict[str, Any]) -> str:
    tags = [str(tag).strip().lower() for tag in (payload.get("tags") or []) if str(tag).strip()]
    body = str(payload.get("body") or "").strip()
    lowered = body.lower()
    if any(tag in {"guide", "how-to", "howto", "tutorial"} for tag in tags):
        return "guide"
    if re.search(r"(^|\n)\s*\d+[\).\s]", body):
        return "guide"
    if any(token in lowered for token in ["step ", "steps", "first,", "next,", "finally"]):
        return "guide"
    if any(token in lowered for token in [" i ", " my ", " we ", " our ", "summer", "vacation", "when "]):
        return "narrative"
    return "informative"


def _article_scene_count(payload: Dict[str, Any]) -> int:
    body_len = len(str(payload.get("body") or "").strip())
    if body_len < 700:
        return 3
    if body_len > 4500:
        return 7
    if body_len > 2500:
        return 6
    return 5


def _article_script_plan(payload: Dict[str, Any]) -> Dict[str, Any]:
    story_kind = _article_story_kind(payload)
    scene_count = _article_scene_count(payload)
    if scene_count == 3:
        scenes = [
            {"id": "s1", "title": "Hook / Premise", "purpose": "Establish the topic in plain language.", "on_screen": "What this is about"},
            {"id": "s2", "title": "Core", "purpose": "Combine context and key points.", "on_screen": "Core ideas"},
            {"id": "s3", "title": "Takeaway / Close", "purpose": "Summarize outcome and close naturally.", "on_screen": "Closing thought"},
        ]
        return {"story_kind": story_kind, "scene_count": scene_count, "scenes": scenes}

    if story_kind == "guide":
        base = [
            {"id": "s1", "title": "Hook / Premise", "purpose": "State the guide objective.", "on_screen": "What this is about"},
            {"id": "s2", "title": "Goal", "purpose": "Define the target outcome.", "on_screen": "Goal"},
            {"id": "s3", "title": "Steps", "purpose": "Present the main steps.", "on_screen": "Steps"},
            {"id": "s4", "title": "Common pitfalls", "purpose": "Warn about likely mistakes.", "on_screen": "Common pitfalls"},
            {"id": "s5", "title": "Recap", "purpose": "Close with concise recap.", "on_screen": "Recap"},
        ]
    elif story_kind == "informative":
        base = [
            {"id": "s1", "title": "Hook / Premise", "purpose": "Establish the core subject.", "on_screen": "What this is about"},
            {"id": "s2", "title": "Setup / Context", "purpose": "Provide context to frame the argument.", "on_screen": "The setup"},
            {"id": "s3", "title": "Argument / Evidence", "purpose": "Present key points and support.", "on_screen": "Key points"},
            {"id": "s4", "title": "Implications", "purpose": "Explain why the argument matters.", "on_screen": "What it means"},
            {"id": "s5", "title": "Close / Next Step", "purpose": "End with a grounded close.", "on_screen": "Closing thought"},
        ]
    else:
        base = [
            {"id": "s1", "title": "Hook / Premise", "purpose": "Establish what this story is about.", "on_screen": "What this is about"},
            {"id": "s2", "title": "Setup / Context", "purpose": "Provide people/time/context.", "on_screen": "The setup"},
            {"id": "s3", "title": "Key Moments", "purpose": "Summarize 2–4 meaningful moments.", "on_screen": "The highlights"},
            {"id": "s4", "title": "Outcome / Takeaways", "purpose": "State what changed or was learned.", "on_screen": "What it means"},
            {"id": "s5", "title": "Close / Next Step", "purpose": "Provide a natural close.", "on_screen": "Closing thought"},
        ]

    # Expand long content to 6–7 scenes by splitting core segments.
    next_index = 6
    while len(base) < scene_count:
        base.insert(-1, {"id": f"s{next_index}", "title": f"Detail {next_index - 4}", "purpose": "Add grounded detail from content.", "on_screen": "More detail"})
        next_index += 1
    return {"story_kind": story_kind, "scene_count": scene_count, "scenes": base}


def _article_source_chunks(payload: Dict[str, Any], *, target: int) -> List[str]:
    summary = str(payload.get("summary") or "").strip()
    body = str(payload.get("body") or "").strip()
    title = str(payload.get("title") or "Article").strip() or "Article"
    chunks: List[str] = []
    if summary:
        chunks.extend(_sentence_chunks(summary, limit=2))
    for paragraph in [part.strip() for part in re.split(r"\n\s*\n", body) if part.strip()]:
        chunks.extend(_sentence_chunks(paragraph, limit=2))
    if not chunks:
        chunks = [title]
    while len(chunks) < target:
        chunks.append(chunks[-1])
    return chunks[:target]


def _article_script_from_plan_deterministic(
    payload: Dict[str, Any],
    plan: Dict[str, Any],
    *,
    audience: str,
    tone: str,
    length_target: str,
) -> Tuple[Dict[str, Any], str]:
    title = str(payload.get("title") or "Article").strip() or "Article"
    plan_scenes = plan.get("scenes") if isinstance(plan.get("scenes"), list) else []
    chunks = _article_source_chunks(payload, target=max(len(plan_scenes), 3))
    scenes: List[Dict[str, Any]] = []
    for idx, plan_scene in enumerate(plan_scenes):
        if not isinstance(plan_scene, dict):
            continue
        content = chunks[idx] if idx < len(chunks) else chunks[-1]
        voice = " ".join(_sentence_chunks(content, limit=2))[:420]
        scenes.append(
            {
                "id": str(plan_scene.get("id") or f"s{idx + 1}"),
                "title": str(plan_scene.get("title") or f"Scene {idx + 1}"),
                "voiceover": voice,
                "on_screen": _on_screen_text(str(plan_scene.get("on_screen") or content)),
            }
        )

    script_title = f"{title} Intent Script"
    script_json = {
        "title": script_title,
        "scenes": scenes,
        "duration_hint": "60-90s",
        "metadata": {
            "audience": audience,
            "tone": tone,
            "length_target": length_target,
            "dependencies": [],
            "story_kind": plan.get("story_kind"),
        },
    }
    return script_json, _compose_intent_text(script_title, scenes)


def _strip_code_fence(value: str) -> str:
    text = str(value or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    return text.strip()


def _article_script_from_model(
    payload: Dict[str, Any],
    plan: Dict[str, Any],
    *,
    audience: str,
    tone: str,
    length_target: str,
) -> Optional[Tuple[Dict[str, Any], str]]:
    try:
        resolved = resolve_ai_config(purpose_slug="documentation")
        user_payload = {
            "title": payload.get("title") or "",
            "summary": payload.get("summary") or "",
            "body": payload.get("body") or "",
            "tags": payload.get("tags") or [],
            "scene_plan": plan,
            "constraints": [
                "Use ONLY supplied title/summary/body/tags.",
                "Do not mention URLs, IDs, lifecycle state, validation, schema version, hash, owner, lineage, timestamps.",
                "Do not invent events not present in content.",
                "If detail is missing, keep wording generic.",
            ],
            "output_schema": {
                "title": "string",
                "scenes": [{"id": "s1", "title": "string", "voiceover": "string", "on_screen": "string <= 12 words"}],
                "duration_hint": "60-90s",
            },
        }
        response = invoke_model(
            resolved_config=resolved,
            messages=[
                {"role": "system", "content": "Return strict JSON only. Fill scene skeleton in order."},
                {"role": "developer", "content": "Ground every line in supplied article content. No metadata narration."},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ],
        )
        raw = _strip_code_fence(str(response.get("content") or ""))
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return None
        scenes_input = parsed.get("scenes") if isinstance(parsed.get("scenes"), list) else []
        if not scenes_input:
            return None
        scenes: List[Dict[str, Any]] = []
        for idx, item in enumerate(scenes_input):
            if not isinstance(item, dict):
                continue
            voiceover = str(item.get("voiceover") or "").strip()
            on_screen = _on_screen_text(str(item.get("on_screen") or ""))
            if not voiceover:
                continue
            scenes.append(
                {
                    "id": str(item.get("id") or f"s{idx + 1}"),
                    "title": str(item.get("title") or f"Scene {idx + 1}"),
                    "voiceover": voiceover[:500],
                    "on_screen": on_screen or _on_screen_text(voiceover),
                }
            )
        if len(scenes) < 3:
            return None
        title = str(parsed.get("title") or payload.get("title") or "Article").strip() or "Article"
        script_title = f"{title} Intent Script"
        script_json = {
            "title": script_title,
            "scenes": scenes,
            "duration_hint": "60-90s",
            "metadata": {
                "audience": audience,
                "tone": tone,
                "length_target": length_target,
                "dependencies": [],
                "story_kind": plan.get("story_kind"),
            },
        }
        return script_json, _compose_intent_text(script_title, scenes)
    except Exception:
        return None


def _generate_intent_script_for_article_content(payload: Dict[str, Any], *, audience: str, tone: str, length_target: str) -> Tuple[Dict[str, Any], str]:
    plan = _article_script_plan(payload)
    generated = _article_script_from_model(payload, plan, audience=audience, tone=tone, length_target=length_target)
    if generated:
        return generated
    return _article_script_from_plan_deterministic(payload, plan, audience=audience, tone=tone, length_target=length_target)


def _generate_intent_script_for_artifact(artifact: Artifact, *, audience: str, tone: str, length_target: str) -> Tuple[Dict[str, Any], str]:
    source = _artifact_source_record(artifact)
    scenes: List[Dict[str, Any]] = []
    scenes.append(
        _intent_scene(
            "s1",
            f"{artifact.title} overview",
            outcome=(
                f"This is a {artifact.type.slug} artifact in {artifact.artifact_state} state, "
                f"with validation {artifact.validation_status or 'unknown'}."
            ),
        )
    )
    scenes.append(
        _intent_scene(
            "s2",
            "Provenance and trust signals",
            outcome=(
                f"Show owner, schema version, and content hash {str(artifact.content_hash or '')[:16]} "
                "to explain traceability."
            ),
        )
    )
    if artifact.type.slug == "article":
        latest = _latest_artifact_revision(artifact)
        content = latest.content_json if latest and isinstance(latest.content_json, dict) else {}
        narrative = str(content.get("summary") or content.get("body_markdown") or "").strip()
        scenes.append(
            _intent_scene(
                "s3",
                "Content narrative",
                outcome=narrative[:480] or "Describe the article narrative and intended audience outcome.",
            )
        )
    elif artifact.type.slug == "workflow":
        spec = artifact.workflow_spec_json if isinstance(artifact.workflow_spec_json, dict) else {}
        scenes.append(
            _intent_scene(
                "s3",
                "Workflow path",
                outcome=f"Walk through {len(spec.get('steps') or [])} deterministic workflow steps.",
            )
        )
    elif artifact.type.slug == "blueprint" and isinstance(source, Blueprint):
        scenes.append(
            _intent_scene(
                "s3",
                "Blueprint intent",
                outcome=(source.description or source.spec_text or "").strip()[:480] or "Explain blueprint intent and expected deployment outcome.",
            )
        )
    script_json = {
        "title": f"{artifact.title} Intent Script",
        "scenes": scenes,
        "duration_hint": "60-90s",
        "metadata": {
            "audience": audience,
            "tone": tone,
            "length_target": length_target,
            "dependencies": ["xyn-api", "xyn-ui", "ledger"],
        },
    }
    return script_json, _compose_intent_text(f"{artifact.title} Intent Script", scenes)


def _parse_optional_dt(value: str) -> Optional[Any]:
    raw = str(value or "").strip()
    if not raw:
        return None
    return parse_datetime(raw)


def _artifact_source_record(artifact: Artifact) -> Any:
    ref_type = str(artifact.source_ref_type or "").strip()
    ref_id = str(artifact.source_ref_id or "").strip()
    if not ref_type or not ref_id:
        return None
    if ref_type == "Blueprint":
        return Blueprint.objects.filter(id=ref_id).first()
    if ref_type == "BlueprintDraftSession":
        return BlueprintDraftSession.objects.filter(id=ref_id).first()
    if ref_type == "Module":
        return Module.objects.filter(id=ref_id).first()
    if ref_type == "ContextPack":
        return ContextPack.objects.filter(id=ref_id).first()
    return None


def _artifact_payload_for_hash(artifact: Artifact) -> Dict[str, Any]:
    source = _artifact_source_record(artifact)
    payload: Dict[str, Any] = {
        "artifact_type": artifact.type.slug,
        "artifact_state": artifact.artifact_state,
        "title": artifact.title,
        "summary": artifact.summary or "",
        "schema_version": artifact.schema_version or "",
        "format": artifact.format or "",
    }
    if artifact.type.slug == "article":
        latest = _latest_artifact_revision(artifact)
        content = latest.content_json if latest and isinstance(latest.content_json, dict) else {}
        payload["article"] = {
            "title": content.get("title") or artifact.title,
            "summary": content.get("summary") or artifact.summary or "",
            "body_markdown": content.get("body_markdown") or "",
            "format": artifact.format,
            "video_spec_json": artifact.video_spec_json if isinstance(artifact.video_spec_json, dict) else {},
        }
    elif artifact.type.slug == "workflow":
        payload["workflow"] = {
            "profile": artifact.workflow_profile or "",
            "spec": artifact.workflow_spec_json if isinstance(artifact.workflow_spec_json, dict) else {},
            "schema_version": artifact.workflow_state_schema_version,
        }
    elif artifact.type.slug == "blueprint" and isinstance(source, Blueprint):
        payload["blueprint"] = {
            "name": source.name,
            "namespace": source.namespace,
            "description": source.description or "",
            "spec_text": source.spec_text or "",
            "metadata_json": source.metadata_json or {},
            "status": source.status,
            "family_id": artifact.family_id or "",
        }
    elif artifact.type.slug == "module" and isinstance(source, Module):
        payload["module"] = {
            "fqn": source.fqn,
            "type": source.type,
            "current_version": source.current_version,
            "status": source.status,
            "spec": source.latest_module_spec_json or {},
        }
    elif artifact.type.slug == "context_pack" and isinstance(source, ContextPack):
        payload["context_pack"] = {
            "name": source.name,
            "purpose": source.purpose,
            "scope": source.scope,
            "namespace": source.namespace,
            "project_key": source.project_key,
            "version": source.version,
            "is_default": bool(source.is_default),
            "is_active": bool(source.is_active),
            "content_markdown": source.content_markdown or "",
        }
    return payload


def compute_content_hash(artifact: Artifact) -> str:
    normalized = json.dumps(_artifact_payload_for_hash(artifact), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_artifact(artifact: Artifact) -> Tuple[str, List[str]]:
    source = _artifact_source_record(artifact)
    slug = artifact.type.slug
    errors: List[str] = []
    warnings: List[str] = []

    if slug == "blueprint":
        if not isinstance(source, Blueprint):
            errors.append("blueprint source record not found")
        elif not str(source.spec_text or "").strip():
            errors.append("blueprint spec_text is required")
    elif slug == "article":
        latest = _latest_artifact_revision(artifact)
        content = latest.content_json if latest and isinstance(latest.content_json, dict) else {}
        if not str(content.get("body_markdown") or "").strip():
            errors.append("article body_markdown is required")
        if not str(content.get("summary") or "").strip():
            warnings.append("article summary is empty")
    elif slug == "workflow":
        spec = artifact.workflow_spec_json if isinstance(artifact.workflow_spec_json, dict) else {}
        profile = str(artifact.workflow_profile or spec.get("profile") or "").strip().lower() or "tour"
        workflow_errors = _validate_workflow_spec(spec, profile=profile)
        if workflow_errors:
            errors.extend([str(entry) for entry in workflow_errors])
    elif slug == "module":
        if not isinstance(source, Module):
            errors.append("module source record not found")
        elif not source.latest_module_spec_json:
            warnings.append("module spec is empty")
    elif slug == "context_pack":
        if not isinstance(source, ContextPack):
            errors.append("context pack source record not found")
        elif not str(source.content_markdown or "").strip():
            errors.append("context pack content is required")

    if errors:
        return "fail", errors
    if warnings:
        return "warning", warnings
    return "pass", []


@csrf_exempt
@login_required
def artifacts_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)

    artifact_type = str(request.GET.get("type") or "").strip().lower()
    artifact_state = str(request.GET.get("state") or "").strip().lower()
    query = str(request.GET.get("query") or request.GET.get("q") or "").strip()
    owner = str(request.GET.get("owner") or "").strip()

    try:
        limit = max(1, min(500, int(request.GET.get("limit") or 100)))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(0, int(request.GET.get("offset") or 0))
    except (TypeError, ValueError):
        offset = 0

    qs = Artifact.objects.select_related("type", "author", "parent_artifact", "lineage_root").all()
    if artifact_type:
        qs = qs.filter(type__slug=artifact_type)
    if artifact_state:
        qs = qs.filter(artifact_state=artifact_state)
    if owner:
        qs = qs.filter(author_id=owner)
    if query:
        qs = qs.filter(
            models.Q(title__icontains=query)
            | models.Q(summary__icontains=query)
            | models.Q(source_ref_id__icontains=query)
            | models.Q(source_ref_type__icontains=query)
        )
    qs = qs.order_by("-updated_at", "-created_at")
    total = qs.count()
    items = list(qs[offset : offset + limit])

    blueprint_ids = [item.source_ref_id for item in items if item.source_ref_type == "Blueprint" and item.source_ref_id]
    draft_ids = [item.source_ref_id for item in items if item.source_ref_type == "BlueprintDraftSession" and item.source_ref_id]
    blueprints_by_id = {str(item.id): item for item in Blueprint.objects.filter(id__in=blueprint_ids)} if blueprint_ids else {}
    drafts_by_id = {str(item.id): item for item in BlueprintDraftSession.objects.filter(id__in=draft_ids)} if draft_ids else {}

    data: List[Dict[str, Any]] = []
    for artifact in items:
        source = None
        if artifact.source_ref_type == "Blueprint":
            source = blueprints_by_id.get(artifact.source_ref_id)
        elif artifact.source_ref_type == "BlueprintDraftSession":
            source = drafts_by_id.get(artifact.source_ref_id)
        data.append(_serialize_unified_artifact(artifact, source))
    return JsonResponse({"artifacts": data, "count": total, "limit": limit, "offset": offset})


@csrf_exempt
@login_required
def artifact_detail(request: HttpRequest, artifact_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method not in {"GET", "PATCH"}:
        return JsonResponse({"error": "method not allowed"}, status=405)

    artifact = get_object_or_404(
        Artifact.objects.select_related("type", "author", "parent_artifact", "lineage_root"),
        id=artifact_id,
    )
    identity = _identity_from_user(request.user)
    if request.method == "PATCH":
        payload = _parse_json(request)
        old_artifact = Artifact.objects.get(id=artifact.id)
        old_source = None
        if artifact.source_ref_type == "Blueprint" and artifact.source_ref_id:
            old_source = Blueprint.objects.filter(id=artifact.source_ref_id).first()
        elif artifact.source_ref_type == "BlueprintDraftSession" and artifact.source_ref_id:
            old_source = BlueprintDraftSession.objects.filter(id=artifact.source_ref_id).first()

        updates: Dict[str, Any] = {}
        if "title" in payload:
            updates["title"] = str(payload.get("title") or "").strip() or artifact.title
        if "summary" in payload:
            updates["summary"] = str(payload.get("summary") or "").strip()
        if "schema_version" in payload:
            updates["schema_version"] = str(payload.get("schema_version") or "").strip()
        if "tags" in payload or "tags_json" in payload:
            tags_payload = payload.get("tags") if "tags" in payload else payload.get("tags_json")
            if not isinstance(tags_payload, list):
                return JsonResponse({"error": "tags must be an array"}, status=400)
            updates["tags_json"] = [str(tag).strip() for tag in tags_payload if str(tag).strip()]
        if "artifact_state" in payload:
            next_state = str(payload.get("artifact_state") or "").strip()
            valid_states = {choice[0] for choice in Artifact.ARTIFACT_STATE_CHOICES}
            if next_state not in valid_states:
                return JsonResponse({"error": "invalid artifact_state"}, status=400)
            updates["artifact_state"] = next_state
        if "parent_artifact_id" in payload:
            parent_id = str(payload.get("parent_artifact_id") or "").strip()
            if parent_id:
                parent = Artifact.objects.filter(id=parent_id).first()
                if not parent:
                    return JsonResponse({"error": "parent_artifact_id not found"}, status=404)
                updates["parent_artifact"] = parent
                updates["lineage_root"] = parent.lineage_root or parent
            else:
                updates["parent_artifact"] = None
                updates["lineage_root"] = artifact

        if updates:
            for field, value in updates.items():
                setattr(artifact, field, value)
            update_fields = list(updates.keys()) + ["updated_at"]
            artifact.save(update_fields=update_fields)

        new_artifact = Artifact.objects.get(id=artifact.id)
        new_source = None
        if artifact.source_ref_type == "Blueprint" and artifact.source_ref_id:
            new_source = Blueprint.objects.filter(id=artifact.source_ref_id).first()
        elif artifact.source_ref_type == "BlueprintDraftSession" and artifact.source_ref_id:
            new_source = BlueprintDraftSession.objects.filter(id=artifact.source_ref_id).first()
        diff_payload = compute_artifact_diff(old_artifact, new_artifact, old_source=old_source, new_source=new_source)
        changed_fields = diff_payload.get("changed_fields") or []
        if changed_fields:
            summary = f"Updated {artifact.type.name} artifact: {', '.join(changed_fields[:3])}"
            emit_ledger_event(
                actor=identity,
                action="artifact.update",
                artifact=new_artifact,
                summary=summary,
                metadata=diff_payload,
                dedupe_key=make_dedupe_key("artifact.update", str(new_artifact.id), diff_payload=diff_payload),
            )
            if "artifact_state" in changed_fields:
                state = new_artifact.artifact_state
                if state == "deprecated":
                    emit_ledger_event(
                        actor=identity,
                        action="artifact.deprecate",
                        artifact=new_artifact,
                        summary=f"Deprecated {artifact.type.name} artifact",
                        metadata={"reason": str(payload.get("reason") or "").strip()},
                        dedupe_key=make_dedupe_key("artifact.deprecate", str(new_artifact.id), state=state),
                    )
                elif state == "immutable":
                    emit_ledger_event(
                        actor=identity,
                        action="artifact.archive",
                        artifact=new_artifact,
                        summary=f"Archived {artifact.type.name} artifact",
                        metadata={"reason": str(payload.get("reason") or "").strip()},
                        dedupe_key=make_dedupe_key("artifact.archive", str(new_artifact.id), state=state),
                    )
        artifact = new_artifact

    source = None
    if artifact.source_ref_type == "Blueprint" and artifact.source_ref_id:
        source = Blueprint.objects.filter(id=artifact.source_ref_id).first()
    elif artifact.source_ref_type == "BlueprintDraftSession" and artifact.source_ref_id:
        source = BlueprintDraftSession.objects.filter(id=artifact.source_ref_id).first()
    return JsonResponse(_serialize_unified_artifact(artifact, source))


@csrf_exempt
@login_required
def artifact_activity(request: HttpRequest, artifact_id: str) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    get_object_or_404(Artifact, id=artifact_id)
    qs = LedgerEvent.objects.select_related("actor_user", "artifact").filter(artifact_id=artifact_id)
    action = str(request.GET.get("action") or "").strip()
    since = _parse_optional_dt(str(request.GET.get("since") or ""))
    until = _parse_optional_dt(str(request.GET.get("until") or ""))
    try:
        limit = max(1, min(500, int(request.GET.get("limit") or 100)))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(0, int(request.GET.get("offset") or 0))
    except (TypeError, ValueError):
        offset = 0

    if action:
        qs = qs.filter(action=action)
    if since:
        qs = qs.filter(created_at__gte=since)
    if until:
        qs = qs.filter(created_at__lte=until)

    total = qs.count()
    rows = list(qs.order_by("-created_at")[offset : offset + limit])
    return JsonResponse({"events": [_serialize_ledger_event(row) for row in rows], "count": total, "limit": limit, "offset": offset})


@csrf_exempt
@login_required
def ledger_collection(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error

    qs = LedgerEvent.objects.select_related("actor_user", "artifact")
    actor = str(request.GET.get("actor") or "").strip()
    workspace = str(request.GET.get("workspace") or "").strip()
    artifact_id = str(request.GET.get("artifact_id") or "").strip()
    artifact_type = str(request.GET.get("artifact_type") or "").strip()
    action = str(request.GET.get("action") or "").strip()
    since_raw = str(request.GET.get("since") or "").strip()
    until_raw = str(request.GET.get("until") or "").strip()

    since = _parse_optional_dt(since_raw) if since_raw else None
    until = _parse_optional_dt(until_raw) if until_raw else None
    if since_raw and since is None:
        return JsonResponse({"error": "invalid since datetime"}, status=400)
    if until_raw and until is None:
        return JsonResponse({"error": "invalid until datetime"}, status=400)

    if actor:
        qs = qs.filter(actor_user_id=actor)
    if workspace:
        qs = qs.filter(artifact__workspace_id=workspace)
    if artifact_id:
        qs = qs.filter(artifact_id=artifact_id)
    if artifact_type:
        qs = qs.filter(artifact_type=artifact_type)
    if action:
        qs = qs.filter(action=action)
    if since:
        qs = qs.filter(created_at__gte=since)
    if until:
        qs = qs.filter(created_at__lte=until)

    try:
        limit = max(1, min(500, int(request.GET.get("limit") or 100)))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(0, int(request.GET.get("offset") or 0))
    except (TypeError, ValueError):
        offset = 0
    total = qs.count()
    rows = list(qs.order_by("-created_at")[offset : offset + limit])
    return JsonResponse(
        {
            "events": [_serialize_ledger_event(row) for row in rows],
            "count": total,
            "limit": limit,
            "offset": offset,
        }
    )


@csrf_exempt
@login_required
def ledger_summary_by_user(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error

    qs = LedgerEvent.objects.select_related("actor_user")
    workspace = str(request.GET.get("workspace") or "").strip()
    since_raw = str(request.GET.get("since") or "").strip()
    until_raw = str(request.GET.get("until") or "").strip()
    since = _parse_optional_dt(since_raw) if since_raw else None
    until = _parse_optional_dt(until_raw) if until_raw else None
    if since_raw and since is None:
        return JsonResponse({"error": "invalid since datetime"}, status=400)
    if until_raw and until is None:
        return JsonResponse({"error": "invalid until datetime"}, status=400)
    if workspace:
        qs = qs.filter(artifact__workspace_id=workspace)
    if since:
        qs = qs.filter(created_at__gte=since)
    if until:
        qs = qs.filter(created_at__lte=until)
    rows = list(
        qs.values(
            "actor_user_id",
            "actor_user__email",
            "actor_user__display_name",
            "action",
            "summary",
            "artifact_id",
            "artifact__title",
        ).order_by("-created_at")
    )
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        actor_id = str(row["actor_user_id"] or "")
        if not actor_id:
            continue
        summary = grouped.setdefault(
            actor_id,
            {
                "actor_user_id": actor_id,
                "email": row["actor_user__email"] or "",
                "display_name": row["actor_user__display_name"] or "",
                "create_count": 0,
                "update_count": 0,
                "publish_count": 0,
                "canonize_count": 0,
                "deprecate_count": 0,
                "archive_count": 0,
                "total_count": 0,
                "top_artifacts": {},
            },
        )
        action = str(row["action"] or "")
        event_summary = str(row["summary"] or "").lower()
        artifact_id = str(row["artifact_id"] or "")
        artifact_title = str(row["artifact__title"] or "").strip() or artifact_id
        summary["total_count"] += 1
        if action == "artifact.create":
            summary["create_count"] += 1
        elif action == "artifact.update":
            summary["update_count"] += 1
            if "published" in event_summary:
                summary["publish_count"] += 1
        elif action == "artifact.canonize":
            summary["canonize_count"] += 1
        elif action == "artifact.deprecate":
            summary["deprecate_count"] += 1
        elif action == "artifact.archive":
            summary["archive_count"] += 1
        if artifact_id:
            top_artifacts = summary["top_artifacts"]
            current = top_artifacts.get(artifact_id) or {"artifact_id": artifact_id, "title": artifact_title, "count": 0}
            current["count"] += 1
            top_artifacts[artifact_id] = current

    result_rows: List[Dict[str, Any]] = []
    for item in grouped.values():
        artifacts = sorted(item["top_artifacts"].values(), key=lambda value: (-int(value["count"]), str(value["title"])))[:5]
        row = dict(item)
        row["top_artifacts"] = artifacts
        result_rows.append(row)
    result_rows.sort(key=lambda item: (-int(item["total_count"]), str(item["email"] or item["display_name"] or item["actor_user_id"])))
    return JsonResponse({"rows": result_rows})


@csrf_exempt
@login_required
def ledger_summary_by_artifact(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    artifact_id = str(request.GET.get("artifact_id") or "").strip()
    if not artifact_id:
        return JsonResponse({"error": "artifact_id required"}, status=400)
    qs = LedgerEvent.objects.select_related("actor_user").filter(artifact_id=artifact_id).order_by("-created_at")
    counts = (
        qs.values("action")
        .annotate(count=models.Count("id"))
        .order_by("action")
    )
    return JsonResponse(
        {
            "artifact_id": artifact_id,
            "counts": [{"action": row["action"], "count": int(row["count"])} for row in counts],
            "events": [_serialize_ledger_event(event) for event in qs[:200]],
        }
    )


@csrf_exempt
@login_required
def artifacts_create_draft_session(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error

    payload = _parse_json(request)
    draft_kind = str(payload.get("kind") or payload.get("draft_kind") or "blueprint").strip().lower()
    if draft_kind not in {"blueprint", "solution"}:
        return JsonResponse({"error": "kind must be blueprint or solution"}, status=400)
    title = (payload.get("title") or payload.get("name") or "").strip() or "Untitled draft"
    blueprint_kind = str(payload.get("blueprint_kind") or "solution").strip().lower()
    namespace = str(payload.get("namespace") or "").strip()
    project_key = str(payload.get("project_key") or "").strip()
    initial_prompt = str(payload.get("initial_prompt") or "").strip()
    revision_instruction = str(payload.get("revision_instruction") or "").strip()
    selected_context_pack_ids = payload.get("selected_context_pack_ids")
    if selected_context_pack_ids is None:
        selected_context_pack_ids = payload.get("context_pack_ids")
    if not isinstance(selected_context_pack_ids, list):
        selected_context_pack_ids = []

    blueprint = None
    blueprint_id = payload.get("blueprint_id")
    if blueprint_id:
        blueprint = Blueprint.objects.filter(id=blueprint_id).first()
        if not blueprint:
            return JsonResponse({"error": "blueprint_id not found"}, status=404)
        namespace = namespace or blueprint.namespace
        project_key = project_key or f"{blueprint.namespace}.{blueprint.name}"

    with transaction.atomic():
        session = BlueprintDraftSession.objects.create(
            name=title,
            title=title,
            blueprint=blueprint,
            draft_kind=draft_kind,
            blueprint_kind=blueprint_kind if blueprint_kind in {"solution", "module", "bundle"} else "solution",
            status="drafting",
            namespace=namespace,
            project_key=project_key,
            initial_prompt=initial_prompt,
            revision_instruction=revision_instruction,
            selected_context_pack_ids=selected_context_pack_ids,
            context_pack_ids=selected_context_pack_ids,
            created_by=request.user,
            updated_by=request.user,
        )
        artifact = ensure_draft_session_artifact(session, owner_user=request.user)
        emit_ledger_event(
            actor=_identity_from_user(request.user),
            action="artifact.create",
            artifact=artifact,
            summary="Created Draft Session artifact",
            metadata={
                "title": artifact.title,
                "initial_artifact_state": artifact.artifact_state,
                "schema_version": artifact.schema_version,
            },
            dedupe_key=make_dedupe_key("artifact.create", str(artifact.id)),
        )
    return JsonResponse({"artifact_id": str(artifact.id), "session_id": str(session.id)})


@csrf_exempt
@login_required
def artifacts_create_blueprint(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error

    payload = _parse_json(request)
    name = str(payload.get("name") or "").strip()
    if not name:
        return JsonResponse({"error": "name is required"}, status=400)
    namespace = str(payload.get("namespace") or "core").strip() or "core"
    description = str(payload.get("description") or "").strip()
    spec_text = str(payload.get("spec_text") or "")
    metadata_json = payload.get("metadata_json") if isinstance(payload.get("metadata_json"), dict) else None
    parent_artifact_id = str(payload.get("parent_artifact_id") or "").strip()
    parent_artifact = Artifact.objects.filter(id=parent_artifact_id).first() if parent_artifact_id else None
    requested_state = str(payload.get("artifact_state") or "canonical").strip().lower()
    if requested_state not in {"canonical", "provisional"}:
        return JsonResponse({"error": "artifact_state must be canonical or provisional"}, status=400)

    identity = _identity_from_user(request.user)

    with transaction.atomic():
        old_source = Blueprint.objects.filter(name=name, namespace=namespace).first()
        blueprint, created = Blueprint.objects.get_or_create(
            name=name,
            namespace=namespace,
            defaults={
                "description": description,
                "spec_text": spec_text,
                "metadata_json": metadata_json,
                "created_by": request.user,
                "updated_by": request.user,
            },
        )
        if not created:
            blueprint.description = description
            if "spec_text" in payload:
                blueprint.spec_text = spec_text
            if "metadata_json" in payload:
                blueprint.metadata_json = metadata_json
            blueprint.updated_by = request.user
            blueprint.save(update_fields=["description", "spec_text", "metadata_json", "updated_by", "updated_at"])
        if requested_state == "provisional":
            artifact_type, _ = ArtifactType.objects.get_or_create(
                slug="blueprint",
                defaults={
                    "name": "Blueprint",
                    "description": "Blueprint artifact",
                    "icon": "LayoutTemplate",
                    "schema_json": {"entity": "Blueprint"},
                },
            )
            family_id = str(blueprint.blueprint_family_id or "").strip() or str(blueprint.id)
            artifact = Artifact.objects.create(
                workspace=_default_workspace(),
                type=artifact_type,
                artifact_state="provisional",
                family_id=family_id,
                title=name,
                summary=description or "",
                schema_version="v1",
                tags_json=[],
                status="draft",
                version=1,
                visibility="team",
                author=identity,
                custodian=identity,
                source_ref_type="Blueprint",
                source_ref_id=str(blueprint.id),
                parent_artifact=parent_artifact,
                lineage_root=(parent_artifact.lineage_root or parent_artifact) if parent_artifact else None,
                scope_json={"namespace": namespace, "name": blueprint.name, "fqn": f"{namespace}.{blueprint.name}"},
                provenance_json={"source_system": "xyn", "source_model": "Blueprint", "source_id": str(blueprint.id)},
            )
            if not artifact.lineage_root_id:
                artifact.lineage_root = artifact
                artifact.save(update_fields=["lineage_root", "updated_at"])
            blueprint.artifact = artifact
            blueprint.blueprint_family_id = family_id
            blueprint.save(update_fields=["artifact", "blueprint_family_id", "updated_at"])
        else:
            artifact = ensure_blueprint_artifact(blueprint, owner_user=request.user, parent_artifact=parent_artifact)
        emit_ledger_event(
            actor=identity,
            action="artifact.create",
            artifact=artifact,
            summary="Created Blueprint artifact",
            metadata={
                "title": artifact.title,
                "initial_artifact_state": artifact.artifact_state,
                "schema_version": artifact.schema_version,
            },
            dedupe_key=make_dedupe_key("artifact.create", str(artifact.id)),
        )
        if old_source and not created:
            old_artifact = Artifact.objects.get(id=artifact.id)
            old_artifact.title = old_source.name or old_artifact.title
            old_artifact.summary = old_source.description or old_artifact.summary
            diff_payload = compute_artifact_diff(
                old_artifact,
                artifact,
                old_source=old_source,
                new_source=blueprint,
            )
            if diff_payload.get("changed_fields"):
                emit_ledger_event(
                    actor=identity,
                    action="artifact.update",
                    artifact=artifact,
                    summary=f"Updated Blueprint artifact: {', '.join(diff_payload['changed_fields'][:3])}",
                    metadata=diff_payload,
                    dedupe_key=make_dedupe_key("artifact.update", str(artifact.id), diff_payload=diff_payload),
                )

    return JsonResponse({"artifact_id": str(artifact.id), "blueprint_id": str(blueprint.id)})


@csrf_exempt
@login_required
def artifact_canonize_to_blueprint(request: HttpRequest, artifact_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error

    draft_artifact = get_object_or_404(Artifact.objects.select_related("type"), id=artifact_id)
    if draft_artifact.type.slug != "draft_session":
        return JsonResponse({"error": "artifact_type must be draft_session"}, status=400)
    if draft_artifact.source_ref_type != "BlueprintDraftSession" or not draft_artifact.source_ref_id:
        return JsonResponse({"error": "artifact source is not a draft session"}, status=400)

    session = BlueprintDraftSession.objects.filter(id=draft_artifact.source_ref_id).first()
    if not session:
        return JsonResponse({"error": "draft session not found"}, status=404)
    identity = _identity_from_user(request.user)

    payload = _parse_json(request)
    title = str(payload.get("title") or session.title or session.name or "").strip()
    if not title:
        title = "untitled-blueprint"
    name = str(payload.get("name") or slugify(title) or f"blueprint-{session.id.hex[:8]}").strip()
    namespace = str(payload.get("namespace") or session.namespace or "core").strip() or "core"
    description = str(payload.get("description") or session.requirements_summary or "").strip()
    spec_text = ""
    if isinstance(session.current_draft_json, dict) and session.current_draft_json:
        spec_text = json.dumps(session.current_draft_json, indent=2, ensure_ascii=False)
    elif session.current_draft_json:
        spec_text = str(session.current_draft_json)
    metadata_json = session.metadata_json if isinstance(session.metadata_json, dict) else {}

    with transaction.atomic():
        blueprint, created = Blueprint.objects.get_or_create(
            name=name,
            namespace=namespace,
            defaults={
                "description": description,
                "spec_text": spec_text,
                "metadata_json": metadata_json,
                "created_by": request.user,
                "updated_by": request.user,
            },
        )
        if not created:
            blueprint.description = description or blueprint.description
            if spec_text:
                blueprint.spec_text = spec_text
            if metadata_json:
                blueprint.metadata_json = metadata_json
            blueprint.updated_by = request.user
            blueprint.save(update_fields=["description", "spec_text", "metadata_json", "updated_by", "updated_at"])
        blueprint_artifact = ensure_blueprint_artifact(
            blueprint,
            owner_user=request.user,
            parent_artifact=draft_artifact,
        )
        emit_ledger_event(
            actor=identity,
            action="artifact.create",
            artifact=blueprint_artifact,
            summary="Created Blueprint artifact",
            metadata={
                "title": blueprint_artifact.title,
                "initial_artifact_state": blueprint_artifact.artifact_state,
                "schema_version": blueprint_artifact.schema_version,
            },
            dedupe_key=make_dedupe_key("artifact.create", str(blueprint_artifact.id)),
        )
        emit_ledger_event(
            actor=identity,
            action="artifact.canonize",
            artifact=draft_artifact,
            summary="Canonized Draft Session into Blueprint",
            metadata={
                "blueprint_artifact_id": str(blueprint_artifact.id),
                "blueprint_source_ref_id": str(blueprint.id),
                "link": {
                    "from_artifact_id": str(draft_artifact.id),
                    "to_artifact_id": str(blueprint_artifact.id),
                },
            },
            dedupe_key=make_dedupe_key(
                "artifact.canonize",
                str(draft_artifact.id),
                target_artifact_id=str(blueprint_artifact.id),
            ),
        )
        previous_state = draft_artifact.artifact_state
        draft_artifact.artifact_state = "deprecated"
        draft_artifact.save(update_fields=["artifact_state", "updated_at"])
        if previous_state != "deprecated":
            emit_ledger_event(
                actor=identity,
                action="artifact.deprecate",
                artifact=draft_artifact,
                summary="Deprecated Draft Session artifact",
                metadata={"reason": "canonized_to_blueprint"},
                dedupe_key=make_dedupe_key("artifact.deprecate", str(draft_artifact.id), state="deprecated"),
            )
        session.linked_blueprint = blueprint
        session.save(update_fields=["linked_blueprint", "updated_at"])

    return JsonResponse(
        {
            "blueprint_id": str(blueprint.id),
            "blueprint_artifact_id": str(blueprint_artifact.id),
            "parent_artifact_id": str(draft_artifact.id),
            "lineage_root_id": str(blueprint_artifact.lineage_root_id) if blueprint_artifact.lineage_root_id else None,
        }
    )


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
    previous_state = artifact.artifact_state
    artifact.status = "deprecated"
    artifact.artifact_state = "deprecated"
    artifact.save(update_fields=["status", "artifact_state", "updated_at"])
    _record_artifact_event(artifact, "artifact_deprecated", identity, {})
    if previous_state != "deprecated":
        emit_ledger_event(
            actor=identity,
            action="artifact.deprecate",
            artifact=artifact,
            summary=f"Deprecated {artifact.type.name} artifact",
            metadata={},
            dedupe_key=make_dedupe_key("artifact.deprecate", str(artifact.id), state="deprecated"),
        )
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


def _resolve_article_workspace(identity: UserIdentity, requested_workspace_id: str) -> Optional[Workspace]:
    if requested_workspace_id:
        workspace = Workspace.objects.filter(id=requested_workspace_id).first()
        if not workspace:
            return None
        membership = _workspace_membership(identity, str(workspace.id))
        if membership or _can_manage_articles(identity):
            return workspace
        return None
    default_workspace = Workspace.objects.filter(slug="platform-builder").first() or Workspace.objects.first()
    if default_workspace:
        return default_workspace
    return None


def _resolve_workflow_or_404(workflow_id_or_slug: str) -> Artifact:
    by_id = (
        Artifact.objects.filter(id=workflow_id_or_slug, type__slug=WORKFLOW_ARTIFACT_TYPE_SLUG)
        .select_related("type", "workspace", "article_category", "author")
        .first()
    )
    if by_id:
        return by_id
    by_slug = (
        Artifact.objects.filter(slug=workflow_id_or_slug, type__slug=WORKFLOW_ARTIFACT_TYPE_SLUG)
        .select_related("type", "workspace", "article_category", "author")
        .first()
    )
    if by_slug:
        return by_slug
    return get_object_or_404(Artifact, id=workflow_id_or_slug, type__slug=WORKFLOW_ARTIFACT_TYPE_SLUG)


def _execute_action_blueprint_create_demo_draft(
    *,
    identity: UserIdentity,
    params: Dict[str, Any],
    idempotency_key: str,
) -> Dict[str, Any]:
    namespace = str(params.get("namespace") or "core").strip() or "core"
    project_key = str(params.get("project_key") or "").strip()
    title = str(params.get("title") or "subscriber-notes-demo").strip() or "subscriber-notes-demo"
    initial_prompt = str(params.get("initial_prompt") or "").strip()
    if not project_key:
        suffix = re.sub(r"[^a-z0-9-]+", "-", title.lower()).strip("-") or "demo"
        project_key = f"{namespace}.{suffix}"
    existing = BlueprintDraftSession.objects.filter(metadata_json__workflow_action_idempotency_key=idempotency_key).order_by("-created_at").first()
    if existing:
        return {"resource_id": str(existing.id), "resource_type": "draft_session", "reused": True, "title": existing.title or existing.name}
    context_pack_ids = _recommended_context_pack_ids(
        draft_kind="blueprint",
        namespace=namespace or None,
        project_key=project_key or None,
        generate_code=False,
    )
    session = BlueprintDraftSession.objects.create(
        name=title,
        title=title,
        draft_kind="blueprint",
        blueprint_kind="solution",
        namespace=namespace,
        project_key=project_key,
        initial_prompt=initial_prompt,
        selected_context_pack_ids=context_pack_ids,
        context_pack_ids=context_pack_ids,
        status="drafting",
        metadata_json={"workflow_action_idempotency_key": idempotency_key},
    )
    return {"resource_id": str(session.id), "resource_type": "draft_session", "reused": False, "title": session.title or session.name}


WORKFLOW_ACTION_CATALOG: Dict[str, Dict[str, Any]] = {
    "blueprint.create_demo_draft": {
        "name": "Create demo draft session",
        "description": "Create a draft session for onboarding/workflow tours.",
        "required_permissions": ["platform_admin", "platform_architect"],
        "supports_dry_run": True,
        "idempotent": True,
        "params_schema_json": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "namespace": {"type": "string"},
                "project_key": {"type": "string"},
                "initial_prompt": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "handler": _execute_action_blueprint_create_demo_draft,
    }
}


def _validate_action_params(schema: Dict[str, Any], params: Dict[str, Any]) -> Optional[str]:
    if schema.get("type") == "object" and not isinstance(params, dict):
        return "params must be an object"
    allowed = set((schema.get("properties") or {}).keys())
    for key in params.keys():
        if key not in allowed:
            return f"unsupported param: {key}"
    return None


@csrf_exempt
def workflows_actions_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _can_manage_articles(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    rows = []
    for action_id, meta in sorted(WORKFLOW_ACTION_CATALOG.items()):
        rows.append(
            {
                "action_id": action_id,
                "name": meta.get("name"),
                "description": meta.get("description"),
                "params_schema_json": meta.get("params_schema_json") or {},
                "required_permissions": meta.get("required_permissions") or [],
                "supports_dry_run": bool(meta.get("supports_dry_run")),
                "idempotent": bool(meta.get("idempotent")),
            }
        )
    return JsonResponse({"actions": rows})


@csrf_exempt
def workflows_actions_execute(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _can_manage_articles(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    action_id = str(payload.get("action_id") or "").strip()
    if action_id not in WORKFLOW_ACTION_CATALOG:
        return JsonResponse({"error": "unknown action_id"}, status=404)
    action_meta = WORKFLOW_ACTION_CATALOG[action_id]
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    validation_error = _validate_action_params(action_meta.get("params_schema_json") or {}, params)
    if validation_error:
        return JsonResponse({"error": validation_error}, status=400)
    dry_run = bool(payload.get("dry_run"))
    idempotency_key = str(payload.get("idempotency_key") or "").strip() or f"{action_id}:{_normalized_json_hash(params)}"
    if dry_run and action_meta.get("supports_dry_run"):
        return JsonResponse({"ok": True, "dry_run": True, "action_id": action_id, "idempotency_key": idempotency_key})
    handler = action_meta.get("handler")
    if not callable(handler):
        return JsonResponse({"error": "action handler unavailable"}, status=500)
    try:
        result = handler(identity=identity, params=params, idempotency_key=idempotency_key)
    except Exception as exc:
        return JsonResponse({"error": str(exc) or "action execution failed"}, status=500)
    return JsonResponse({"ok": True, "action_id": action_id, "idempotency_key": idempotency_key, "result": result})


@csrf_exempt
def workflows_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    workflow_type = _ensure_workflow_artifact_type()
    if request.method == "POST":
        if not _can_manage_articles(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        title = str(payload.get("title") or "").strip()
        if not title:
            return JsonResponse({"error": "title is required"}, status=400)
        workspace = _resolve_article_workspace(identity, str(payload.get("workspace_id") or "").strip())
        if not workspace:
            return JsonResponse({"error": "workspace not found or forbidden"}, status=404)
        slug = _normalize_artifact_slug(str(payload.get("slug") or ""), fallback_title=title)
        if not slug:
            return JsonResponse({"error": "slug is required"}, status=400)
        if _artifact_slug_exists(str(workspace.id), slug):
            return JsonResponse({"error": "slug already exists in this workspace"}, status=400)
        profile = _normalize_workflow_profile(payload.get("profile"), fallback="tour")
        category_slug = _normalize_article_category(payload.get("category_slug") or payload.get("category"), fallback=WORKFLOW_DEFAULT_CATEGORY)
        category = _resolve_article_category_slug(category_slug, allow_disabled=True)
        if not category:
            return JsonResponse({"error": f"unknown category: {category_slug}"}, status=400)
        visibility_type = _normalize_article_visibility_type(payload.get("visibility_type"), fallback="private")
        allowed_roles = _normalize_role_slugs(payload.get("allowed_roles"))
        spec_input = payload.get("workflow_spec_json") if isinstance(payload.get("workflow_spec_json"), dict) else {}
        spec = _normalize_workflow_spec(spec_input, profile=profile, title=title, category_slug=category.slug)
        errors = _validate_workflow_spec(spec, profile=profile)
        if errors:
            return JsonResponse({"error": "invalid workflow_spec_json", "details": errors}, status=400)
        with transaction.atomic():
            artifact = Artifact.objects.create(
                workspace=workspace,
                type=workflow_type,
                title=title,
                slug=slug,
                format="workflow",
                status="draft",
                version=1,
                author=identity,
                custodian=identity,
                visibility=_artifact_visibility_for_article_type(visibility_type),
                scope_json={
                    "slug": slug,
                    "category": category.slug,
                    "visibility_type": visibility_type,
                    "allowed_roles": allowed_roles,
                    "tags": _normalize_doc_tags(payload.get("tags")),
                },
                article_category=category,
                workflow_profile=profile,
                workflow_spec_json=spec,
                workflow_state_schema_version=int(spec.get("schema_version") or WORKFLOW_SCHEMA_VERSION),
            )
            _record_artifact_event(artifact, "workflow_created", identity, {"profile": profile, "category": category.slug})
        return JsonResponse({"workflow": _serialize_workflow_detail(artifact)})

    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    profile_filter = _normalize_workflow_profile(request.GET.get("profile"), fallback="")
    category_filter = str(request.GET.get("category") or "").strip().lower()
    status_filter = str(request.GET.get("status") or "").strip().lower()
    query = str(request.GET.get("q") or "").strip().lower()
    include_unpublished = request.GET.get("include_unpublished") == "1"
    workspace_id = str(request.GET.get("workspace_id") or "").strip()
    qs = Artifact.objects.filter(type=workflow_type).select_related("type", "workspace", "article_category")
    if workspace_id:
        qs = qs.filter(workspace_id=workspace_id)
    rows: List[Dict[str, Any]] = []
    for artifact in qs.order_by("-updated_at", "-created_at"):
        if not include_unpublished and artifact.status != "published":
            continue
        if status_filter and artifact.status != status_filter:
            continue
        if not _can_view_workflow(identity, artifact):
            continue
        spec = artifact.workflow_spec_json if isinstance(artifact.workflow_spec_json, dict) else {}
        profile = str(artifact.workflow_profile or spec.get("profile") or "").strip().lower()
        if profile_filter and profile != profile_filter:
            continue
        category_slug = _article_category(artifact)
        if category_filter and category_slug != category_filter:
            continue
        serialized = _serialize_workflow_summary(artifact)
        if query:
            haystack = f"{serialized.get('title', '')} {serialized.get('slug', '')} {serialized.get('description', '')}".lower()
            if query not in haystack:
                continue
        rows.append(serialized)
    return JsonResponse({"workflows": rows})


@csrf_exempt
def workflow_detail(request: HttpRequest, workflow_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_workflow_or_404(workflow_id)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if not _can_view_workflow(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    return JsonResponse({"workflow": _serialize_workflow_detail(artifact)})


@csrf_exempt
def workflow_spec_update(request: HttpRequest, workflow_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_workflow_or_404(workflow_id)
    if not _can_edit_workflow(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    if request.method not in {"PUT", "PATCH"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    profile = _normalize_workflow_profile(payload.get("profile"), fallback=artifact.workflow_profile or "tour")
    spec_input = payload.get("workflow_spec_json") if isinstance(payload.get("workflow_spec_json"), dict) else (artifact.workflow_spec_json or {})
    category_slug = _normalize_article_category(payload.get("category_slug") or _article_category(artifact), fallback=WORKFLOW_DEFAULT_CATEGORY)
    category = _resolve_article_category_slug(category_slug, allow_disabled=True)
    if not category:
        return JsonResponse({"error": f"unknown category: {category_slug}"}, status=400)
    next_title = str(payload.get("title") or artifact.title).strip() or artifact.title
    next_slug = _normalize_artifact_slug(payload.get("slug"), fallback_title=next_title) if "slug" in payload else _artifact_slug(artifact)
    if next_slug and next_slug != _artifact_slug(artifact) and _artifact_slug_exists(str(artifact.workspace_id), next_slug):
        return JsonResponse({"error": "slug already exists in this workspace"}, status=400)
    spec = _normalize_workflow_spec(spec_input, profile=profile, title=next_title, category_slug=category.slug)
    errors = _validate_workflow_spec(spec, profile=profile)
    if errors:
        return JsonResponse({"error": "invalid workflow_spec_json", "details": errors}, status=400)
    artifact.title = next_title
    artifact.slug = next_slug or ""
    artifact.workflow_profile = profile
    artifact.workflow_spec_json = spec
    artifact.workflow_state_schema_version = int(spec.get("schema_version") or WORKFLOW_SCHEMA_VERSION)
    scope = dict(artifact.scope_json or {})
    scope["category"] = category.slug
    if "visibility_type" in payload:
        visibility_type = _normalize_article_visibility_type(payload.get("visibility_type"), fallback=_workflow_visibility_type_from_artifact(artifact))
        scope["visibility_type"] = visibility_type
        artifact.visibility = _artifact_visibility_for_article_type(visibility_type)
    if "allowed_roles" in payload:
        scope["allowed_roles"] = _normalize_role_slugs(payload.get("allowed_roles"))
    if "tags" in payload:
        scope["tags"] = _normalize_doc_tags(payload.get("tags"))
    artifact.scope_json = scope
    artifact.article_category = category
    artifact.version += 1
    artifact.save(
        update_fields=[
            "title",
            "slug",
            "workflow_profile",
            "workflow_spec_json",
            "workflow_state_schema_version",
            "scope_json",
            "article_category",
            "visibility",
            "version",
            "updated_at",
        ]
    )
    _record_artifact_event(artifact, "workflow_updated", identity, {"profile": profile, "version": artifact.version})
    return JsonResponse({"workflow": _serialize_workflow_detail(artifact)})


@csrf_exempt
def workflow_transition(request: HttpRequest, workflow_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _can_manage_articles(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    artifact = _resolve_workflow_or_404(workflow_id)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    to_status = str(payload.get("to_status") or "").strip().lower()
    if to_status not in ARTICLE_STATUS_CHOICES:
        return JsonResponse({"error": "invalid status"}, status=400)
    from_status = artifact.status
    if to_status == from_status:
        return JsonResponse({"workflow": _serialize_workflow_detail(artifact)})
    allowed = ARTICLE_TRANSITIONS.get(from_status, set())
    if to_status not in allowed:
        return JsonResponse({"error": f"invalid transition: {from_status} -> {to_status}"}, status=400)
    artifact.status = to_status
    artifact.artifact_state = _artifact_state_for_status(to_status)
    update_fields = ["status", "artifact_state", "updated_at"]
    if to_status == "published":
        validation_status, validation_errors = validate_artifact(artifact)
        content_hash = compute_content_hash(artifact)
        artifact.content_hash = content_hash
        artifact.validation_status = validation_status
        artifact.validation_errors_json = validation_errors or []
        update_fields.extend(["content_hash", "validation_status", "validation_errors_json"])
        if validation_status == "fail":
            return JsonResponse(
                {"error": "artifact validation failed", "validation_status": validation_status, "validation_errors": validation_errors},
                status=400,
            )
        artifact.published_at = timezone.now()
        artifact.ratified_by = identity
        artifact.ratified_at = timezone.now()
        update_fields.extend(["published_at", "ratified_by", "ratified_at"])
    artifact.save(update_fields=list(dict.fromkeys(update_fields)))
    _record_artifact_event(artifact, "workflow_status_changed", identity, {"from": from_status, "to": to_status})
    if to_status == "published":
        emit_ledger_event(
            actor=identity,
            action="artifact.update",
            artifact=artifact,
            summary="Published Workflow artifact",
            metadata={
                "validation_status": artifact.validation_status,
                "content_hash": artifact.content_hash,
                "status": "published",
            },
            dedupe_key=make_dedupe_key(
                "artifact.update",
                str(artifact.id),
                diff_payload={
                    "validation_status": artifact.validation_status,
                    "content_hash": artifact.content_hash,
                    "status": "published",
                },
            ),
        )
    return JsonResponse({"workflow": _serialize_workflow_detail(artifact)})


def _serialize_workflow_run(run: WorkflowRun) -> Dict[str, Any]:
    return {
        "id": str(run.id),
        "workflow_id": str(run.workflow_artifact_id),
        "user_id": str(run.user_id) if run.user_id else None,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "metadata_json": run.metadata_json or {},
    }


@csrf_exempt
def workflow_run_start(request: HttpRequest, workflow_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_workflow_or_404(workflow_id)
    if not _can_view_workflow(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    run = WorkflowRun.objects.create(
        workflow_artifact=artifact,
        user=identity,
        status="running",
        metadata_json={"started_from": str(payload.get("started_from") or "ui"), "user_agent": request.META.get("HTTP_USER_AGENT", "")[:256]},
    )
    WorkflowRunEvent.objects.create(run=run, event_type="run_started", payload_json={"at": timezone.now().isoformat()})
    return JsonResponse({"run": _serialize_workflow_run(run)})


@csrf_exempt
def workflow_run_event(request: HttpRequest, workflow_id: str, run_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_workflow_or_404(workflow_id)
    if not _can_view_workflow(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    run = get_object_or_404(WorkflowRun, id=run_id, workflow_artifact=artifact)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    step_id = str(payload.get("step_id") or "").strip()
    event_type = str(payload.get("type") or payload.get("event_type") or "event").strip().lower()
    details = payload.get("payload_json") if isinstance(payload.get("payload_json"), dict) else payload
    event = WorkflowRunEvent.objects.create(run=run, step_id=step_id, event_type=event_type, payload_json=details or {})
    return JsonResponse({"event_id": str(event.id)})


@csrf_exempt
def workflow_run_complete(request: HttpRequest, workflow_id: str, run_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_workflow_or_404(workflow_id)
    if not _can_view_workflow(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    run = get_object_or_404(WorkflowRun, id=run_id, workflow_artifact=artifact)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    status = str(payload.get("status") or "completed").strip().lower()
    if status not in {"completed", "failed", "aborted"}:
        return JsonResponse({"error": "invalid status"}, status=400)
    run.status = status
    run.completed_at = timezone.now()
    run.save(update_fields=["status", "completed_at"])
    WorkflowRunEvent.objects.create(run=run, event_type="run_completed", payload_json={"status": status})
    return JsonResponse({"run": _serialize_workflow_run(run)})


@csrf_exempt
def articles_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    article_type = _ensure_article_artifact_type()

    if request.method == "POST":
        if not _can_manage_articles(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        title = str(payload.get("title") or "").strip()
        if not title:
            return JsonResponse({"error": "title is required"}, status=400)
        workspace_id = str(payload.get("workspace_id") or "").strip()
        workspace = _resolve_article_workspace(identity, workspace_id)
        if not workspace:
            return JsonResponse({"error": "workspace not found or forbidden"}, status=404)
        slug = _normalize_artifact_slug(str(payload.get("slug") or ""), fallback_title=title)
        if not slug:
            return JsonResponse({"error": "slug is required"}, status=400)
        if _artifact_slug_exists(str(workspace.id), slug):
            return JsonResponse({"error": "slug already exists in this workspace"}, status=400)
        category_slug = _normalize_article_category(payload.get("category_slug") or payload.get("category"), fallback="web")
        category = _resolve_article_category_slug(category_slug, allow_disabled=True)
        if not category:
            return JsonResponse({"error": f"unknown category: {category_slug}"}, status=400)
        visibility_type = _normalize_article_visibility_type(payload.get("visibility_type"), fallback="private")
        article_format = _normalize_article_format(payload.get("format"), fallback="standard")
        allowed_roles = _normalize_role_slugs(payload.get("allowed_roles"))
        if visibility_type == "role_based" and not allowed_roles:
            return JsonResponse({"error": "allowed_roles is required for role_based visibility"}, status=400)
        invalid_roles = [role for role in allowed_roles if role not in PLATFORM_ROLE_IDS and role not in WORKSPACE_ROLE_SLUGS]
        if invalid_roles:
            return JsonResponse({"error": f"invalid allowed_roles: {', '.join(sorted(set(invalid_roles)))}"}, status=400)
        route_bindings = _normalize_doc_route_bindings(payload.get("route_bindings"))
        tags = _normalize_doc_tags(payload.get("tags"))
        summary = str(payload.get("summary") or "")
        body_markdown = str(payload.get("body_markdown") or "")
        body_html = str(payload.get("body_html") or "")
        status = str(payload.get("status") or "draft").strip().lower()
        if status not in ARTICLE_STATUS_CHOICES:
            return JsonResponse({"error": "invalid status"}, status=400)
        requested_video_pack = payload.get("video_context_pack_id") if "video_context_pack_id" in payload else None
        video_context_pack, pack_error = _resolve_video_context_pack_for_article(
            None,
            requested_video_pack,
            allow_clear=True,
        )
        if pack_error:
            return pack_error
        candidate_video_spec = payload.get("video_spec_json") if isinstance(payload.get("video_spec_json"), dict) else None
        candidate_video_ai_config = payload.get("video_ai_config_json") if isinstance(payload.get("video_ai_config_json"), dict) else None
        if candidate_video_spec is not None:
            spec_errors = validate_video_spec(candidate_video_spec, require_scenes=article_format == "video_explainer")
            if spec_errors:
                return JsonResponse({"error": "invalid video_spec_json", "details": spec_errors}, status=400)
        published_at = timezone.now() if status == "published" else None
        scaffold_quality = "none"
        if article_format == "video_explainer":
            generation_fields = _extract_explainer_generation_fields(
                title=title,
                intent=str(payload.get("intent") or ""),
                summary=summary,
                description=str(payload.get("description") or body_markdown or summary),
                audience=str(payload.get("audience") or ""),
                category=category.slug,
            )
            if candidate_video_spec is not None:
                final_video_spec = candidate_video_spec
                scaffold_quality = "provided"
            else:
                final_video_spec, scaffold_quality = _build_explainer_video_spec(
                    title=title,
                    summary=summary,
                    intent=generation_fields.get("topic") or str(payload.get("intent") or summary or title),
                    topic=generation_fields.get("topic") or "",
                    grounding=generation_fields.get("grounding") or "",
                    category=generation_fields.get("category") or "",
                    duration=str(payload.get("duration") or ""),
                    audience=generation_fields.get("audience") or "",
                    description=str(payload.get("description") or body_markdown or summary),
                )
        else:
            final_video_spec = None
        initial_summary = summary
        initial_body_markdown = body_markdown
        if article_format == "video_explainer" and isinstance(final_video_spec, dict):
            initial_summary, initial_body_markdown = _derive_explainer_initial_content(
                title=title,
                summary=summary,
                body_markdown=body_markdown,
                scenes=final_video_spec.get("scenes") if isinstance(final_video_spec.get("scenes"), list) else [],
            )
        with transaction.atomic():
            artifact = Artifact.objects.create(
                workspace=workspace,
                type=article_type,
                title=title,
                slug=slug,
                format=article_format,
                status=status,
                version=1,
                visibility=_artifact_visibility_for_article_type(visibility_type),
                author=identity,
                custodian=identity,
                published_at=published_at,
                ratified_by=identity if status in {"ratified", "published"} else None,
                ratified_at=timezone.now() if status in {"ratified", "published"} else None,
                scope_json={
                    "slug": slug,
                    "category": category.slug,
                    "visibility_type": visibility_type,
                    "allowed_roles": allowed_roles,
                    "route_bindings": route_bindings,
                    "tags": tags,
                    "cover_image_url": str(payload.get("cover_image_url") or ""),
                    "canonical_url": str(payload.get("canonical_url") or ""),
                    "license_json": payload.get("license_json") if isinstance(payload.get("license_json"), dict) else {},
                },
                provenance_json=payload.get("provenance_json") if isinstance(payload.get("provenance_json"), dict) else {},
                video_spec_json=final_video_spec,
                video_ai_config_json=candidate_video_ai_config if article_format == "video_explainer" else None,
                video_context_pack=video_context_pack if article_format == "video_explainer" else None,
                article_category=category,
            )
            ArtifactRevision.objects.create(
                artifact=artifact,
                revision_number=1,
                content_json={
                    "title": title,
                    "summary": initial_summary,
                    "body_markdown": initial_body_markdown,
                    "body_html": body_html,
                    "tags": tags,
                    "provenance_json": payload.get("revision_provenance_json")
                    if isinstance(payload.get("revision_provenance_json"), dict)
                    else {},
                },
                created_by=identity,
            )
            ArtifactExternalRef.objects.update_or_create(
                artifact=artifact,
                system="shine",
                defaults={"external_id": str(artifact.id), "slug_path": slug},
            )
            _record_artifact_event(
                artifact,
                "article_created",
                identity,
                {
                    "category": category.slug,
                    "visibility_type": visibility_type,
                    "status": status,
                    "format": article_format,
                    "video_context_pack_id": str(video_context_pack.id) if video_context_pack else None,
                },
            )
            if article_format == "video_explainer" and isinstance(final_video_spec, dict):
                emit_ledger_event(
                    actor=identity,
                    action="draft.scaffolded",
                    artifact=artifact,
                    summary="Generated initial explainer scenes scaffold",
                    metadata={
                        "scene_count": len(final_video_spec.get("scenes") or []) if isinstance(final_video_spec.get("scenes"), list) else 0,
                        "scaffold_quality": scaffold_quality,
                    },
                    dedupe_key=f"draft.scaffolded:{artifact.id}",
                )
            for route in route_bindings:
                value = str(route or "").strip()
                if not value:
                    continue
                PublishBinding.objects.get_or_create(
                    scope_type="article",
                    scope_id=artifact.id,
                    target_type="xyn_ui_route",
                    target_value=value,
                    defaults={"label": "Route", "enabled": True},
                )
        return JsonResponse({"article": _serialize_article_detail(artifact)})

    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    qs = Artifact.objects.filter(type=article_type).select_related("type", "workspace", "author")
    workspace_id = str(request.GET.get("workspace_id") or "").strip()
    if workspace_id:
        qs = qs.filter(workspace_id=workspace_id)
    status = str(request.GET.get("status") or "").strip().lower()
    if status:
        qs = qs.filter(status=status)
    category_filter = str(request.GET.get("category") or "").strip().lower()
    visibility_filter = str(request.GET.get("visibility") or "").strip().lower()
    route_id = str(request.GET.get("route_id") or "").strip()
    query = str(request.GET.get("q") or "").strip().lower()
    include_unpublished = request.GET.get("include_unpublished") == "1"
    results: list[dict[str, Any]] = []
    for artifact in qs.order_by("-published_at", "-updated_at", "-created_at"):
        if not include_unpublished and not _can_manage_articles(identity) and artifact.status != "published":
            continue
        if not _can_view_article(identity, artifact):
            continue
        category = _article_category(artifact)
        if category_filter and category != category_filter:
            continue
        visibility_type = _article_visibility_type_from_artifact(artifact)
        if visibility_filter and visibility_type != visibility_filter:
            continue
        bindings = _article_route_bindings(artifact)
        if route_id and route_id not in bindings:
            continue
        serialized = _serialize_article_summary(artifact)
        if query:
            haystack = " ".join(
                [
                    serialized.get("title", ""),
                    serialized.get("slug", ""),
                    serialized.get("summary", ""),
                    " ".join(serialized.get("tags") or []),
                ]
            ).lower()
            if query not in haystack:
                continue
        results.append(serialized)
    return JsonResponse({"articles": results})


def _serialize_article_category(category: ArticleCategory) -> Dict[str, Any]:
    referenced_count = Artifact.objects.filter(article_category=category, type__slug=ARTICLE_ARTIFACT_TYPE_SLUG).count()
    return {
        "id": str(category.id),
        "slug": category.slug,
        "name": category.name,
        "description": category.description or "",
        "enabled": bool(category.enabled),
        "referenced_article_count": referenced_count,
        "created_at": category.created_at,
        "updated_at": category.updated_at,
        "references": {
            "articles": referenced_count,
        },
    }


def _serialize_publish_binding(binding: PublishBinding, *, source: str) -> Dict[str, Any]:
    return {
        "id": str(binding.id),
        "label": binding.label,
        "target_type": binding.target_type,
        "target_value": binding.target_value,
        "enabled": bool(binding.enabled),
        "source": source,
        "created_at": binding.created_at,
        "updated_at": binding.updated_at,
    }


def _validate_publish_binding_payload(payload: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], Optional[JsonResponse]]:
    target_type = str(payload.get("target_type") or "").strip()
    target_value = str(payload.get("target_value") or "").strip()
    label = str(payload.get("label") or "").strip()
    enabled = bool(payload.get("enabled", True))
    if not label:
        return None, JsonResponse({"error": "label is required"}, status=400)
    if not _is_valid_binding_target(target_type, target_value):
        return None, JsonResponse({"error": "invalid target_type/target_value"}, status=400)
    return {"target_type": target_type, "target_value": target_value, "label": label, "enabled": enabled}, None


@csrf_exempt
def article_categories_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    _ensure_default_article_categories_and_bindings()
    if request.method == "POST":
        if not _can_manage_articles(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        slug = str(payload.get("slug") or "").strip().lower()
        name = str(payload.get("name") or "").strip()
        if not slug or not ARTICLE_CATEGORY_SLUG_PATTERN.match(slug):
            return JsonResponse({"error": "invalid slug"}, status=400)
        if not name:
            return JsonResponse({"error": "name is required"}, status=400)
        if ArticleCategory.objects.filter(slug=slug).exists():
            return JsonResponse({"error": "slug already exists"}, status=400)
        category = ArticleCategory.objects.create(
            slug=slug,
            name=name,
            description=str(payload.get("description") or ""),
            enabled=bool(payload.get("enabled", True)),
        )
        return JsonResponse({"category": _serialize_article_category(category)})

    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    categories = [_serialize_article_category(item) for item in ArticleCategory.objects.all().order_by("name")]
    return JsonResponse({"categories": categories})


@csrf_exempt
def article_category_detail(request: HttpRequest, category_slug: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    category = get_object_or_404(ArticleCategory, slug=category_slug)
    if request.method in {"PATCH", "PUT"}:
        if not _can_manage_articles(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        if "slug" in payload and str(payload.get("slug") or "").strip().lower() != category.slug:
            return JsonResponse({"error": "Category slug is immutable. Create a new category instead."}, status=400)
        dirty: list[str] = []
        if "name" in payload:
            name = str(payload.get("name") or "").strip()
            if not name:
                return JsonResponse({"error": "name is required"}, status=400)
            category.name = name
            dirty.append("name")
        if "description" in payload:
            category.description = str(payload.get("description") or "")
            dirty.append("description")
        if "enabled" in payload:
            category.enabled = bool(payload.get("enabled"))
            dirty.append("enabled")
        if dirty:
            category.save(update_fields=dirty + ["updated_at"])
        return JsonResponse({"category": _serialize_article_category(category)})

    if request.method == "DELETE":
        if not _can_manage_articles(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        count = Artifact.objects.filter(article_category=category, type__slug=ARTICLE_ARTIFACT_TYPE_SLUG).count()
        if count:
            return JsonResponse(
                {
                    "error": "category_in_use",
                    "message": f"Category is referenced by {count} articles and cannot be deleted. Deprecate it instead.",
                    "referenced_by": {"articles": count},
                },
                status=409,
            )
        category.delete()
        return HttpResponse(status=204)

    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    return JsonResponse({"category": _serialize_article_category(category)})


@csrf_exempt
def article_category_bindings_collection(request: HttpRequest, category_slug: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    category = get_object_or_404(ArticleCategory, slug=category_slug)
    if request.method == "POST":
        if not _can_manage_articles(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        normalized, error = _validate_publish_binding_payload(payload)
        if error:
            return error
        binding = PublishBinding.objects.create(
            scope_type="category",
            scope_id=category.id,
            target_type=normalized["target_type"],
            target_value=normalized["target_value"],
            label=normalized["label"],
            enabled=normalized["enabled"],
        )
        return JsonResponse({"binding": _serialize_publish_binding(binding, source="category")})
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    bindings = PublishBinding.objects.filter(scope_type="category", scope_id=category.id).order_by("label", "target_value")
    return JsonResponse({"bindings": [_serialize_publish_binding(item, source="category") for item in bindings]})


@csrf_exempt
def article_category_binding_detail(request: HttpRequest, category_slug: str, binding_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    category = get_object_or_404(ArticleCategory, slug=category_slug)
    binding = get_object_or_404(PublishBinding, id=binding_id, scope_type="category", scope_id=category.id)
    if request.method in {"PATCH", "PUT"}:
        if not _can_manage_articles(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        dirty: list[str] = []
        if "label" in payload:
            label = str(payload.get("label") or "").strip()
            if not label:
                return JsonResponse({"error": "label is required"}, status=400)
            binding.label = label
            dirty.append("label")
        target_type = str(payload.get("target_type") or binding.target_type)
        target_value = str(payload.get("target_value") or binding.target_value)
        if "target_type" in payload or "target_value" in payload:
            if not _is_valid_binding_target(target_type, target_value):
                return JsonResponse({"error": "invalid target_type/target_value"}, status=400)
            binding.target_type = target_type
            binding.target_value = target_value
            dirty.extend(["target_type", "target_value"])
        if "enabled" in payload:
            binding.enabled = bool(payload.get("enabled"))
            dirty.append("enabled")
        if dirty:
            binding.save(update_fields=sorted(set(dirty + ["updated_at"])))
        return JsonResponse({"binding": _serialize_publish_binding(binding, source="category")})
    if request.method == "DELETE":
        if not _can_manage_articles(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        binding.delete()
        return JsonResponse({"ok": True})
    return JsonResponse({"error": "method not allowed"}, status=405)


@csrf_exempt
def article_bindings_collection(request: HttpRequest, article_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if request.method == "POST":
        if not _can_edit_article(identity, artifact):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        normalized, error = _validate_publish_binding_payload(payload)
        if error:
            return error
        binding = PublishBinding.objects.create(
            scope_type="article",
            scope_id=artifact.id,
            target_type=normalized["target_type"],
            target_value=normalized["target_value"],
            label=normalized["label"],
            enabled=normalized["enabled"],
        )
        return JsonResponse({"binding": _serialize_publish_binding(binding, source="article")})
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    category = _article_category_record(artifact)
    category_bindings = []
    if category:
        category_bindings = [
            _serialize_publish_binding(item, source="category")
            for item in PublishBinding.objects.filter(scope_type="category", scope_id=category.id).order_by("label", "target_value")
        ]
    article_bindings = [
        _serialize_publish_binding(item, source="article")
        for item in PublishBinding.objects.filter(scope_type="article", scope_id=artifact.id).order_by("label", "target_value")
    ]
    return JsonResponse({"bindings": article_bindings, "inherited_bindings": category_bindings})


@csrf_exempt
def article_binding_detail(request: HttpRequest, article_id: str, binding_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    binding = get_object_or_404(PublishBinding, id=binding_id, scope_type="article", scope_id=artifact.id)
    if request.method in {"PATCH", "PUT"}:
        if not _can_edit_article(identity, artifact):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        dirty: list[str] = []
        if "label" in payload:
            label = str(payload.get("label") or "").strip()
            if not label:
                return JsonResponse({"error": "label is required"}, status=400)
            binding.label = label
            dirty.append("label")
        target_type = str(payload.get("target_type") or binding.target_type)
        target_value = str(payload.get("target_value") or binding.target_value)
        if "target_type" in payload or "target_value" in payload:
            if not _is_valid_binding_target(target_type, target_value):
                return JsonResponse({"error": "invalid target_type/target_value"}, status=400)
            binding.target_type = target_type
            binding.target_value = target_value
            dirty.extend(["target_type", "target_value"])
        if "enabled" in payload:
            binding.enabled = bool(payload.get("enabled"))
            dirty.append("enabled")
        if dirty:
            binding.save(update_fields=sorted(set(dirty + ["updated_at"])))
        return JsonResponse({"binding": _serialize_publish_binding(binding, source="article")})
    if request.method == "DELETE":
        if not _can_edit_article(identity, artifact):
            return JsonResponse({"error": "forbidden"}, status=403)
        binding.delete()
        return JsonResponse({"ok": True})
    return JsonResponse({"error": "method not allowed"}, status=405)


def _resolve_article_or_404(article_id_or_slug: str) -> Artifact:
    by_id = (
        Artifact.objects.filter(id=article_id_or_slug, type__slug=ARTICLE_ARTIFACT_TYPE_SLUG)
        .select_related("type", "workspace", "article_category", "video_context_pack")
        .first()
    )
    if by_id:
        return by_id
    by_slug = (
        Artifact.objects.filter(slug=article_id_or_slug, type__slug=ARTICLE_ARTIFACT_TYPE_SLUG)
        .select_related("type", "workspace", "article_category", "video_context_pack")
        .first()
    )
    if by_slug:
        return by_slug
    return get_object_or_404(Artifact, id=article_id_or_slug, type__slug=ARTICLE_ARTIFACT_TYPE_SLUG)


def _resolve_context_pack_artifact_or_404(pack_id_or_slug: str) -> Artifact:
    by_id = (
        Artifact.objects.filter(id=pack_id_or_slug, type__slug=CONTEXT_PACK_ARTIFACT_TYPE_SLUG)
        .select_related("type", "workspace")
        .first()
    )
    if by_id:
        return by_id
    by_slug = (
        Artifact.objects.filter(slug=pack_id_or_slug, type__slug=CONTEXT_PACK_ARTIFACT_TYPE_SLUG)
        .select_related("type", "workspace")
        .first()
    )
    if by_slug:
        return by_slug
    by_title = (
        Artifact.objects.filter(title__iexact=pack_id_or_slug, type__slug=CONTEXT_PACK_ARTIFACT_TYPE_SLUG)
        .select_related("type", "workspace")
        .order_by("-updated_at")
        .first()
    )
    if by_title:
        return by_title
    return get_object_or_404(Artifact, id=pack_id_or_slug, type__slug=CONTEXT_PACK_ARTIFACT_TYPE_SLUG)


def _lookup_context_pack_artifact_for_intent(*, message: str, proposal: Dict[str, Any]) -> Optional[Artifact]:
    inferred = proposal.get("inferred_fields") if isinstance(proposal.get("inferred_fields"), dict) else {}
    candidates: List[str] = []
    for key in ("target_id", "target_slug", "slug", "name", "title", "context_pack"):
        raw = str(inferred.get(key) or proposal.get(key) or "").strip()
        if raw:
            candidates.append(raw)
    quoted = re.findall(r"[\"']([^\"']+)[\"']", str(message or ""))
    candidates.extend([item.strip() for item in quoted if str(item or "").strip()])
    phrase_match = re.search(r"context\s*pack\s+([a-zA-Z0-9_.:-]+)", str(message or ""), flags=re.IGNORECASE)
    if phrase_match:
        candidates.append(str(phrase_match.group(1) or "").strip())
    deduped: List[str] = []
    seen: Set[str] = set()
    for candidate in candidates:
        normalized = candidate.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(candidate)

    if not deduped:
        return None
    for candidate in deduped:
        row = (
            Artifact.objects.filter(type__slug=CONTEXT_PACK_ARTIFACT_TYPE_SLUG)
            .filter(Q(id=candidate) | Q(slug=candidate) | Q(title__iexact=candidate))
            .order_by("-updated_at")
            .first()
        )
        if row:
            return row
    return None


@csrf_exempt
def article_detail(request: HttpRequest, article_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if request.method in {"PATCH", "PUT"}:
        if not _can_edit_article(identity, artifact):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        if "body_markdown" in payload or "body_html" in payload:
            return JsonResponse({"error": "body updates must use /revisions endpoint"}, status=400)
        scope = dict(artifact.scope_json or {})
        dirty_fields: set[str] = set()
        if "title" in payload:
            title = str(payload.get("title") or "").strip()
            if not title:
                return JsonResponse({"error": "title is required"}, status=400)
            artifact.title = title
            dirty_fields.add("title")
        if "slug" in payload:
            slug = _normalize_artifact_slug(str(payload.get("slug") or ""), fallback_title=artifact.title)
            if not slug:
                return JsonResponse({"error": "slug is required"}, status=400)
            if _artifact_slug_exists(str(artifact.workspace_id), slug, exclude_artifact_id=str(artifact.id)):
                return JsonResponse({"error": "slug already exists in this workspace"}, status=400)
            artifact.slug = slug
            scope["slug"] = slug
            ArtifactExternalRef.objects.update_or_create(
                artifact=artifact,
                system="shine",
                defaults={"external_id": str(artifact.id), "slug_path": slug},
            )
            dirty_fields.update({"slug", "scope_json"})
        if "category" in payload or "category_slug" in payload:
            next_slug = _normalize_article_category(payload.get("category_slug") or payload.get("category"), fallback=_article_category(artifact))
            category = _resolve_article_category_slug(next_slug, allow_disabled=True)
            if not category:
                return JsonResponse({"error": f"unknown category: {next_slug}"}, status=400)
            artifact.article_category = category
            scope["category"] = category.slug
            dirty_fields.update({"scope_json", "article_category"})
        if "format" in payload:
            artifact.format = _normalize_article_format(payload.get("format"), fallback=_article_format(artifact))
            dirty_fields.add("format")
            if artifact.format == "video_explainer" and not isinstance(artifact.video_spec_json, dict):
                artifact.video_spec_json = _default_video_spec_for_artifact(artifact)
                dirty_fields.add("video_spec_json")
            if artifact.format != "video_explainer" and artifact.video_context_pack_id:
                artifact.video_context_pack = None
                dirty_fields.add("video_context_pack")
        if "video_context_pack_id" in payload:
            next_pack, pack_error = _resolve_video_context_pack_for_article(artifact, payload.get("video_context_pack_id"), allow_clear=True)
            if pack_error:
                return pack_error
            artifact.video_context_pack = next_pack
            dirty_fields.add("video_context_pack")
        if "video_spec_json" in payload:
            candidate = payload.get("video_spec_json")
            if candidate is None:
                artifact.video_spec_json = None
                dirty_fields.add("video_spec_json")
            elif isinstance(candidate, dict):
                require_scenes = artifact.format == "video_explainer" or str(payload.get("format") or "").strip().lower() == "video_explainer"
                spec_errors = validate_video_spec(candidate, require_scenes=require_scenes)
                if spec_errors:
                    return JsonResponse({"error": "invalid video_spec_json", "details": spec_errors}, status=400)
                artifact.video_spec_json = candidate
                dirty_fields.add("video_spec_json")
            else:
                return JsonResponse({"error": "video_spec_json must be an object or null"}, status=400)
        if "video_ai_config_json" in payload:
            candidate_ai_config = payload.get("video_ai_config_json")
            if candidate_ai_config is None:
                artifact.video_ai_config_json = None
                dirty_fields.add("video_ai_config_json")
            elif isinstance(candidate_ai_config, dict):
                artifact.video_ai_config_json = candidate_ai_config
                dirty_fields.add("video_ai_config_json")
            else:
                return JsonResponse({"error": "video_ai_config_json must be an object or null"}, status=400)
        if "visibility_type" in payload:
            visibility_type = _normalize_article_visibility_type(
                payload.get("visibility_type"),
                fallback=_article_visibility_type_from_artifact(artifact),
            )
            allowed_roles = _normalize_role_slugs(payload.get("allowed_roles") if "allowed_roles" in payload else scope.get("allowed_roles"))
            if visibility_type == "role_based" and not allowed_roles:
                return JsonResponse({"error": "allowed_roles is required for role_based visibility"}, status=400)
            invalid_roles = [role for role in allowed_roles if role not in PLATFORM_ROLE_IDS and role not in WORKSPACE_ROLE_SLUGS]
            if invalid_roles:
                return JsonResponse({"error": f"invalid allowed_roles: {', '.join(sorted(set(invalid_roles)))}"}, status=400)
            scope["visibility_type"] = visibility_type
            scope["allowed_roles"] = allowed_roles
            artifact.visibility = _artifact_visibility_for_article_type(visibility_type)
            dirty_fields.update({"scope_json", "visibility"})
        elif "allowed_roles" in payload:
            allowed_roles = _normalize_role_slugs(payload.get("allowed_roles"))
            invalid_roles = [role for role in allowed_roles if role not in PLATFORM_ROLE_IDS and role not in WORKSPACE_ROLE_SLUGS]
            if invalid_roles:
                return JsonResponse({"error": f"invalid allowed_roles: {', '.join(sorted(set(invalid_roles)))}"}, status=400)
            scope["allowed_roles"] = allowed_roles
            dirty_fields.add("scope_json")
        if "route_bindings" in payload:
            route_bindings = _normalize_doc_route_bindings(payload.get("route_bindings"))
            scope["route_bindings"] = route_bindings
            existing = PublishBinding.objects.filter(scope_type="article", scope_id=artifact.id, target_type="xyn_ui_route")
            existing_values = {row.target_value: row for row in existing}
            requested = set(route_bindings)
            for value, row in existing_values.items():
                if value not in requested:
                    row.enabled = False
                    row.save(update_fields=["enabled", "updated_at"])
            for value in requested:
                PublishBinding.objects.update_or_create(
                    scope_type="article",
                    scope_id=artifact.id,
                    target_type="xyn_ui_route",
                    target_value=value,
                    defaults={"label": "Route", "enabled": True},
                )
            dirty_fields.add("scope_json")
        if "tags" in payload:
            scope["tags"] = _normalize_doc_tags(payload.get("tags"))
            dirty_fields.add("scope_json")
        if "cover_image_url" in payload:
            scope["cover_image_url"] = str(payload.get("cover_image_url") or "")
            dirty_fields.add("scope_json")
        if "canonical_url" in payload:
            scope["canonical_url"] = str(payload.get("canonical_url") or "")
            dirty_fields.add("scope_json")
        if "license_json" in payload and isinstance(payload.get("license_json"), dict):
            scope["license_json"] = payload.get("license_json")
            dirty_fields.add("scope_json")
        if dirty_fields:
            artifact.scope_json = scope
            dirty_fields.add("updated_at")
            artifact.save(update_fields=sorted(dirty_fields))
            _record_artifact_event(artifact, "article_metadata_updated", identity, {"fields": sorted(dirty_fields)})
    if not _can_view_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    return JsonResponse({"article": _serialize_article_detail(artifact)})


@csrf_exempt
def article_revisions_collection(request: HttpRequest, article_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if request.method == "POST":
        if not _can_edit_article(identity, artifact):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        body_markdown = str(payload.get("body_markdown") or "")
        body_html = str(payload.get("body_html") or "")
        if not body_markdown and not body_html:
            return JsonResponse({"error": "body_markdown or body_html is required"}, status=400)
        latest = _latest_artifact_revision(artifact)
        content = dict((latest.content_json if latest else {}) or {})
        content["title"] = str(payload.get("title") or content.get("title") or artifact.title)
        content["summary"] = str(payload.get("summary") or content.get("summary") or "")
        if "tags" in payload:
            content["tags"] = _normalize_doc_tags(payload.get("tags"))
        if "body_markdown" in payload:
            content["body_markdown"] = body_markdown
        if "body_html" in payload:
            content["body_html"] = body_html
        provenance_json = payload.get("provenance_json") if isinstance(payload.get("provenance_json"), dict) else {}
        content["provenance_json"] = provenance_json
        revision_no = _next_artifact_revision_number(artifact)
        with transaction.atomic():
            revision = ArtifactRevision.objects.create(
                artifact=artifact,
                revision_number=revision_no,
                content_json=content,
                created_by=identity,
            )
            artifact.version = revision_no
            if content.get("title"):
                artifact.title = str(content.get("title"))
            artifact.save(update_fields=["version", "title", "updated_at"])
            _record_artifact_event(
                artifact,
                "article_revision_created",
                identity,
                {"revision_number": revision_no, "source": str(payload.get("source") or "manual")},
            )
            if provenance_json.get("agent_slug"):
                _record_artifact_event(
                    artifact,
                    "ai_invoked",
                    identity,
                    {
                        "revision_number": revision_no,
                        "agent_slug": provenance_json.get("agent_slug"),
                        "provider": provenance_json.get("provider"),
                        "model_name": provenance_json.get("model_name"),
                    },
                )
        return JsonResponse({"revision": _serialize_article_revision(revision), "article": _serialize_article_detail(artifact)})

    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if not _can_view_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    revisions = ArtifactRevision.objects.filter(artifact=artifact).select_related("created_by").order_by("-revision_number")
    return JsonResponse({"revisions": [_serialize_article_revision(item) for item in revisions]})


@csrf_exempt
def article_convert_html_to_markdown(request: HttpRequest, article_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if not _can_edit_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    latest = _latest_artifact_revision(artifact)
    if not latest:
        return JsonResponse({"error": "no revision to convert"}, status=400)
    content = dict((latest.content_json if latest else {}) or {})
    body_markdown = str(content.get("body_markdown") or "")
    body_html = str(content.get("body_html") or "")
    if body_markdown.strip():
        return JsonResponse(
            {"article": _serialize_article_detail(artifact), "revision": _serialize_article_revision(latest), "converted": False, "reason": "already_markdown"}
        )
    if not body_html.strip():
        return JsonResponse({"error": "no body_html to convert"}, status=400)
    converted = _convert_article_html_to_markdown(body_html)
    if not converted:
        return JsonResponse({"error": "unable to convert body_html to markdown"}, status=400)
    content["body_markdown"] = converted
    provenance = dict(content.get("provenance_json") or {})
    provenance["html_to_markdown"] = {
        "converted_at": timezone.now().isoformat(),
        "converted_by": str(identity.id),
        "source": "article_convert_html_to_markdown",
    }
    content["provenance_json"] = provenance
    revision_no = _next_artifact_revision_number(artifact)
    with transaction.atomic():
        revision = ArtifactRevision.objects.create(
            artifact=artifact,
            revision_number=revision_no,
            content_json=content,
            created_by=identity,
        )
        artifact.version = revision_no
        artifact.save(update_fields=["version", "updated_at"])
        _record_artifact_event(
            artifact,
            "article_revision_created",
            identity,
            {"revision_number": revision_no, "source": "html_to_markdown"},
        )
    return JsonResponse({"article": _serialize_article_detail(artifact), "revision": _serialize_article_revision(revision), "converted": True})


def _video_generate_text(
    identity: UserIdentity,
    artifact: Artifact,
    purpose_slug: str,
    prompt: str,
    metadata: Dict[str, Any],
    *,
    explicit_agent: Any = None,
    explicit_context_packs: Any = None,
) -> Tuple[str, Dict[str, Any]]:
    resolved_agent, agent_source, agent_error = _resolve_agent_for_purpose(artifact, purpose_slug, explicit_override=explicit_agent)
    if not resolved_agent:
        raise AiConfigError(agent_error or f"no agent resolved for {purpose_slug}")
    packs, context_source, context_hash, context_error, override_mode, effective_pack_refs = _resolve_context_packs_for_purpose(
        artifact,
        purpose_slug,
        resolved_agent,
        explicit_override=explicit_context_packs,
    )
    if context_error:
        raise AiConfigError(context_error)
    resolved_context = _resolve_context_pack_list(packs)
    context_text = str(resolved_context.get("effective_context") or "").strip()

    resolved = resolve_ai_config(agent_slug=resolved_agent.slug, purpose_slug=purpose_slug)
    base_system_prompt = str(resolved.get("system_prompt") or "").strip()
    if context_text:
        resolved["system_prompt"] = f"{base_system_prompt}\n\n{context_text}".strip() if base_system_prompt else context_text

    result = invoke_model(
        resolved_config=resolved,
        messages=[{"role": "user", "content": prompt}],
    )
    AuditLog.objects.create(
        message="ai_invocation",
        metadata_json={
            "actor_identity_id": str(identity.id),
            "agent_slug": resolved.get("agent_slug") or resolved_agent.slug,
            "agent_id": str(resolved_agent.id),
            "provider": resolved.get("provider"),
            "model_name": resolved.get("model_name"),
            "purpose": resolved.get("purpose"),
            "purpose_slug": purpose_slug,
            "agent_source": agent_source,
            "context_source": context_source,
            "context_pack_refs": resolved_context.get("refs", []),
            "effective_context_pack_refs": effective_pack_refs,
            "context_pack_hash": context_hash,
            "context_pack_override_mode": override_mode,
            "effective_model_config_id": str(resolved_agent.model_config_id) if resolved_agent.model_config_id else None,
            "metadata": metadata,
        },
    )
    return str(result.get("content") or "").strip(), {
        "agent_slug": resolved.get("agent_slug") or resolved_agent.slug,
        "agent_id": str(resolved_agent.id),
        "agent_name": resolved_agent.name,
        "agent_source": agent_source,
        "provider": resolved.get("provider"),
        "model_name": resolved.get("model_name"),
        "model_config_id": resolved.get("model_config_id"),
        "purpose_slug": purpose_slug,
        "context_source": context_source,
        "context_pack_refs": resolved_context.get("refs", []),
        "effective_context_pack_refs": effective_pack_refs,
        "context_pack_hash": context_hash,
        "context_pack_override_mode": override_mode,
        "effective_model_config_id": str(resolved_agent.model_config_id) if resolved_agent.model_config_id else None,
    }


def _generate_storyboard_from_script(script_text: str, duration_seconds_target: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    cleaned = [line.strip() for line in script_text.splitlines() if line.strip()]
    if not cleaned:
        cleaned = ["Intro", "Problem", "Approach", "Outcome", "Call to action"]
    scene_count = min(max(3, len(cleaned)), 8)
    per_scene = max(8, int(duration_seconds_target / max(scene_count, 1)))
    storyboard: List[Dict[str, Any]] = []
    scenes: List[Dict[str, Any]] = []
    start_seconds = 0
    for index in range(scene_count):
        source = cleaned[index] if index < len(cleaned) else f"Scene {index + 1}"
        end_seconds = start_seconds + per_scene
        time_range = f"{start_seconds // 60}:{start_seconds % 60:02d}-{end_seconds // 60}:{end_seconds % 60:02d}"
        storyboard.append(
            {
                "scene": index + 1,
                "time_range": time_range,
                "on_screen_text": source[:120],
                "visual_description": f"Visual for: {source[:180]}",
                "motion": "subtle camera move",
                "assets": [{"type": "image_prompt", "value": f"cinematic explainer frame for: {source[:200]}"}],
                "narration": source,
            }
        )
        scenes.append(
            {
                "id": f"s{index + 1}",
                "name": source[:64] or f"Scene {index + 1}",
                "duration_seconds": per_scene,
                "narration": source,
                "visual_prompt": f"cinematic explainer frame for: {source[:200]}",
                "on_screen_text": source[:120],
                "camera_motion": "subtle camera move",
                "style_constraints": ["brand-safe", "no photoreal humans unless requested"],
                "generated": {"image_asset_url": None, "video_clip_url": None},
            }
        )
        start_seconds = end_seconds
    return storyboard, scenes


def _process_video_render(video_render: VideoRender) -> VideoRender:
    now = timezone.now()
    article = video_render.article
    if video_render.status == "canceled":
        return video_render
    spec = _video_spec(article)
    request_payload = dict(video_render.request_payload_json or {})
    context_pack = ContextPack.objects.filter(id=video_render.context_pack_id).first() if video_render.context_pack_id else None
    if context_pack and "context_pack" not in request_payload:
        request_payload["context_pack"] = _video_context_metadata(context_pack)
    video_render.status = "running"
    video_render.started_at = now
    video_render.error_message = ""
    video_render.error_details_json = {}
    video_render.request_payload_json = sanitize_payload(request_payload)
    video_render.save(update_fields=["status", "started_at", "error_message", "error_details_json", "request_payload_json", "updated_at"])

    provider, assets, raw_result = render_video(spec, request_payload, str(article.id))
    finished_at = timezone.now()
    video_render.provider = provider or "unknown"
    video_render.status = "succeeded"
    video_render.completed_at = finished_at
    video_render.result_payload_json = sanitize_payload(raw_result)
    video_render.output_assets = sanitize_payload(assets)
    video_render.save(
        update_fields=["provider", "status", "completed_at", "result_payload_json", "output_assets", "updated_at"]
    )

    spec["generation"] = {
        **(spec.get("generation") if isinstance(spec.get("generation"), dict) else {}),
        "provider": video_render.provider,
        "model_name": video_render.model_name or "",
        "status": "succeeded",
        "last_render_id": str(video_render.id),
        "spec_snapshot_hash": video_render.spec_snapshot_hash or "",
        "input_snapshot_hash": video_render.input_snapshot_hash or "",
        "context_pack_id": str(video_render.context_pack_id) if video_render.context_pack_id else None,
        "context_pack_version": video_render.context_pack_version or "",
        "context_pack_updated_at": video_render.context_pack_updated_at.isoformat() if video_render.context_pack_updated_at else None,
        "context_pack_hash": video_render.context_pack_hash or "",
        "updated_at": finished_at.isoformat(),
    }
    article.video_spec_json = spec
    article.video_latest_render = video_render
    article.save(update_fields=["video_spec_json", "video_latest_render", "updated_at"])
    return video_render


@csrf_exempt
def article_video_initialize(request: HttpRequest, article_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if not _can_edit_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    dirty_fields: Set[str] = set()
    if artifact.format != "video_explainer":
        artifact.format = "video_explainer"
        dirty_fields.add("format")
    content = _article_content(artifact)
    if not isinstance(artifact.video_spec_json, dict):
        artifact.video_spec_json, _ = _build_explainer_video_spec(
            title=str(content.get("title") or artifact.title),
            summary=str(content.get("summary") or ""),
            intent=str(content.get("summary") or artifact.title),
            description=str(content.get("body_markdown") or content.get("summary") or ""),
        )
        dirty_fields.add("video_spec_json")
    elif not isinstance(artifact.video_spec_json.get("scenes"), list) or len(artifact.video_spec_json.get("scenes") or []) < 3:
        spec, _ = _build_explainer_video_spec(
            title=str(content.get("title") or artifact.title),
            summary=str(content.get("summary") or ""),
            intent=str((artifact.video_spec_json or {}).get("intent") or content.get("summary") or artifact.title),
            duration=str((artifact.video_spec_json or {}).get("duration") or ""),
            audience=str((artifact.video_spec_json or {}).get("audience") or ""),
            description=str(content.get("body_markdown") or content.get("summary") or ""),
            existing_scenes=(artifact.video_spec_json or {}).get("scenes") if isinstance(artifact.video_spec_json, dict) else None,
        )
        artifact.video_spec_json = spec
        dirty_fields.add("video_spec_json")
    if not artifact.video_context_pack_id:
        default_pack = (
            ContextPack.objects.filter(purpose=VIDEO_CONTEXT_PACK_PURPOSE, is_active=True, is_default=True)
            .order_by("-updated_at")
            .first()
        )
        if default_pack:
            artifact.video_context_pack = default_pack
            dirty_fields.add("video_context_pack")
    if dirty_fields:
        artifact.save(update_fields=[*sorted(dirty_fields), "updated_at"])
    _record_artifact_event(artifact, "article_video_initialized", identity, {"format": artifact.format})
    return JsonResponse({"article": _serialize_article_detail(artifact)})


@csrf_exempt
def article_video_ai_config(request: HttpRequest, article_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if artifact.format != "video_explainer":
        return JsonResponse({"error": "article format must be video_explainer"}, status=400)

    if request.method == "GET":
        if not _can_view_article(identity, artifact):
            return JsonResponse({"error": "forbidden"}, status=403)
        return JsonResponse(
            {
                "overrides": _article_video_ai_config(artifact),
                "effective": _effective_video_ai_config(artifact),
            }
        )

    if request.method != "PUT":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if not _can_edit_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)

    payload = _parse_json(request)
    current = _article_video_ai_config(artifact)
    next_agents = dict(current.get("agents") if isinstance(current.get("agents"), dict) else {})
    next_context = dict(current.get("context_packs") if isinstance(current.get("context_packs"), dict) else {})

    if payload.get("reset_all") is True:
        next_agents = {}
        next_context = {}

    if "agents" in payload:
        raw_agents = payload.get("agents")
        if not isinstance(raw_agents, dict):
            return JsonResponse({"error": "agents must be an object"}, status=400)
        for purpose_slug, raw_value in raw_agents.items():
            if purpose_slug not in EXPLAINER_PURPOSES:
                return JsonResponse({"error": f"unsupported purpose '{purpose_slug}'"}, status=400)
            value = str(raw_value or "").strip()
            if not value:
                next_agents.pop(purpose_slug, None)
                continue
            agent = _resolve_agent_value(value)
            if not agent:
                return JsonResponse({"error": f"agent not found or disabled for '{purpose_slug}'"}, status=400)
            if not _is_agent_linked_to_purpose(agent, purpose_slug):
                return JsonResponse({"error": f"agent '{agent.slug}' is not linked to '{purpose_slug}'"}, status=400)
            next_agents[purpose_slug] = agent.slug

    if "context_packs" in payload:
        raw_context = payload.get("context_packs")
        if not isinstance(raw_context, dict):
            return JsonResponse({"error": "context_packs must be an object"}, status=400)
        for purpose_slug, raw_value in raw_context.items():
            if purpose_slug not in EXPLAINER_PURPOSES:
                return JsonResponse({"error": f"unsupported purpose '{purpose_slug}'"}, status=400)
            if raw_value is None or raw_value == "" or (isinstance(raw_value, list) and len(raw_value) == 0):
                next_context.pop(purpose_slug, None)
                continue
            mode = "extend"
            refs_input = raw_value
            if isinstance(raw_value, dict):
                mode = str(raw_value.get("mode") or raw_value.get("override_mode") or "extend").strip().lower()
                if mode not in {"extend", "replace"}:
                    return JsonResponse({"error": f"{purpose_slug}: override mode must be 'extend' or 'replace'"}, status=400)
                refs_input = raw_value.get("context_pack_refs")
                if refs_input is None:
                    refs_input = raw_value.get("refs")
                if refs_input is None:
                    refs_input = raw_value.get("context_packs")
                if refs_input is None:
                    refs_input = raw_value.get("packs")
            refs, err = _normalize_context_pack_override_refs(purpose_slug, refs_input)
            if err:
                return JsonResponse({"error": f"{purpose_slug}: {err}"}, status=400)
            if not refs:
                next_context.pop(purpose_slug, None)
                continue
            next_context[purpose_slug] = {"mode": mode, "context_pack_refs": refs}

    persisted = {"agents": next_agents, "context_packs": next_context}
    artifact.video_ai_config_json = persisted if next_agents or next_context else None
    artifact.save(update_fields=["video_ai_config_json", "updated_at"])

    _record_artifact_event(
        artifact,
        "article_video_ai_config_updated",
        identity,
        {
            "agent_overrides": sorted(list(next_agents.keys())),
            "context_pack_overrides": sorted(list(next_context.keys())),
            "context_pack_override_modes": {
                slug: str((entry or {}).get("mode") or "extend")
                for slug, entry in next_context.items()
                if isinstance(entry, dict)
            },
        },
    )
    return JsonResponse(
        {
            "overrides": _article_video_ai_config(artifact),
            "effective": _effective_video_ai_config(artifact),
            "article": _serialize_article_detail(artifact),
        }
    )


@csrf_exempt
def article_video_generate_script(request: HttpRequest, article_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if not _can_edit_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    payload = _parse_json(request)
    agent_slug = str(payload.get("agent_slug") or "").strip()
    context_pack_override = payload.get("context_pack_id") if "context_pack_id" in payload else payload.get("context_packs")

    spec = _video_spec(artifact)
    script = spec.get("script") if isinstance(spec.get("script"), dict) else {}
    current_draft = str(script.get("draft") or "")
    prompt = (
        "Generate a concise explainer video narration script.\n"
        "Return plain text script only.\n\n"
        f"Title: {artifact.title}\n"
        f"Intent: {spec.get('intent') or ''}\n"
        f"Audience: {spec.get('audience') or 'mixed'}\n"
        f"Tone: {spec.get('tone') or 'clear, confident, warm'}\n"
        f"Duration target (seconds): {spec.get('duration_seconds_target') or 150}\n\n"
        f"Source article markdown:\n{_article_content(artifact).get('body_markdown') or ''}\n"
    )
    try:
        generated, meta = _video_generate_text(
            identity,
            artifact,
            "explainer_script",
            prompt,
            {"artifact_id": str(artifact.id), "workspace_id": str(artifact.workspace_id), "mode": "video_generate_script"},
            explicit_agent=agent_slug or None,
            explicit_context_packs=context_pack_override,
        )
    except (AiConfigError, AiInvokeError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    if not generated:
        return JsonResponse({"error": "AI returned empty content"}, status=400)

    proposals = script.get("proposals") if isinstance(script.get("proposals"), list) else []
    proposal = {
        "id": str(uuid.uuid4()),
        "text": generated,
        "created_at": timezone.now().isoformat(),
        "model": meta.get("model_name"),
        "provider": meta.get("provider"),
        "agent_slug": meta.get("agent_slug"),
    }
    proposals = [proposal, *proposals][:15]
    if not current_draft:
        script["draft"] = generated
    script["proposals"] = proposals
    script["last_generated_at"] = timezone.now().isoformat()
    spec["script"] = script
    resolved_pack_refs = meta.get("context_pack_refs") if isinstance(meta.get("context_pack_refs"), list) else []
    resolved_context_pack = None
    if resolved_pack_refs:
        first_pack_id = str((resolved_pack_refs[0] or {}).get("id") or "").strip() if isinstance(resolved_pack_refs[0], dict) else ""
        if first_pack_id:
            resolved_context_pack = ContextPack.objects.filter(id=first_pack_id).first()
    context_meta = _video_context_metadata(resolved_context_pack)
    generation = spec.get("generation") if isinstance(spec.get("generation"), dict) else {}
    generation.update(
        {
            "provider": meta.get("provider") or generation.get("provider"),
            "model_name": meta.get("model_name") or generation.get("model_name"),
            "purpose_slug": "explainer_script",
            "agent_slug": meta.get("agent_slug") or generation.get("agent_slug"),
            "context_pack_id": context_meta.get("id"),
            "context_pack_version": context_meta.get("version"),
            "context_pack_updated_at": context_meta.get("updated_at"),
            "context_pack_hash": context_meta.get("hash"),
            "context_pack_refs": meta.get("context_pack_refs") if isinstance(meta.get("context_pack_refs"), list) else [],
            "updated_at": timezone.now().isoformat(),
        }
    )
    spec["generation"] = generation
    artifact.video_spec_json = spec
    artifact.format = "video_explainer"
    artifact.video_context_pack = resolved_context_pack
    artifact.save(update_fields=["video_spec_json", "format", "video_context_pack", "updated_at"])
    _record_artifact_event(
        artifact,
        "article_video_script_generated",
        identity,
        {"proposal_id": proposal["id"], "context_pack_id": context_meta.get("id"), "context_pack_hash": context_meta.get("hash")},
    )
    return JsonResponse({"article": _serialize_article_detail(artifact), "proposal": proposal, "overwrote_draft": not bool(current_draft)})


@csrf_exempt
def article_video_generate_storyboard(request: HttpRequest, article_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if not _can_edit_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    payload = _parse_json(request)
    agent_slug = str(payload.get("agent_slug") or "").strip()
    context_pack_override = payload.get("context_pack_id") if "context_pack_id" in payload else payload.get("context_packs")
    spec = _video_spec(artifact)
    script_draft = str(((spec.get("script") or {}).get("draft") if isinstance(spec.get("script"), dict) else "") or "")
    prompt = (
        "Generate a storyboard and scene breakdown for this explainer script.\n"
        "Respond with JSON object keys: storyboard_draft (array), scenes (array).\n\n"
        f"Title: {artifact.title}\n"
        f"Intent: {spec.get('intent') or ''}\n"
        f"Audience: {spec.get('audience') or 'mixed'}\n"
        f"Tone: {spec.get('tone') or 'clear, confident, warm'}\n"
        f"Duration target (seconds): {spec.get('duration_seconds_target') or 150}\n\n"
        f"Script:\n{script_draft}\n"
    )
    generated_text = ""
    meta: Dict[str, Any] = {}
    try:
        generated_text, meta = _video_generate_text(
            identity,
            artifact,
            "explainer_storyboard",
            prompt,
            {"artifact_id": str(artifact.id), "workspace_id": str(artifact.workspace_id), "mode": "video_generate_storyboard"},
            explicit_agent=agent_slug or None,
            explicit_context_packs=context_pack_override,
        )
    except (AiConfigError, AiInvokeError):
        # Fallback to deterministic storyboard if AI generation fails.
        generated_text = ""

    generated_storyboard: List[Dict[str, Any]] = []
    generated_scenes: List[Dict[str, Any]] = []
    if generated_text:
        try:
            parsed = json.loads(generated_text)
            if isinstance(parsed, dict):
                if isinstance(parsed.get("storyboard_draft"), list):
                    generated_storyboard = parsed.get("storyboard_draft") or []
                if isinstance(parsed.get("scenes"), list):
                    generated_scenes = parsed.get("scenes") or []
        except json.JSONDecodeError:
            generated_storyboard = []
            generated_scenes = []

    if not generated_storyboard or not generated_scenes:
        generated_storyboard, generated_scenes = _generate_storyboard_from_script(
            script_draft or _article_content(artifact).get("body_markdown") or "",
            int(spec.get("duration_seconds_target") or 150),
        )

    storyboard = spec.get("storyboard") if isinstance(spec.get("storyboard"), dict) else {}
    existing_draft = storyboard.get("draft")
    proposals = storyboard.get("proposals") if isinstance(storyboard.get("proposals"), list) else []
    proposal = {
        "id": str(uuid.uuid4()),
        "storyboard_draft": generated_storyboard,
        "scenes": generated_scenes,
        "created_at": timezone.now().isoformat(),
        "model": meta.get("model_name"),
        "provider": meta.get("provider"),
        "agent_slug": meta.get("agent_slug"),
    }
    proposals = [proposal, *proposals][:15]
    if not isinstance(existing_draft, list) or len(existing_draft) == 0:
        storyboard["draft"] = generated_storyboard
        spec["scenes"] = generated_scenes
    storyboard["proposals"] = proposals
    storyboard["last_generated_at"] = timezone.now().isoformat()
    spec["storyboard"] = storyboard
    resolved_pack_refs = meta.get("context_pack_refs") if isinstance(meta.get("context_pack_refs"), list) else []
    resolved_context_pack = None
    if resolved_pack_refs:
        first_pack_id = str((resolved_pack_refs[0] or {}).get("id") or "").strip() if isinstance(resolved_pack_refs[0], dict) else ""
        if first_pack_id:
            resolved_context_pack = ContextPack.objects.filter(id=first_pack_id).first()
    context_meta = _video_context_metadata(resolved_context_pack)
    generation = spec.get("generation") if isinstance(spec.get("generation"), dict) else {}
    generation.update(
        {
            "provider": meta.get("provider") or generation.get("provider"),
            "model_name": meta.get("model_name") or generation.get("model_name"),
            "purpose_slug": "explainer_storyboard",
            "agent_slug": meta.get("agent_slug") or generation.get("agent_slug"),
            "context_pack_id": context_meta.get("id"),
            "context_pack_version": context_meta.get("version"),
            "context_pack_updated_at": context_meta.get("updated_at"),
            "context_pack_hash": context_meta.get("hash"),
            "context_pack_refs": meta.get("context_pack_refs") if isinstance(meta.get("context_pack_refs"), list) else [],
            "updated_at": timezone.now().isoformat(),
        }
    )
    spec["generation"] = generation
    artifact.video_spec_json = spec
    artifact.format = "video_explainer"
    artifact.video_context_pack = resolved_context_pack
    artifact.save(update_fields=["video_spec_json", "format", "video_context_pack", "updated_at"])
    _record_artifact_event(
        artifact,
        "article_video_storyboard_generated",
        identity,
        {"proposal_id": proposal["id"], "context_pack_id": context_meta.get("id"), "context_pack_hash": context_meta.get("hash")},
    )
    return JsonResponse({"article": _serialize_article_detail(artifact), "proposal": proposal, "overwrote_draft": not isinstance(existing_draft, list) or len(existing_draft) == 0})


def _video_stage_output(spec: Dict[str, Any], stage_key: str) -> Dict[str, Any]:
    block = spec.get(stage_key) if isinstance(spec.get(stage_key), dict) else {}
    return {
        "draft": block.get("draft"),
        "proposals": block.get("proposals") if isinstance(block.get("proposals"), list) else [],
        "last_generated_at": block.get("last_generated_at"),
    }


def _save_video_stage_proposal(
    *,
    artifact: Artifact,
    identity: UserIdentity,
    stage_key: str,
    purpose_slug: str,
    generated_output: Any,
    meta: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    spec = _video_spec(artifact)
    block = spec.get(stage_key) if isinstance(spec.get(stage_key), dict) else {}
    proposals = block.get("proposals") if isinstance(block.get("proposals"), list) else []
    proposal = {
        "id": str(uuid.uuid4()),
        "output": generated_output,
        "created_at": timezone.now().isoformat(),
        "model": meta.get("model_name"),
        "provider": meta.get("provider"),
        "agent_slug": meta.get("agent_slug"),
        "purpose_slug": purpose_slug,
        "context_pack_refs": meta.get("context_pack_refs") if isinstance(meta.get("context_pack_refs"), list) else [],
        "context_pack_hash": meta.get("context_pack_hash") or "",
    }
    proposals = [proposal, *proposals][:15]
    if block.get("draft") in {None, "", []}:
        block["draft"] = generated_output
    block["proposals"] = proposals
    block["last_generated_at"] = timezone.now().isoformat()
    spec[stage_key] = block
    generation = spec.get("generation") if isinstance(spec.get("generation"), dict) else {}
    generation.update(
        {
            "provider": meta.get("provider") or generation.get("provider"),
            "model_name": meta.get("model_name") or generation.get("model_name"),
            "purpose_slug": purpose_slug,
            "agent_slug": meta.get("agent_slug") or generation.get("agent_slug"),
            "context_pack_hash": meta.get("context_pack_hash") or generation.get("context_pack_hash"),
            "context_pack_refs": meta.get("context_pack_refs") if isinstance(meta.get("context_pack_refs"), list) else generation.get("context_pack_refs", []),
            "updated_at": timezone.now().isoformat(),
        }
    )
    spec["generation"] = generation
    resolved_context_pack = None
    refs = meta.get("context_pack_refs") if isinstance(meta.get("context_pack_refs"), list) else []
    if refs and isinstance(refs[0], dict):
        first_pack_id = str(refs[0].get("id") or "").strip()
        if first_pack_id:
            resolved_context_pack = ContextPack.objects.filter(id=first_pack_id).first()
    artifact.video_spec_json = spec
    artifact.format = "video_explainer"
    artifact.video_context_pack = resolved_context_pack
    artifact.save(update_fields=["video_spec_json", "format", "video_context_pack", "updated_at"])
    _record_artifact_event(
        artifact,
        f"article_video_{stage_key}_generated",
        identity,
        {
            "proposal_id": proposal["id"],
            "purpose_slug": purpose_slug,
            "agent_slug": meta.get("agent_slug"),
            "context_pack_hash": meta.get("context_pack_hash"),
        },
    )
    return proposal, spec


@csrf_exempt
def article_video_generate_visual_prompts(request: HttpRequest, article_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if not _can_edit_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    payload = _parse_json(request)
    instruction = str(payload.get("instruction") or "").strip()
    agent_slug = str(payload.get("agent_slug") or "").strip()
    context_pack_override = payload.get("context_pack_id") if "context_pack_id" in payload else payload.get("context_packs")
    spec = _video_spec(artifact)
    prompt = (
        "Generate scene visual prompts as JSON keyed by scene_id.\n"
        "Each value should include image_prompt, optional negative_prompt, motion_hint, and aspect_ratio=16:9.\n"
        f"Instruction: {instruction or 'Generate clean, brand-safe visuals.'}\n\n"
        f"Scenes JSON:\n{json.dumps(spec.get('scenes') if isinstance(spec.get('scenes'), list) else [], ensure_ascii=False)}"
    )
    try:
        generated_text, meta = _video_generate_text(
            identity,
            artifact,
            "explainer_visual_prompts",
            prompt,
            {"artifact_id": str(artifact.id), "workspace_id": str(artifact.workspace_id), "mode": "video_generate_visual_prompts"},
            explicit_agent=agent_slug or None,
            explicit_context_packs=context_pack_override,
        )
    except (AiConfigError, AiInvokeError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    output: Any = generated_text
    try:
        parsed = json.loads(generated_text)
        if isinstance(parsed, dict):
            output = parsed
    except Exception:
        pass
    proposal, _ = _save_video_stage_proposal(
        artifact=artifact,
        identity=identity,
        stage_key="visual_prompts",
        purpose_slug="explainer_visual_prompts",
        generated_output=output,
        meta=meta,
    )
    return JsonResponse({"article": _serialize_article_detail(artifact), "proposal": proposal, "overwrote_draft": False})


@csrf_exempt
def article_video_generate_narration(request: HttpRequest, article_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if not _can_edit_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    payload = _parse_json(request)
    instruction = str(payload.get("instruction") or "").strip()
    agent_slug = str(payload.get("agent_slug") or "").strip()
    context_pack_override = payload.get("context_pack_id") if "context_pack_id" in payload else payload.get("context_packs")
    spec = _video_spec(artifact)
    storyboard_draft = ((spec.get("storyboard") or {}).get("draft") if isinstance(spec.get("storyboard"), dict) else []) or []
    prompt = (
        "Rewrite this narration for smooth spoken delivery while preserving meaning.\n"
        f"Instruction: {instruction or 'Keep it clear and concise.'}\n\n"
        f"Current script:\n{((spec.get('script') or {}).get('draft') if isinstance(spec.get('script'), dict) else '')}\n\n"
        f"Storyboard draft:\n{json.dumps(storyboard_draft, ensure_ascii=False)}"
    )
    try:
        generated_text, meta = _video_generate_text(
            identity,
            artifact,
            "explainer_narration",
            prompt,
            {"artifact_id": str(artifact.id), "workspace_id": str(artifact.workspace_id), "mode": "video_generate_narration"},
            explicit_agent=agent_slug or None,
            explicit_context_packs=context_pack_override,
        )
    except (AiConfigError, AiInvokeError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    proposal, _ = _save_video_stage_proposal(
        artifact=artifact,
        identity=identity,
        stage_key="narration",
        purpose_slug="explainer_narration",
        generated_output=generated_text,
        meta=meta,
    )
    return JsonResponse({"article": _serialize_article_detail(artifact), "proposal": proposal, "overwrote_draft": False})


@csrf_exempt
def article_video_generate_title_description(request: HttpRequest, article_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if not _can_edit_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    payload = _parse_json(request)
    instruction = str(payload.get("instruction") or "").strip()
    agent_slug = str(payload.get("agent_slug") or "").strip()
    context_pack_override = payload.get("context_pack_id") if "context_pack_id" in payload else payload.get("context_packs")
    spec = _video_spec(artifact)
    prompt = (
        "Return strict JSON with keys: titles (5), descriptions (2), ctas (3).\n"
        f"Instruction: {instruction or 'Concrete, concise, no hype.'}\n\n"
        f"Article title: {artifact.title}\n"
        f"Intent: {spec.get('intent') or ''}\n"
        f"Audience: {spec.get('audience') or ''}\n"
        f"Tone: {spec.get('tone') or ''}\n"
    )
    try:
        generated_text, meta = _video_generate_text(
            identity,
            artifact,
            "explainer_title_description",
            prompt,
            {"artifact_id": str(artifact.id), "workspace_id": str(artifact.workspace_id), "mode": "video_generate_title_description"},
            explicit_agent=agent_slug or None,
            explicit_context_packs=context_pack_override,
        )
    except (AiConfigError, AiInvokeError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    output: Any = generated_text
    try:
        parsed = json.loads(generated_text)
        if isinstance(parsed, dict):
            output = parsed
    except Exception:
        pass
    proposal, _ = _save_video_stage_proposal(
        artifact=artifact,
        identity=identity,
        stage_key="title_description",
        purpose_slug="explainer_title_description",
        generated_output=output,
        meta=meta,
    )
    return JsonResponse({"article": _serialize_article_detail(artifact), "proposal": proposal, "overwrote_draft": False})


@csrf_exempt
def article_video_renders_collection(request: HttpRequest, article_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if request.method == "POST":
        if not _can_edit_article(identity, artifact):
            return JsonResponse({"error": "forbidden"}, status=403)
        payload = _parse_json(request)
        context_pack, pack_error = _resolve_video_context_pack_for_article(
            artifact,
            payload.get("context_pack_id") if "context_pack_id" in payload else None,
            allow_clear=True,
        )
        if pack_error:
            return pack_error
        request_payload = payload.get("request_payload_json") if isinstance(payload.get("request_payload_json"), dict) else {}
        platform_config = _load_platform_config()
        video_generation_cfg = (
            platform_config.get("video_generation")
            if isinstance(platform_config.get("video_generation"), dict)
            else {}
        )
        provider = str(
            payload.get("provider")
            or request_payload.get("provider")
            or video_generation_cfg.get("provider")
            or os.environ.get("XYENCE_VIDEO_PROVIDER")
            or "unknown"
        ).strip().lower() or "unknown"
        model_name = str(payload.get("model_name") or request_payload.get("model_name") or request_payload.get("model") or "").strip()
        spec = _video_spec(artifact)
        spec_hash = _normalized_json_hash(spec)
        context_meta = _video_context_metadata(context_pack)
        context_hash = str(context_meta.get("hash") or "")
        input_hash = _video_input_snapshot_hash(spec_hash, context_hash, provider, model_name)
        request_payload_with_meta = dict(request_payload)
        http_cfg = video_generation_cfg.get("http") if isinstance(video_generation_cfg.get("http"), dict) else {}
        try:
            http_timeout_seconds = int(http_cfg.get("timeout_seconds") or 90)
        except (TypeError, ValueError):
            http_timeout_seconds = 90
        request_payload_with_meta["video_provider_config"] = {
            "enabled": bool(video_generation_cfg.get("enabled", True)),
            "provider": str(video_generation_cfg.get("provider") or provider),
            "http": {
                "endpoint_url": str(http_cfg.get("endpoint_url") or "").strip(),
                "timeout_seconds": http_timeout_seconds,
            },
        }
        request_payload_with_meta["input_snapshot"] = {
            "spec_snapshot_hash": spec_hash,
            "context_pack_hash": context_hash,
            "provider": provider,
            "model_name": model_name,
            "input_snapshot_hash": input_hash,
        }
        if context_meta:
            request_payload_with_meta["context_pack"] = context_meta
        with transaction.atomic():
            render_record = VideoRender.objects.create(
                article=artifact,
                provider=provider,
                model_name=model_name,
                status="queued",
                request_payload_json=sanitize_payload(request_payload_with_meta),
                result_payload_json={},
                output_assets=[],
                context_pack=context_pack,
                context_pack_version=str(context_meta.get("version") or ""),
                context_pack_updated_at=parse_datetime(str(context_meta.get("updated_at"))) if context_meta.get("updated_at") else None,
                context_pack_hash=str(context_meta.get("hash") or ""),
                spec_snapshot_hash=spec_hash,
                input_snapshot_hash=input_hash,
            )
            generation = spec.get("generation") if isinstance(spec.get("generation"), dict) else {}
            generation.update(
                {
                    "provider": provider,
                    "model_name": model_name,
                    "status": "queued",
                    "last_render_id": str(render_record.id),
                    "spec_snapshot_hash": spec_hash,
                    "input_snapshot_hash": input_hash,
                    "context_pack_id": context_meta.get("id"),
                    "context_pack_version": context_meta.get("version"),
                    "context_pack_updated_at": context_meta.get("updated_at"),
                    "context_pack_hash": context_meta.get("hash"),
                    "updated_at": timezone.now().isoformat(),
                }
            )
            spec["generation"] = generation
            artifact.video_spec_json = spec
            artifact.video_context_pack = context_pack
            artifact.save(update_fields=["video_spec_json", "video_context_pack", "updated_at"])
        _record_artifact_event(
            artifact,
            "article_video_render_requested",
            identity,
            {
                "render_id": str(render_record.id),
                "provider": provider,
                "model_name": model_name,
                "spec_snapshot_hash": spec_hash,
                "input_snapshot_hash": input_hash,
                "context_pack_id": context_meta.get("id"),
                "context_pack_hash": context_meta.get("hash"),
            },
        )
        mode = _async_mode()
        if mode == "redis":
            _enqueue_job("xyn_orchestrator.worker_tasks.process_video_render", str(render_record.id))
        else:
            try:
                _process_video_render(render_record)
            except Exception as exc:
                render_record.status = "failed"
                render_record.error_message = str(exc)
                render_record.error_details_json = {"mode": "inline"}
                render_record.completed_at = timezone.now()
                render_record.save(update_fields=["status", "error_message", "error_details_json", "completed_at", "updated_at"])
        render_record.refresh_from_db()
        return JsonResponse({"render": _serialize_video_render(render_record), "article": _serialize_article_detail(artifact)})

    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if not _can_view_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    rows = VideoRender.objects.filter(article=artifact).select_related("context_pack").order_by("-requested_at")
    return JsonResponse({"renders": [_serialize_video_render(row) for row in rows]})


@csrf_exempt
def video_render_detail(request: HttpRequest, render_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    record = get_object_or_404(VideoRender.objects.select_related("article", "context_pack"), id=render_id)
    if request.method == "POST":
        if not _can_edit_article(identity, record.article):
            return JsonResponse({"error": "forbidden"}, status=403)
        action = str((_parse_json(request).get("action") or "").strip().lower())
        if action == "retry":
            retry = VideoRender.objects.create(
                article=record.article,
                provider=record.provider or "unknown",
                model_name=record.model_name or "",
                status="queued",
                request_payload_json=dict(record.request_payload_json or {}),
                result_payload_json={},
                output_assets=[],
                context_pack=record.context_pack,
                context_pack_version=record.context_pack_version,
                context_pack_updated_at=record.context_pack_updated_at,
                context_pack_hash=record.context_pack_hash,
                spec_snapshot_hash=record.spec_snapshot_hash,
                input_snapshot_hash=record.input_snapshot_hash,
            )
            _record_artifact_event(record.article, "article_video_render_retried", identity, {"render_id": str(record.id), "retry_id": str(retry.id)})
            if _async_mode() == "redis":
                _enqueue_job("xyn_orchestrator.worker_tasks.process_video_render", str(retry.id))
            else:
                try:
                    _process_video_render(retry)
                except Exception as exc:
                    retry.status = "failed"
                    retry.error_message = str(exc)
                    retry.error_details_json = {"mode": "inline"}
                    retry.completed_at = timezone.now()
                    retry.save(update_fields=["status", "error_message", "error_details_json", "completed_at", "updated_at"])
            retry.refresh_from_db()
            return JsonResponse({"render": _serialize_video_render(retry)})
        if action == "cancel":
            if record.status in {"succeeded", "failed", "canceled"}:
                return JsonResponse({"render": _serialize_video_render(record)})
            record.status = "canceled"
            record.completed_at = timezone.now()
            record.save(update_fields=["status", "completed_at", "updated_at"])
            _record_artifact_event(record.article, "article_video_render_canceled", identity, {"render_id": str(record.id)})
            return JsonResponse({"render": _serialize_video_render(record)})
        return JsonResponse({"error": "unsupported action"}, status=400)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if not _can_view_article(identity, record.article):
        return JsonResponse({"error": "forbidden"}, status=403)
    return JsonResponse({"render": _serialize_video_render(record)})


@csrf_exempt
def video_render_cancel(request: HttpRequest, render_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    record = get_object_or_404(VideoRender.objects.select_related("article", "context_pack"), id=render_id)
    if not _can_edit_article(identity, record.article):
        return JsonResponse({"error": "forbidden"}, status=403)
    if record.status not in {"succeeded", "failed", "canceled"}:
        record.status = "canceled"
        record.completed_at = timezone.now()
        record.save(update_fields=["status", "completed_at", "updated_at"])
        _record_artifact_event(record.article, "article_video_render_canceled", identity, {"render_id": str(record.id)})
    return JsonResponse({"render": _serialize_video_render(record)})


@csrf_exempt
def video_render_retry(request: HttpRequest, render_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    record = get_object_or_404(VideoRender.objects.select_related("article", "context_pack"), id=render_id)
    if not _can_edit_article(identity, record.article):
        return JsonResponse({"error": "forbidden"}, status=403)
    retry = VideoRender.objects.create(
        article=record.article,
        provider=record.provider or "unknown",
        model_name=record.model_name or "",
        status="queued",
        request_payload_json=dict(record.request_payload_json or {}),
        result_payload_json={},
        output_assets=[],
        context_pack=record.context_pack,
        context_pack_version=record.context_pack_version,
        context_pack_updated_at=record.context_pack_updated_at,
        context_pack_hash=record.context_pack_hash,
        spec_snapshot_hash=record.spec_snapshot_hash,
        input_snapshot_hash=record.input_snapshot_hash,
    )
    _record_artifact_event(record.article, "article_video_render_retried", identity, {"render_id": str(record.id), "retry_id": str(retry.id)})
    if _async_mode() == "redis":
        _enqueue_job("xyn_orchestrator.worker_tasks.process_video_render", str(retry.id))
    else:
        try:
            _process_video_render(retry)
        except Exception as exc:
            retry.status = "failed"
            retry.error_message = str(exc)
            retry.error_details_json = {"mode": "inline"}
            retry.completed_at = timezone.now()
            retry.save(update_fields=["status", "error_message", "error_details_json", "completed_at", "updated_at"])
    retry.refresh_from_db()
    return JsonResponse({"render": _serialize_video_render(retry)})


@csrf_exempt
def article_video_export_package(request: HttpRequest, article_id: str) -> HttpResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = _resolve_article_or_404(article_id)
    if not _can_view_article(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    article_payload = _serialize_article_detail(artifact)
    latest_render = VideoRender.objects.filter(article=artifact, status="succeeded").order_by("-requested_at").first()
    package_text = export_package_text(article_payload, _serialize_video_render(latest_render) if latest_render else None)
    response = HttpResponse(package_text, content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="article-{_artifact_slug(artifact) or artifact.id}-video-package.json"'
    return response


@csrf_exempt
def internal_video_render_detail(request: HttpRequest, render_id: str) -> JsonResponse:
    if auth_error := _require_internal_token(request):
        return auth_error
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    record = get_object_or_404(VideoRender.objects.select_related("article"), id=render_id)
    return JsonResponse(
        {
            "render": _serialize_video_render(record),
            "article": _serialize_article_detail(record.article),
            "video_spec_json": _video_spec(record.article),
        }
    )


@csrf_exempt
def internal_video_render_status(request: HttpRequest, render_id: str) -> JsonResponse:
    if auth_error := _require_internal_token(request):
        return auth_error
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    record = get_object_or_404(VideoRender, id=render_id)
    payload = _parse_json(request)
    status = str(payload.get("status") or "").strip().lower()
    if status not in {"queued", "running", "canceled"}:
        return JsonResponse({"error": "invalid status"}, status=400)
    record.status = status
    if status == "running" and not record.started_at:
        record.started_at = timezone.now()
    if status == "canceled":
        record.completed_at = timezone.now()
    record.save(update_fields=["status", "started_at", "completed_at", "updated_at"])
    return JsonResponse({"render": _serialize_video_render(record)})


@csrf_exempt
def internal_video_render_complete(request: HttpRequest, render_id: str) -> JsonResponse:
    if auth_error := _require_internal_token(request):
        return auth_error
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    record = get_object_or_404(VideoRender.objects.select_related("article"), id=render_id)
    payload = _parse_json(request)
    record.provider = str(payload.get("provider") or record.provider or "unknown")
    record.status = "succeeded"
    record.started_at = record.started_at or timezone.now()
    record.completed_at = timezone.now()
    record.result_payload_json = sanitize_payload(payload.get("result_payload_json") if isinstance(payload.get("result_payload_json"), dict) else {})
    record.output_assets = sanitize_payload(payload.get("output_assets") if isinstance(payload.get("output_assets"), list) else [])
    record.error_message = ""
    record.error_details_json = {}
    record.save(
        update_fields=[
            "provider",
            "status",
            "started_at",
            "completed_at",
            "result_payload_json",
            "output_assets",
            "error_message",
            "error_details_json",
            "updated_at",
        ]
    )
    article = record.article
    spec = _video_spec(article)
    spec["generation"] = {
        **(spec.get("generation") if isinstance(spec.get("generation"), dict) else {}),
        "provider": record.provider,
        "model_name": record.model_name or "",
        "status": "succeeded",
        "last_render_id": str(record.id),
        "spec_snapshot_hash": record.spec_snapshot_hash or "",
        "input_snapshot_hash": record.input_snapshot_hash or "",
        "context_pack_id": str(record.context_pack_id) if record.context_pack_id else None,
        "context_pack_version": record.context_pack_version or "",
        "context_pack_updated_at": record.context_pack_updated_at.isoformat() if record.context_pack_updated_at else None,
        "context_pack_hash": record.context_pack_hash or "",
        "updated_at": timezone.now().isoformat(),
    }
    article.video_spec_json = spec
    article.video_latest_render = record
    article.save(update_fields=["video_spec_json", "video_latest_render", "updated_at"])
    return JsonResponse({"render": _serialize_video_render(record)})


@csrf_exempt
def internal_video_render_error(request: HttpRequest, render_id: str) -> JsonResponse:
    if auth_error := _require_internal_token(request):
        return auth_error
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    record = get_object_or_404(VideoRender.objects.select_related("article"), id=render_id)
    payload = _parse_json(request)
    record.status = "failed"
    record.started_at = record.started_at or timezone.now()
    record.completed_at = timezone.now()
    record.error_message = str(payload.get("error") or "render failed")
    details = payload.get("error_details_json") if isinstance(payload.get("error_details_json"), dict) else {}
    record.error_details_json = sanitize_payload(details)
    record.save(update_fields=["status", "started_at", "completed_at", "error_message", "error_details_json", "updated_at"])
    article = record.article
    spec = _video_spec(article)
    spec["generation"] = {
        **(spec.get("generation") if isinstance(spec.get("generation"), dict) else {}),
        "provider": record.provider,
        "model_name": record.model_name or "",
        "status": "failed",
        "last_render_id": str(record.id),
        "spec_snapshot_hash": record.spec_snapshot_hash or "",
        "input_snapshot_hash": record.input_snapshot_hash or "",
        "context_pack_id": str(record.context_pack_id) if record.context_pack_id else None,
        "context_pack_version": record.context_pack_version or "",
        "context_pack_updated_at": record.context_pack_updated_at.isoformat() if record.context_pack_updated_at else None,
        "context_pack_hash": record.context_pack_hash or "",
        "updated_at": timezone.now().isoformat(),
    }
    article.video_spec_json = spec
    article.save(update_fields=["video_spec_json", "updated_at"])
    return JsonResponse({"render": _serialize_video_render(record)})


@csrf_exempt
def article_transition(request: HttpRequest, article_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _can_manage_articles(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    artifact = _resolve_article_or_404(article_id)
    payload = _parse_json(request)
    to_status = str(payload.get("to_status") or "").strip().lower()
    if to_status not in ARTICLE_STATUS_CHOICES:
        return JsonResponse({"error": "invalid to_status"}, status=400)
    if to_status == artifact.status:
        return JsonResponse({"article": _serialize_article_detail(artifact)})
    allowed = ARTICLE_TRANSITIONS.get(artifact.status, set())
    if to_status not in allowed:
        return JsonResponse({"error": f"invalid transition {artifact.status} -> {to_status}"}, status=400)
    from_status = artifact.status
    artifact.status = to_status
    artifact.artifact_state = _artifact_state_for_status(to_status)
    update_fields = ["status", "artifact_state", "updated_at"]
    if to_status == "published":
        validation_status, validation_errors = validate_artifact(artifact)
        content_hash = compute_content_hash(artifact)
        artifact.content_hash = content_hash
        artifact.validation_status = validation_status
        artifact.validation_errors_json = validation_errors or []
        update_fields.extend(["content_hash", "validation_status", "validation_errors_json"])
        if validation_status == "fail":
            return JsonResponse(
                {"error": "artifact validation failed", "validation_status": validation_status, "validation_errors": validation_errors},
                status=400,
            )
        artifact.published_at = timezone.now()
        artifact.ratified_by = identity
        artifact.ratified_at = timezone.now()
        if _article_visibility_type_from_artifact(artifact) == "private":
            scope = dict(artifact.scope_json or {})
            scope["visibility_type"] = "public"
            artifact.scope_json = scope
            artifact.visibility = "public"
            update_fields.extend(["scope_json", "visibility"])
        update_fields.extend(["published_at", "ratified_by", "ratified_at"])
    artifact.save(update_fields=list(dict.fromkeys(update_fields)))
    _record_artifact_event(artifact, "article_status_changed", identity, {"from": from_status, "to": to_status})
    if to_status == "published":
        _record_artifact_event(artifact, "article_published", identity, {"status": "published"})
        emit_ledger_event(
            actor=identity,
            action="artifact.update",
            artifact=artifact,
            summary="Published Article artifact",
            metadata={
                "validation_status": artifact.validation_status,
                "content_hash": artifact.content_hash,
                "status": "published",
            },
            dedupe_key=make_dedupe_key(
                "artifact.update",
                str(artifact.id),
                diff_payload={
                    "validation_status": artifact.validation_status,
                    "content_hash": artifact.content_hash,
                    "status": "published",
                },
            ),
        )
    if to_status == "deprecated":
        _record_artifact_event(artifact, "article_deprecated", identity, {"status": "deprecated"})
    return JsonResponse({"article": _serialize_article_detail(artifact)})


@csrf_exempt
def docs_by_route(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    route_id = str(request.GET.get("route_id") or "").strip()
    if not route_id:
        return JsonResponse({"error": "route_id is required"}, status=400)
    _ensure_doc_artifact_type()
    _ensure_article_artifact_type()
    workspace_id = str(request.GET.get("workspace_id") or "").strip()
    guide_article_qs = Artifact.objects.filter(type__slug=ARTICLE_ARTIFACT_TYPE_SLUG).select_related("type", "workspace", "author")
    if workspace_id:
        guide_article_qs = guide_article_qs.filter(workspace_id=workspace_id)
    candidates: list[Artifact] = []
    for artifact in guide_article_qs.order_by("-published_at", "-updated_at", "-created_at"):
        if _article_category(artifact) not in GUIDE_ARTICLE_CATEGORIES:
            continue
        if not _can_view_article(identity, artifact):
            continue
        bindings = _article_route_bindings(artifact)
        if route_id in bindings:
            candidates.append(artifact)
    if candidates:
        return JsonResponse({"doc": _article_to_doc_page_payload(candidates[0]), "route_id": route_id})

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
    _ensure_doc_artifact_type()
    article_type = _ensure_article_artifact_type()
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
        visibility_type = "public" if visibility == "public" else ("private" if visibility == "private" else "authenticated")
        route_bindings = _normalize_doc_route_bindings(payload.get("route_bindings"))
        tags = _normalize_doc_tags(payload.get("tags"))
        summary = str(payload.get("summary") or "")
        body_markdown = str(payload.get("body_markdown") or "")
        category_slug = _normalize_article_category(payload.get("category"), fallback=_derive_guide_category(tags))
        category = _resolve_article_category_slug(category_slug, allow_disabled=True)
        if not category:
            return JsonResponse({"error": f"unknown category: {category_slug}"}, status=400)
        with transaction.atomic():
            artifact = Artifact.objects.create(
                workspace=docs_workspace,
                type=article_type,
                title=title,
                slug=slug,
                status="draft",
                version=1,
                visibility=visibility,
                author=identity,
                custodian=identity,
                scope_json={
                    "route_bindings": route_bindings,
                    "slug": slug,
                    "category": category.slug,
                    "visibility_type": visibility_type,
                    "allowed_roles": [],
                    "tags": tags,
                },
                article_category=category,
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
            _record_artifact_event(artifact, "article_created", identity, {"category": category.slug, "route_bindings": route_bindings})
            for route in route_bindings:
                value = str(route or "").strip()
                if not value:
                    continue
                PublishBinding.objects.get_or_create(
                    scope_type="article",
                    scope_id=artifact.id,
                    target_type="xyn_ui_route",
                    target_value=value,
                    defaults={"label": "Route", "enabled": True},
                )
        return JsonResponse({"doc": _article_to_doc_page_payload(artifact, revision)})

    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    tags_query = str(request.GET.get("tags") or "").strip()
    tags_filter = {tag.strip().lower() for tag in tags_query.split(",") if tag.strip()} if tags_query else set()
    include_drafts = request.GET.get("include_drafts") == "1"
    docs: list[Dict[str, Any]] = []

    article_qs = Artifact.objects.filter(type=article_type).select_related("type", "workspace")
    for artifact in article_qs.order_by("-published_at", "-updated_at", "-created_at"):
        if _article_category(artifact) not in GUIDE_ARTICLE_CATEGORIES:
            continue
        if (not _can_manage_docs(identity) or not include_drafts) and artifact.status != "published":
            continue
        if not _can_view_article(identity, artifact):
            continue
        serialized = _article_to_doc_page_payload(artifact)
        doc_tags = set(serialized.get("tags") or [])
        if tags_filter and not tags_filter.issubset(doc_tags):
            continue
        docs.append(serialized)

    # Backward-compatible fallback for legacy doc_page artifacts.
    if not docs:
        qs = Artifact.objects.filter(type__slug=DOC_ARTIFACT_TYPE_SLUG).select_related("type", "workspace")
        if not _can_manage_docs(identity) or not include_drafts:
            qs = qs.filter(status="published", visibility__in=["public", "team"])
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
    article = Artifact.objects.select_related("type").filter(type__slug=ARTICLE_ARTIFACT_TYPE_SLUG, slug=slug).first()
    if article and _article_category(article) in GUIDE_ARTICLE_CATEGORIES:
        if not _can_view_article(identity, article):
            return JsonResponse({"error": "forbidden"}, status=403)
        return JsonResponse({"doc": _article_to_doc_page_payload(article)})
    artifact = get_object_or_404(Artifact.objects.select_related("type"), type__slug=DOC_ARTIFACT_TYPE_SLUG, slug=slug)
    if not _can_view_doc(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    return JsonResponse({"doc": _serialize_doc_page(artifact)})


@csrf_exempt
def doc_detail(request: HttpRequest, doc_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    artifact = get_object_or_404(Artifact.objects.select_related("type"), id=doc_id)
    if request.method in {"PUT", "PATCH"}:
        if not _can_manage_docs(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        if artifact.type.slug == ARTICLE_ARTIFACT_TYPE_SLUG:
            payload = _parse_json(request)
            scope_payload: Dict[str, Any] = {}
            if "route_bindings" in payload:
                scope_payload["route_bindings"] = _normalize_doc_route_bindings(payload.get("route_bindings"))
            if "tags" in payload:
                scope_payload["tags"] = _normalize_doc_tags(payload.get("tags"))
            if "visibility" in payload:
                raw_visibility = str(payload.get("visibility") or "").strip().lower()
                if raw_visibility not in {"private", "team", "public"}:
                    return JsonResponse({"error": "invalid visibility"}, status=400)
                scope_payload["visibility_type"] = (
                    "public" if raw_visibility == "public" else ("private" if raw_visibility == "private" else "authenticated")
                )
            article_update_payload = {
                "title": payload.get("title"),
                "slug": payload.get("slug"),
                "route_bindings": scope_payload.get("route_bindings"),
                "tags": scope_payload.get("tags"),
                "visibility_type": scope_payload.get("visibility_type"),
                "category": payload.get("category"),
            }
            article_update_payload = {key: value for key, value in article_update_payload.items() if value is not None}
            if article_update_payload:
                latest = _latest_artifact_revision(artifact)
                content = dict((latest.content_json if latest else {}) or {})
                scope = dict(artifact.scope_json or {})
                if "title" in article_update_payload:
                    artifact.title = str(article_update_payload["title"] or artifact.title).strip() or artifact.title
                    content["title"] = artifact.title
                if "slug" in article_update_payload:
                    normalized_slug = _normalize_artifact_slug(str(article_update_payload.get("slug") or ""), fallback_title=artifact.title)
                    if not normalized_slug:
                        return JsonResponse({"error": "slug is required"}, status=400)
                    if _artifact_slug_exists(str(artifact.workspace_id), normalized_slug, exclude_artifact_id=str(artifact.id)):
                        return JsonResponse({"error": "slug already exists in docs workspace"}, status=400)
                    artifact.slug = normalized_slug
                    scope["slug"] = normalized_slug
                if "route_bindings" in article_update_payload:
                    route_bindings = _normalize_doc_route_bindings(article_update_payload.get("route_bindings"))
                    scope["route_bindings"] = route_bindings
                    existing = PublishBinding.objects.filter(scope_type="article", scope_id=artifact.id, target_type="xyn_ui_route")
                    existing_values = {row.target_value: row for row in existing}
                    requested = set(route_bindings)
                    for value, row in existing_values.items():
                        if value not in requested:
                            row.enabled = False
                            row.save(update_fields=["enabled", "updated_at"])
                    for value in requested:
                        PublishBinding.objects.update_or_create(
                            scope_type="article",
                            scope_id=artifact.id,
                            target_type="xyn_ui_route",
                            target_value=value,
                            defaults={"label": "Route", "enabled": True},
                        )
                if "tags" in article_update_payload:
                    scope["tags"] = _normalize_doc_tags(article_update_payload.get("tags"))
                    content["tags"] = _normalize_doc_tags(article_update_payload.get("tags"))
                if "visibility_type" in article_update_payload:
                    visibility_type = _normalize_article_visibility_type(article_update_payload.get("visibility_type"), fallback="authenticated")
                    scope["visibility_type"] = visibility_type
                    artifact.visibility = _artifact_visibility_for_article_type(visibility_type)
                if "category" in article_update_payload:
                    category_slug = _normalize_article_category(article_update_payload.get("category"), fallback="guide")
                    category = _resolve_article_category_slug(category_slug, allow_disabled=True)
                    if category:
                        artifact.article_category = category
                        scope["category"] = category.slug
                if "summary" in payload:
                    content["summary"] = str(payload.get("summary") or "")
                if "body_markdown" in payload:
                    content["body_markdown"] = str(payload.get("body_markdown") or "")
                artifact.scope_json = scope
                artifact.version = _next_artifact_revision_number(artifact)
                artifact.save(update_fields=["title", "slug", "visibility", "scope_json", "article_category", "version", "updated_at"])
                revision = ArtifactRevision.objects.create(
                    artifact=artifact,
                    revision_number=artifact.version,
                    content_json=content,
                    created_by=identity,
                )
                _record_artifact_event(artifact, "article_revision_created", identity, {"revision_number": artifact.version, "source": "manual"})
                return JsonResponse({"doc": _article_to_doc_page_payload(artifact, revision)})
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
    if artifact.type.slug == ARTICLE_ARTIFACT_TYPE_SLUG:
        if not _can_view_article(identity, artifact):
            return JsonResponse({"error": "forbidden"}, status=403)
        return JsonResponse({"doc": _article_to_doc_page_payload(artifact)})
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
    artifact = get_object_or_404(Artifact, id=doc_id)
    if artifact.type.slug == ARTICLE_ARTIFACT_TYPE_SLUG:
        if _article_category(artifact) not in GUIDE_ARTICLE_CATEGORIES:
            return JsonResponse({"error": "not a guide article"}, status=400)
        artifact.status = "published"
        if artifact.visibility == "private":
            artifact.visibility = "team"
            scope = dict(artifact.scope_json or {})
            scope["visibility_type"] = "authenticated"
            artifact.scope_json = scope
            update_fields = ["status", "visibility", "scope_json", "published_at", "ratified_by", "ratified_at", "updated_at"]
        else:
            update_fields = ["status", "published_at", "ratified_by", "ratified_at", "updated_at"]
        artifact.published_at = timezone.now()
        artifact.ratified_by = identity
        artifact.ratified_at = timezone.now()
        artifact.save(update_fields=update_fields)
        _record_artifact_event(artifact, "article_published", identity, {"status": "published"})
        return JsonResponse({"doc": _article_to_doc_page_payload(artifact)})
    if artifact.type.slug != DOC_ARTIFACT_TYPE_SLUG:
        return JsonResponse({"error": "unsupported artifact type"}, status=400)
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
    _ensure_workflow_artifact_type()
    artifact = (
        Artifact.objects.filter(
            type__slug=WORKFLOW_ARTIFACT_TYPE_SLUG,
            slug=tour_slug,
            workflow_profile="tour",
            status="published",
        )
        .select_related("type", "workspace", "article_category")
        .first()
    )
    if not artifact:
        return JsonResponse({"error": "tour not found"}, status=404)
    if not _can_view_workflow(identity, artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    spec = _normalize_workflow_spec(
        artifact.workflow_spec_json if isinstance(artifact.workflow_spec_json, dict) else {},
        profile="tour",
        title=artifact.title,
        category_slug=_article_category(artifact),
    )
    errors = _validate_workflow_spec(spec, profile="tour")
    if errors:
        return JsonResponse({"error": "invalid workflow spec", "details": errors}, status=500)
    payload = {
        "workflow_id": str(artifact.id),
        "slug": _artifact_slug(artifact),
        "title": artifact.title,
        "description": str(spec.get("description") or ""),
        "schema_version": int(spec.get("schema_version") or WORKFLOW_SCHEMA_VERSION),
        "profile": "tour",
        "category_slug": str(spec.get("category_slug") or WORKFLOW_DEFAULT_CATEGORY),
        "settings": spec.get("settings") if isinstance(spec.get("settings"), dict) else {"allow_skip": True, "show_progress": True},
        "steps": spec.get("steps") if isinstance(spec.get("steps"), list) else [],
        "entry": spec.get("entry") if isinstance(spec.get("entry"), dict) else {},
    }
    return JsonResponse(payload)


@csrf_exempt
def intent_scripts_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    scope_type = str(request.GET.get("scope_type") or "").strip().lower()
    scope_ref_id = str(request.GET.get("scope_ref_id") or "").strip()
    scope = str(request.GET.get("scope") or "").strip()
    if scope and ":" in scope:
        lhs, rhs = scope.split(":", 1)
        scope_type = scope_type or lhs.strip().lower()
        scope_ref_id = scope_ref_id or rhs.strip()
    elif scope:
        scope_type = scope_type or scope.lower()
    qs = IntentScript.objects.select_related("created_by", "artifact").order_by("-created_at")
    if scope_type:
        qs = qs.filter(scope_type=scope_type)
    if scope_ref_id:
        qs = qs.filter(scope_ref_id=scope_ref_id)
    rows: List[Dict[str, Any]] = []
    for row in qs[:300]:
        if row.artifact_id and row.artifact and not _can_view_generic_artifact(identity, row.artifact):
            continue
        rows.append(_serialize_intent_script(row))
    return JsonResponse({"items": rows})


@csrf_exempt
def intent_script_detail(request: HttpRequest, script_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    script = get_object_or_404(IntentScript.objects.select_related("artifact", "created_by"), id=script_id)
    if script.artifact_id and script.artifact and not _can_view_generic_artifact(identity, script.artifact):
        return JsonResponse({"error": "forbidden"}, status=403)
    if request.method == "GET":
        return JsonResponse({"item": _serialize_intent_script(script)})
    if request.method not in {"PUT", "PATCH"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    if "title" in payload:
        script.title = str(payload.get("title") or "").strip() or script.title
    if "status" in payload:
        status = str(payload.get("status") or "").strip().lower()
        if status in {"draft", "final"}:
            script.status = status
    if "script_text" in payload:
        script.script_text = str(payload.get("script_text") or "")
    if "script_json" in payload and isinstance(payload.get("script_json"), dict):
        script.script_json = payload.get("script_json")
    script.save(update_fields=["title", "status", "script_text", "script_json", "updated_at"])
    return JsonResponse({"item": _serialize_intent_script(script)})


@csrf_exempt
def intent_script_generate(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    scope_type = str(payload.get("scope_type") or "").strip().lower()
    scope_ref_id = str(payload.get("scope_ref_id") or "").strip()
    audience = str(payload.get("audience") or "developer").strip().lower()
    tone = str(payload.get("tone") or "clear, confident").strip()
    length_target = str(payload.get("length_target") or "short").strip()
    if scope_type not in {"tour", "artifact", "manual"}:
        return JsonResponse({"error": "scope_type must be tour|artifact|manual"}, status=400)
    if not scope_ref_id and scope_type != "manual":
        return JsonResponse({"error": "scope_ref_id required"}, status=400)

    title = "Intent Script"
    script_json: Dict[str, Any] = {"scenes": [], "metadata": {"audience": audience, "tone": tone, "length_target": length_target, "dependencies": []}}
    script_text = ""
    linked_artifact: Optional[Artifact] = None

    if scope_type == "tour":
        artifact = Artifact.objects.filter(type__slug=WORKFLOW_ARTIFACT_TYPE_SLUG, id=scope_ref_id).first()
        if not artifact:
            artifact = Artifact.objects.filter(type__slug=WORKFLOW_ARTIFACT_TYPE_SLUG, slug=scope_ref_id).first()
        if not artifact:
            return JsonResponse({"error": "tour not found"}, status=404)
        if not _can_view_workflow(identity, artifact):
            return JsonResponse({"error": "forbidden"}, status=403)
        linked_artifact = artifact
        title = f"{artifact.title} Intent Script"
        script_json, script_text = _generate_intent_script_for_tour(artifact, audience=audience, tone=tone, length_target=length_target)
    elif scope_type == "artifact":
        artifact = Artifact.objects.select_related("type").filter(id=scope_ref_id).first()
        if not artifact:
            return JsonResponse({"error": "artifact not found"}, status=404)
        if not _can_view_generic_artifact(identity, artifact):
            return JsonResponse({"error": "forbidden"}, status=403)
        linked_artifact = artifact
        title = f"{artifact.title} Intent Script"
        if artifact.type.slug == "article":
            if artifact.format == "video_explainer":
                existing_scenes = _explainer_scenes_payload_for_intent_script(artifact)
                if len(existing_scenes) >= 3:
                    script_json, script_text = _intent_script_from_existing_scenes(
                        artifact.title,
                        existing_scenes,
                        audience=audience,
                        tone=tone,
                        length_target=length_target,
                    )
                else:
                    return JsonResponse(
                        {
                            "status": "MissingFields",
                            "message": "Add scenes to the explainer draft before generating an intent script.",
                            "missing_fields": [
                                {"field": "scenes", "reason": "Explainer scenes are required", "options_available": False},
                            ],
                        },
                        status=400,
                    )
            else:
                content_payload = _article_content_payload_for_intent_script(artifact)
                validation_error = _article_intent_script_validation_error(content_payload)
                if validation_error:
                    return JsonResponse(
                        {
                            "status": "MissingFields",
                            "message": validation_error,
                            "missing_fields": [
                                {"field": "summary", "reason": "Add summary text or article body", "options_available": False},
                                {"field": "body", "reason": "Add summary text or article body", "options_available": False},
                            ],
                        },
                        status=400,
                    )
                script_json, script_text = _generate_intent_script_for_article_content(
                    content_payload, audience=audience, tone=tone, length_target=length_target
                )
            title = str(script_json.get("title") or title)
        else:
            script_json, script_text = _generate_intent_script_for_artifact(artifact, audience=audience, tone=tone, length_target=length_target)
    else:
        title = str(payload.get("title") or "Manual Intent Script").strip() or "Manual Intent Script"
        script_json = {
            "scenes": [
                _intent_scene(
                    "s1",
                    "Narrative setup",
                    outcome="Describe the objective, inputs, and expected output.",
                )
            ],
            "metadata": {"audience": audience, "tone": tone, "length_target": length_target, "dependencies": []},
        }
        script_text = _compose_intent_text(title, script_json["scenes"])

    row = IntentScript.objects.create(
        title=title,
        scope_type=scope_type,
        scope_ref_id=scope_ref_id or "",
        format_version="1",
        script_json=script_json,
        script_text=script_text,
        artifact=linked_artifact,
        created_by=identity,
        status="draft",
    )

    if linked_artifact is not None:
        emit_ledger_event(
            actor=identity,
            action="artifact.update",
            artifact=linked_artifact,
            summary=f"Generated intent script for {linked_artifact.type.slug}",
            metadata={"intent_script_id": str(row.id), "scope_type": scope_type, "audience": audience},
            dedupe_key=make_dedupe_key("artifact.update", str(linked_artifact.id), diff_payload={"intent_script_id": str(row.id)}),
        )

    return JsonResponse({"item": _serialize_intent_script(row)})


def _ensure_default_agent_purposes() -> None:
    try:
        ensure_default_ai_seeds()
    except Exception:
        logger.exception("Failed to ensure default AI seeds; continuing without blocking request")


def _serialize_agent_purpose(purpose: AgentPurpose) -> Dict[str, Any]:
    model = purpose.model_config
    provider = model.provider if model else None
    references = get_purpose_reference_summary(purpose.id)
    return {
        "slug": purpose.slug,
        "name": purpose.name or purpose.slug.replace("-", " ").title(),
        "description": purpose.description or "",
        "status": purpose.status or "active",
        "enabled": (purpose.status or "active") == "active",
        "preamble": purpose.preamble or "",
        "referenced_by": references,
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


def get_purpose_reference_summary(purpose_id: Any) -> Dict[str, int]:
    return {
        "agents": AgentDefinitionPurpose.objects.filter(purpose_id=purpose_id).count(),
    }


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


def _serialize_agent_default_context_pack_ref(ref: Any) -> Optional[Dict[str, Any]]:
    pack = _resolve_context_pack_ref(ref)
    if not pack:
        return None
    return {
        "id": str(pack.id),
        "slug": pack.name,
        "name": pack.name,
        "purpose": pack.purpose,
        "scope": pack.scope,
        "version": pack.version,
        "content_hash": _context_pack_content_hash(pack),
        "state": "canonical" if pack.is_active else "deprecated",
        "is_active": bool(pack.is_active),
    }


def _normalize_agent_default_context_pack_refs(raw_refs: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    refs: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for raw_ref in _normalize_pack_refs_input(raw_refs):
        pack = _resolve_context_pack_ref(raw_ref)
        if not pack:
            return [], "context pack ref not found"
        key = str(pack.id)
        if key in seen:
            continue
        seen.add(key)
        refs.append(
            {
                "id": str(pack.id),
                "name": pack.name,
                "purpose": pack.purpose,
                "scope": pack.scope,
                "version": pack.version,
            }
        )
    return refs, None


def _model_config_compat_payload(config: ModelConfig) -> Dict[str, Any]:
    base_params = {
        "temperature": config.temperature,
        "top_p": config.top_p,
        "max_tokens": config.max_tokens,
    }
    effective_params, warnings = compute_effective_params(
        provider=str(config.provider.slug or ""),
        model_name=str(config.model_name or ""),
        base_params=base_params,
        invocation_mode="chat",
    )
    return {
        "provider": config.provider.slug,
        "model_name": config.model_name,
        "effective_params": effective_params,
        "warnings": warnings,
    }


def _serialize_agent_definition(agent: AgentDefinition) -> Dict[str, Any]:
    purpose_slugs = [item.slug for item in agent.purposes.all().order_by("slug")]
    default_refs = agent.context_pack_refs_json if isinstance(agent.context_pack_refs_json, list) else []
    default_context_packs = [item for item in (_serialize_agent_default_context_pack_ref(ref) for ref in default_refs) if item]
    return {
        "id": str(agent.id),
        "slug": agent.slug,
        "name": agent.name,
        "model_config_id": str(agent.model_config_id),
        "model_config": _serialize_model_config(agent.model_config),
        "override_prompt_text": agent.system_prompt_text or "",
        "default_context_pack_refs_json": default_refs,
        "default_context_packs": default_context_packs,
        # Backward-compatible aliases.
        "system_prompt_text": agent.system_prompt_text or "",
        "context_pack_refs_json": default_refs,
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
        config.enabled = False
        config.save(update_fields=["enabled", "updated_at"])
        return JsonResponse(
            {
                "model_config": _serialize_model_config(config),
                "status": "deprecated",
                "message": "Model config deprecated (disabled).",
            }
        )
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
def ai_model_config_compat(request: HttpRequest, model_config_id: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if not _can_manage_ai(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    config = get_object_or_404(ModelConfig.objects.select_related("provider"), id=model_config_id)
    return JsonResponse(_model_config_compat_payload(config))


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
        system_prompt_text=str(payload.get("override_prompt_text") or payload.get("system_prompt_text") or ""),
        context_pack_refs_json=[],
        is_default=bool(payload.get("is_default", False)),
        enabled=bool(payload.get("enabled", True)),
    )
    raw_default_refs = payload.get("default_context_pack_refs_json")
    if raw_default_refs is None:
        raw_default_refs = payload.get("context_pack_refs_json")
    if raw_default_refs is not None:
        refs, ref_err = _normalize_agent_default_context_pack_refs(raw_default_refs)
        if ref_err:
            agent.delete()
            return JsonResponse({"error": ref_err}, status=400)
        agent.context_pack_refs_json = refs
        agent.save(update_fields=["context_pack_refs_json", "updated_at"])
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
    if "override_prompt_text" in payload or "system_prompt_text" in payload:
        agent.system_prompt_text = str(payload.get("override_prompt_text") or payload.get("system_prompt_text") or "")
    if "default_context_pack_refs_json" in payload or "context_pack_refs_json" in payload:
        raw_default_refs = payload.get("default_context_pack_refs_json")
        if raw_default_refs is None:
            raw_default_refs = payload.get("context_pack_refs_json")
        refs, ref_err = _normalize_agent_default_context_pack_refs(raw_default_refs)
        if ref_err:
            return JsonResponse({"error": ref_err}, status=400)
        agent.context_pack_refs_json = refs
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


def _intent_apply_create_draft(
    *,
    identity: UserIdentity,
    payload: Dict[str, Any],
    request_id: str,
) -> JsonResponse:
    if not _can_manage_articles(identity):
        return JsonResponse({"error": "forbidden"}, status=403)

    contract = _intent_contract_registry().get("ArticleDraft")
    if contract is None:
        return JsonResponse({"error": "intake contract unavailable"}, status=500)
    merged = contract.merge_defaults(payload or {})
    merged["format"] = contract.normalize_format(merged.get("format"))
    missing = contract.missing_fields(merged)
    if missing:
        return JsonResponse(
            {
                "status": "MissingFields",
                "action_type": "CreateDraft",
                "artifact_type": "ArticleDraft",
                "summary": "Draft requires additional fields before it can proceed.",
                "missing_fields": [
                    {
                        "field": field_name,
                        "reason": "required by intake contract",
                        "options_available": contract.options_available(field_name),
                    }
                    for field_name in missing
                ],
                "audit": {
                    "request_id": request_id,
                    "timestamp": timezone.now().isoformat(),
                    **_intent_context_pack_audit(),
                },
            },
            status=400,
        )

    title = str(merged.get("title") or "").strip()
    category_slug = str(merged.get("category") or "").strip().lower()
    external_format = str(merged.get("format") or "article").strip().lower()
    intent_value = str(merged.get("intent") or "").strip()
    duration_value = str(merged.get("duration") or "").strip()
    tags = _normalize_doc_tags(merged.get("tags"))
    summary = str(merged.get("summary") or "")
    body_markdown = str(merged.get("body") or "")

    category = _resolve_article_category_slug(category_slug, allow_disabled=False)
    if not category:
        return JsonResponse({"error": f"unknown category: {category_slug}"}, status=400)

    workspace = _resolve_article_workspace(identity, str(payload.get("workspace_id") or "")) or _docs_workspace()
    slug = _normalize_artifact_slug(str(payload.get("slug") or ""), fallback_title=title)
    if not slug:
        slug = _normalize_artifact_slug("", fallback_title=title)
    if _artifact_slug_exists(str(workspace.id), slug):
        slug = _normalize_artifact_slug(f"{slug}-{uuid.uuid4().hex[:6]}", fallback_title=title)

    article_type = _ensure_article_artifact_type()
    try:
        internal_format = intent_to_internal_format(external_format)
    except PatchValidationError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    video_spec = None
    scaffold_quality = "none"
    video_context_pack = None
    if internal_format == "video_explainer":
        generation_fields = _extract_explainer_generation_fields(
            title=title,
            intent=intent_value,
            summary=summary,
            description=str(merged.get("description") or body_markdown or summary),
            audience=str(merged.get("audience") or ""),
            category=category.slug,
        )
        video_spec, scaffold_quality = _build_explainer_video_spec(
            title=title,
            summary=summary,
            intent=generation_fields.get("topic") or intent_value or title,
            topic=generation_fields.get("topic") or "",
            grounding=generation_fields.get("grounding") or "",
            category=generation_fields.get("category") or "",
            duration=duration_value,
            audience=generation_fields.get("audience") or "",
            description=str(merged.get("description") or body_markdown or summary),
        )
        spec_errors = validate_video_spec(video_spec, require_scenes=True)
        if spec_errors:
            return JsonResponse({"error": "invalid video spec", "details": spec_errors}, status=400)
        video_context_pack, pack_error = _resolve_video_context_pack_for_article(
            None,
            payload.get("video_context_pack_id") if isinstance(payload, dict) else None,
            allow_clear=False,
        )
        if pack_error:
            return pack_error
        summary, body_markdown = _derive_explainer_initial_content(
            title=title,
            summary=summary,
            body_markdown=body_markdown,
            scenes=video_spec.get("scenes") if isinstance(video_spec.get("scenes"), list) else [],
        )

    with transaction.atomic():
        artifact = Artifact.objects.create(
            workspace=workspace,
            type=article_type,
            title=title,
            slug=slug,
            format=internal_format,
            status="draft",
            version=1,
            visibility=_artifact_visibility_for_article_type("private"),
            author=identity,
            custodian=identity,
            scope_json={
                "slug": slug,
                "category": category.slug,
                "visibility_type": "private",
                "allowed_roles": [],
                "route_bindings": [],
                "tags": tags,
            },
            article_category=category,
            video_spec_json=video_spec,
            video_context_pack=video_context_pack if internal_format == "video_explainer" else None,
        )
        ArtifactRevision.objects.create(
            artifact=artifact,
            revision_number=1,
            content_json={
                "title": title,
                "summary": summary,
                "body_markdown": body_markdown,
                "body_html": "",
                "tags": tags,
            },
            created_by=identity,
        )
        ArtifactExternalRef.objects.update_or_create(
            artifact=artifact,
            system="shine",
            defaults={"external_id": str(artifact.id), "slug_path": slug},
        )
        emit_ledger_event(
            actor=identity,
            action="draft.created",
            artifact=artifact,
            summary="Created Article draft via intent engine",
            metadata={"fields_set": sorted([k for k in ["title", "category", "format", "intent", "duration"] if str(merged.get(k) or "").strip()])},
            dedupe_key=f"draft.created:{artifact.id}",
        )
        if internal_format == "video_explainer" and isinstance(video_spec, dict):
            emit_ledger_event(
                actor=identity,
                action="draft.scaffolded",
                artifact=artifact,
                summary="Generated initial explainer scenes scaffold",
                metadata={
                    "scene_count": len(video_spec.get("scenes") or []) if isinstance(video_spec.get("scenes"), list) else 0,
                    "scaffold_quality": scaffold_quality,
                },
                dedupe_key=f"draft.scaffolded:{artifact.id}",
            )

    intent_telemetry_increment("apply_success")
    payload_response = {
        "status": "DraftReady",
        "action_type": "CreateDraft",
        "artifact_type": "ArticleDraft",
        "artifact_id": str(artifact.id),
        "summary": "Draft created successfully.",
        "next_actions": [{"label": "Open editor", "action": "OpenEditor"}],
        "audit": {
            "request_id": request_id,
            "timestamp": timezone.now().isoformat(),
            **_intent_context_pack_audit(),
        },
    }
    _audit_intent_event(
        message="intent.apply",
        identity=identity,
        request_id=request_id,
        artifact_id=str(artifact.id),
        proposal={},
        resolution=payload_response,
    )
    return JsonResponse(payload_response)


def _intent_apply_patch(
    *,
    identity: UserIdentity,
    artifact_type: str,
    artifact_id: str,
    patch_object: Dict[str, Any],
    request_id: str,
) -> JsonResponse:
    if artifact_type == "ArticleDraft":
        artifact = _resolve_article_or_404(artifact_id)
        if not _can_edit_article(identity, artifact):
            return JsonResponse({"error": "forbidden"}, status=403)
        try:
            updated = intent_apply_patch(
                artifact=artifact,
                actor=identity,
                patch_object=patch_object,
                category_resolver=lambda: _intent_category_options(),
            )
        except PatchValidationError as exc:
            intent_telemetry_increment("apply_error")
            return JsonResponse(
                {
                    "status": "ValidationError",
                    "action_type": "ApplyPatch",
                    "artifact_type": "ArticleDraft",
                    "artifact_id": str(artifact.id),
                    "summary": "Patch failed deterministic validation.",
                    "validation_errors": [str(exc)],
                    "audit": {
                        "request_id": request_id,
                        "timestamp": timezone.now().isoformat(),
                        **_intent_context_pack_audit(),
                    },
                },
                status=400,
            )

        latest = ArtifactRevision.objects.filter(artifact=updated).order_by("-revision_number").first()
        current_content = dict((latest.content_json if latest else {}) or {})
        metadata = {
            "title": updated.title,
            "category": _article_category(updated),
            "format": _article_format(updated),
            "summary_hash": hashlib.sha256(str(current_content.get("summary") or "").encode("utf-8")).hexdigest(),
            "body_hash": hashlib.sha256(str(current_content.get("body_markdown") or "").encode("utf-8")).hexdigest(),
        }
        emit_ledger_event(
            actor=identity,
            action="draft.patched",
            artifact=updated,
            summary="Patched Article draft via intent engine",
            metadata=metadata,
            dedupe_key=f"draft.patched:{updated.id}:{hashlib.sha256(json.dumps(metadata, sort_keys=True).encode('utf-8')).hexdigest()}",
        )
        intent_telemetry_increment("apply_success")
        payload_response = {
            "status": "DraftReady",
            "action_type": "ApplyPatch",
            "artifact_type": "ArticleDraft",
            "artifact_id": str(updated.id),
            "summary": "Patch applied successfully.",
            "next_actions": [{"label": "Open editor", "action": "OpenEditor"}],
            "audit": {
                "request_id": request_id,
                "timestamp": timezone.now().isoformat(),
                **_intent_context_pack_audit(),
            },
        }
        _audit_intent_event(
            message="intent.apply",
            identity=identity,
            request_id=request_id,
            artifact_id=str(updated.id),
            proposal={"patch_object": patch_object},
            resolution=payload_response,
        )
        return JsonResponse(payload_response)

    artifact = _resolve_context_pack_artifact_or_404(artifact_id)
    if not _can_manage_docs(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    if str(artifact.source_ref_type or "") != "ContextPack":
        return JsonResponse({"error": "context pack target unavailable"}, status=404)
    pack = ContextPack.objects.filter(id=artifact.source_ref_id).first()
    if not pack:
        return JsonResponse({"error": "context pack target unavailable"}, status=404)
    try:
        updated_pack, hash_info, changes = intent_apply_context_pack_patch(
            pack=pack,
            actor=identity,
            patch_object=patch_object,
        )
    except PatchValidationError as exc:
        intent_telemetry_increment("apply_error")
        return JsonResponse(
            {
                "status": "ValidationError",
                "action_type": "ApplyPatch",
                "artifact_type": "ContextPack",
                "artifact_id": str(artifact.id),
                "summary": "Patch failed deterministic validation.",
                "validation_errors": [str(exc)],
                "audit": {
                    "request_id": request_id,
                    "timestamp": timezone.now().isoformat(),
                    **_intent_context_pack_audit(),
                },
            },
            status=400,
        )

    artifact.title = updated_pack.name
    artifact.summary = f"{updated_pack.purpose} · {updated_pack.scope} · v{updated_pack.version}"
    artifact.scope_json = {
        "purpose": updated_pack.purpose,
        "scope": updated_pack.scope,
        "namespace": updated_pack.namespace,
        "project_key": updated_pack.project_key,
    }
    artifact.save(update_fields=["title", "summary", "scope_json", "updated_at"])

    metadata = {
        "title": updated_pack.name,
        "format": (
            str((updated_pack.applies_to_json or {}).get("content_format") or "json")
            if isinstance(updated_pack.applies_to_json, dict)
            else "json"
        ),
        "changed_fields": [entry.get("field") for entry in changes if isinstance(entry, dict)],
        "before_content_hash": hash_info.get("before_hash"),
        "after_content_hash": hash_info.get("after_hash"),
    }
    emit_ledger_event(
        actor=identity,
        action="contextpack.patched",
        artifact=artifact,
        summary="Patched Context Pack via intent engine",
        metadata=metadata,
        dedupe_key=f"contextpack.patched:{artifact.id}:{hashlib.sha256(json.dumps(metadata, sort_keys=True).encode('utf-8')).hexdigest()}",
    )
    intent_telemetry_increment("apply_success")
    payload_response = {
        "status": "DraftReady",
        "action_type": "ApplyPatch",
        "artifact_type": "ContextPack",
        "artifact_id": str(artifact.id),
        "summary": "Context pack patch applied successfully.",
        "next_actions": [{"label": "Open editor", "action": "OpenEditor"}],
        "audit": {
            "request_id": request_id,
            "timestamp": timezone.now().isoformat(),
            **_intent_context_pack_audit(),
        },
    }
    _audit_intent_event(
        message="intent.apply",
        identity=identity,
        request_id=request_id,
        artifact_id=str(artifact.id),
        proposal={"patch_object": patch_object, "artifact_type": "ContextPack"},
        resolution=payload_response,
    )
    return JsonResponse(payload_response)


@csrf_exempt
def xyn_intent_resolve(request: HttpRequest) -> JsonResponse:
    if not _intent_engine_enabled():
        return JsonResponse({"error": "intent engine disabled"}, status=404)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    message = str(payload.get("message") or "").strip()
    if not message:
        return JsonResponse({"error": "message is required"}, status=400)

    context_payload = payload.get("context") if isinstance(payload.get("context"), dict) else {}
    context_artifact_id = str(context_payload.get("artifact_id") or "").strip()
    context_artifact_type = str(context_payload.get("artifact_type") or "").strip()
    context_artifact = None
    if context_artifact_id:
        normalized_context_type = str(context_artifact_type or "").strip().lower()
        if normalized_context_type in {"contextpack", "context_pack"}:
            context_artifact = _resolve_context_pack_artifact_or_404(context_artifact_id)
            if not _can_manage_docs(identity):
                return JsonResponse({"error": "forbidden"}, status=403)
        else:
            context_artifact = _resolve_article_or_404(context_artifact_id)
            if not _can_edit_article(identity, context_artifact):
                return JsonResponse({"error": "forbidden"}, status=403)
            if context_artifact_type and context_artifact_type not in {"ArticleDraft", "article"}:
                return JsonResponse({"error": "unsupported artifact_type context"}, status=400)

    engine = _intent_engine()
    result, proposal = engine.resolve(message=message, context=ResolutionContext(artifact=context_artifact))
    if context_artifact is not None:
        result["artifact_id"] = str(context_artifact.id)

    request_id = str((result.get("audit") or {}).get("request_id") or uuid.uuid4())
    intent_telemetry_increment(
        {
            "DraftReady": "resolve_success",
            "MissingFields": "resolve_missing_fields",
            "ValidationError": "resolve_validation_error",
        }.get(str(result.get("status") or ""), "resolve_success")
    )
    _audit_intent_event(
        message="intent.resolve",
        identity=identity,
        request_id=request_id,
        artifact_id=str(context_artifact.id) if context_artifact else None,
        proposal=proposal,
        resolution=result,
    )
    return JsonResponse(result)


@csrf_exempt
def xyn_intent_apply(request: HttpRequest) -> JsonResponse:
    if not _intent_engine_enabled():
        return JsonResponse({"error": "intent engine disabled"}, status=404)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)

    payload = _parse_json(request)
    action_type = str(payload.get("action_type") or "").strip()
    artifact_type = str(payload.get("artifact_type") or "").strip()
    body_payload = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
    request_id = str(uuid.uuid4())

    if action_type not in {"CreateDraft", "ApplyPatch"}:
        return JsonResponse({"error": "action_type must be CreateDraft or ApplyPatch"}, status=400)
    if artifact_type not in {"ArticleDraft", "ContextPack"}:
        return JsonResponse({"error": "artifact_type must be ArticleDraft or ContextPack"}, status=400)

    if action_type == "CreateDraft":
        if artifact_type != "ArticleDraft":
            return JsonResponse({"error": "CreateDraft currently supports ArticleDraft only"}, status=400)
        return _intent_apply_create_draft(identity=identity, payload=body_payload, request_id=request_id)

    artifact_id = str(payload.get("artifact_id") or "").strip()
    if not artifact_id:
        return JsonResponse({"error": "artifact_id is required for ApplyPatch"}, status=400)
    return _intent_apply_patch(
        identity=identity,
        artifact_type=artifact_type,
        artifact_id=artifact_id,
        patch_object=body_payload,
        request_id=request_id,
    )


def xyn_intent_options(request: HttpRequest) -> JsonResponse:
    if not _intent_engine_enabled():
        return JsonResponse({"error": "intent engine disabled"}, status=404)
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    artifact_type = str(request.GET.get("artifact_type") or "").strip()
    field_name = str(request.GET.get("field") or "").strip().lower()
    if artifact_type not in {"ArticleDraft", "ContextPack"}:
        return JsonResponse({"error": "artifact_type must be ArticleDraft or ContextPack"}, status=400)
    allowed_fields = {"category", "format", "duration"} if artifact_type == "ArticleDraft" else {"format"}
    if field_name not in allowed_fields:
        return JsonResponse({"error": f"field must be {'|'.join(sorted(allowed_fields))}"}, status=400)
    contract = _intent_contract_registry().get(artifact_type)
    options = contract.options_for_field(field_name) if contract else []
    return JsonResponse({"artifact_type": artifact_type, "field": field_name, "options": options})


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
            "effective_params": result.get("effective_params") if isinstance(result.get("effective_params"), dict) else {},
            "warnings": result.get("warnings") if isinstance(result.get("warnings"), list) else [],
            "agent_slug": resolved.get("agent_slug") or agent_slug,
        }
    )


@csrf_exempt
def ai_activity(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)

    workspace_id = str(request.GET.get("workspace_id") or "").strip()
    artifact_id = str(request.GET.get("artifact_id") or "").strip()
    limit_raw = str(request.GET.get("limit") or "100").strip()
    try:
        limit = max(1, min(int(limit_raw), 300))
    except ValueError:
        limit = 100

    is_manager = _can_manage_ai(identity)
    if workspace_id and not is_manager and not _workspace_membership(identity, workspace_id):
        return JsonResponse({"error": "forbidden"}, status=403)

    artifact_lookup: Dict[str, Artifact] = {}
    if workspace_id or artifact_id:
        artifact_qs = Artifact.objects.all()
        if artifact_id:
            artifact_qs = artifact_qs.filter(id=artifact_id)
        elif workspace_id:
            artifact_qs = artifact_qs.filter(workspace_id=workspace_id)
        artifact_lookup = {str(item.id): item for item in artifact_qs.select_related("type")}

    items: List[Dict[str, Any]] = []
    audit_qs = AuditLog.objects.filter(message="ai_invocation").order_by("-created_at")[:600]
    for entry in audit_qs:
        meta = entry.metadata_json if isinstance(entry.metadata_json, dict) else {}
        actor_identity_id = str(meta.get("actor_identity_id") or "")
        if not is_manager and not workspace_id and actor_identity_id and actor_identity_id != str(identity.id):
            continue
        payload_meta = meta.get("metadata") if isinstance(meta.get("metadata"), dict) else {}
        event_artifact_id = str(payload_meta.get("artifact_id") or "")
        if artifact_id and event_artifact_id != artifact_id:
            continue
        if workspace_id and str(payload_meta.get("workspace_id") or "") != workspace_id:
            if event_artifact_id and event_artifact_id in artifact_lookup:
                pass
            else:
                continue
        artifact = artifact_lookup.get(event_artifact_id) if event_artifact_id else None
        items.append(
            {
                "id": str(entry.id),
                "event_type": entry.message,
                "status": "succeeded",
                "summary": str(payload_meta.get("mode") or "AI invocation complete"),
                "created_at": entry.created_at,
                "actor_id": actor_identity_id or None,
                "agent_slug": str(meta.get("agent_slug") or ""),
                "provider": str(meta.get("provider") or ""),
                "model_name": str(meta.get("model_name") or ""),
                "artifact_id": event_artifact_id or None,
                "artifact_type": (artifact.type.slug if artifact and artifact.type_id else "") or "article",
                "artifact_title": artifact.title if artifact else "",
                "source": "audit_log",
            }
        )
        if len(items) >= limit:
            break

    if workspace_id and len(items) < limit:
        events = (
            ArtifactEvent.objects.filter(artifact__workspace_id=workspace_id, event_type__in=["ai_invoked", "article_revision_created"])
            .select_related("artifact")
            .order_by("-created_at")[:300]
        )
        for event in events:
            if artifact_id and str(event.artifact_id) != artifact_id:
                continue
            payload = event.payload_json if isinstance(event.payload_json, dict) else {}
            summary = str(payload.get("mode") or payload.get("source") or event.event_type)
            items.append(
                {
                    "id": str(event.id),
                    "event_type": event.event_type,
                    "status": "succeeded",
                    "summary": summary,
                    "created_at": event.created_at,
                    "actor_id": str(event.actor_id) if event.actor_id else None,
                    "agent_slug": str(payload.get("agent_slug") or ""),
                    "provider": str(payload.get("provider") or ""),
                    "model_name": str(payload.get("model_name") or ""),
                    "artifact_id": str(event.artifact_id),
                    "artifact_type": event.artifact.type.slug if event.artifact.type_id else "",
                    "artifact_title": event.artifact.title,
                    "source": "artifact_event",
                }
            )
            if len(items) >= limit:
                break

    items.sort(key=lambda entry: str(entry.get("created_at") or ""), reverse=True)
    return JsonResponse({"items": items[:limit]})


@csrf_exempt
def ai_purposes_collection(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    _ensure_default_agent_purposes()
    if request.method == "GET":
        status_filter = str(request.GET.get("status") or "").strip().lower()
        enabled_filter = str(request.GET.get("enabled") or "").strip().lower()
        purposes = AgentPurpose.objects.select_related("model_config__provider").order_by("slug")
        if status_filter in {"active", "deprecated"}:
            purposes = purposes.filter(status=status_filter)
        if enabled_filter in {"1", "true", "yes"}:
            purposes = purposes.exclude(status="deprecated")
        elif enabled_filter in {"0", "false", "no"}:
            purposes = purposes.filter(status="deprecated")
        return JsonResponse({"purposes": [_serialize_agent_purpose(item) for item in purposes]})
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if not _can_manage_ai(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    payload = _parse_json(request)
    slug = str(payload.get("slug") or "").strip().lower()
    if not slug:
        return JsonResponse({"error": "slug is required"}, status=400)
    if not PURPOSE_SLUG_PATTERN.match(slug):
        return JsonResponse({"error": "slug must match ^[a-z0-9][a-z0-9-]{1,62}$"}, status=400)
    if AgentPurpose.objects.filter(slug=slug).exists():
        return JsonResponse({"error": "slug already exists"}, status=400)
    preamble = str(payload.get("preamble") or "")
    if len(preamble) > 1000:
        return JsonResponse({"error": "preamble must be 1000 characters or less"}, status=400)
    purpose = AgentPurpose.objects.create(
        slug=slug,
        name=str(payload.get("name") or "").strip(),
        description=str(payload.get("description") or "").strip(),
        preamble=preamble,
        status=(
            str(payload.get("status") or "").strip().lower()
            if str(payload.get("status") or "").strip().lower() in {"active", "deprecated"}
            else ("active" if bool(payload.get("enabled", True)) else "deprecated")
        ),
        enabled=bool(payload.get("enabled", True)),
        updated_by=request.user if getattr(request, "user", None) and request.user.is_authenticated else None,
    )
    purpose.enabled = purpose.status == "active"
    purpose.save(update_fields=["enabled", "updated_at"])
    return JsonResponse({"purpose": _serialize_agent_purpose(purpose)})


@csrf_exempt
def ai_purpose_detail(request: HttpRequest, purpose_slug: str) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    _ensure_default_agent_purposes()
    purpose = get_object_or_404(AgentPurpose.objects.select_related("model_config__provider"), slug=purpose_slug)
    if request.method == "GET":
        return JsonResponse({"purpose": _serialize_agent_purpose(purpose)})
    if request.method == "DELETE":
        if not _can_manage_ai(identity):
            return JsonResponse({"error": "forbidden"}, status=403)
        purpose.status = "deprecated"
        purpose.enabled = False
        purpose.updated_by = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
        purpose.save(update_fields=["status", "enabled", "updated_by", "updated_at"])
        return JsonResponse({"purpose": _serialize_agent_purpose(purpose)})
    if request.method not in {"PUT", "PATCH"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    if not _can_manage_ai(identity):
        return JsonResponse({"error": "forbidden"}, status=403)
    payload = _parse_json(request)
    if "slug" in payload and str(payload.get("slug") or "").strip().lower() != purpose.slug:
        return JsonResponse({"error": "Purpose slug is immutable. Create a new purpose instead."}, status=400)
    if "enabled" in payload:
        purpose.status = "active" if bool(payload.get("enabled")) else "deprecated"
    if "status" in payload:
        next_status = str(payload.get("status") or "").strip().lower()
        if next_status not in {"active", "deprecated"}:
            return JsonResponse({"error": "status must be one of: active, deprecated"}, status=400)
        purpose.status = next_status
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
    purpose.enabled = purpose.status != "deprecated"
    purpose.save(
        update_fields=["name", "description", "status", "enabled", "preamble", "model_config", "updated_by", "updated_at"]
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
        ensure_blueprint_artifact(blueprint, owner_user=request.user)
        return JsonResponse({"id": str(blueprint.id)})

    qs = Blueprint.objects.select_related("artifact").all().order_by("namespace", "name")
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
            "artifact_id": str(b.artifact_id) if b.artifact_id else None,
            "artifact_state": (b.artifact.artifact_state if b.artifact_id and b.artifact else None),
            "family_id": (b.artifact.family_id if b.artifact_id and b.artifact else (b.blueprint_family_id or "")),
            "parent_artifact_id": (
                str(b.artifact.parent_artifact_id) if b.artifact_id and b.artifact and b.artifact.parent_artifact_id else None
            ),
            "name": (b.artifact.title if b.artifact_id and b.artifact and b.artifact.title else b.name),
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
        ensure_blueprint_artifact(blueprint, owner_user=request.user)
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
            "artifact_id": str(blueprint.artifact_id) if blueprint.artifact_id else None,
            "artifact_state": blueprint.artifact.artifact_state if blueprint.artifact_id and blueprint.artifact else None,
            "family_id": (
                blueprint.artifact.family_id if blueprint.artifact_id and blueprint.artifact else (blueprint.blueprint_family_id or "")
            ),
            "derived_from_artifact_id": (
                str(blueprint.artifact.parent_artifact_id)
                if blueprint.artifact_id and blueprint.artifact and blueprint.artifact.parent_artifact_id
                else None
            ),
            "name": (blueprint.artifact.title if blueprint.artifact_id and blueprint.artifact and blueprint.artifact.title else blueprint.name),
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
def blueprint_revise(request: HttpRequest, artifact_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    identity = _identity_from_user(request.user)

    base_artifact = get_object_or_404(
        Artifact.objects.select_related("type", "workspace", "lineage_root", "parent_artifact"),
        id=artifact_id,
    )
    if base_artifact.type.slug != "blueprint":
        return JsonResponse({"error": "artifact_type must be blueprint"}, status=400)
    if base_artifact.artifact_state != "canonical":
        return JsonResponse({"error": "only canonical blueprints can be revised"}, status=400)
    if base_artifact.source_ref_type != "Blueprint" or not base_artifact.source_ref_id:
        return JsonResponse({"error": "artifact source is not a blueprint"}, status=400)

    source_blueprint = Blueprint.objects.filter(id=base_artifact.source_ref_id).first()
    if not source_blueprint:
        return JsonResponse({"error": "source blueprint not found"}, status=404)

    family_id = str(base_artifact.family_id or base_artifact.id)
    seed = {
        "name": source_blueprint.name,
        "namespace": source_blueprint.namespace,
        "description": source_blueprint.description or "",
        "spec_text_hash": hashlib.sha256((source_blueprint.spec_text or "").encode("utf-8")).hexdigest(),
        "metadata_hash": hashlib.sha256(json.dumps(source_blueprint.metadata_json or {}, sort_keys=True).encode("utf-8")).hexdigest(),
        "parent_artifact_id": str(base_artifact.id),
    }
    seed_hash = hashlib.sha256(json.dumps(seed, sort_keys=True).encode("utf-8")).hexdigest()

    existing = (
        Artifact.objects.select_related("type")
        .filter(
            type__slug="blueprint",
            artifact_state="provisional",
            family_id=family_id,
            parent_artifact_id=base_artifact.id,
        )
        .filter(provenance_json__revision_seed_hash=seed_hash)
        .order_by("-created_at")
        .first()
    )
    if existing:
        return JsonResponse(
            {
                "artifact_id": str(existing.id),
                "blueprint_id": existing.source_ref_id,
                "family_id": family_id,
                "parent_artifact_id": str(base_artifact.id),
            }
        )

    artifact_type, _ = ArtifactType.objects.get_or_create(
        slug="blueprint",
        defaults={
            "name": "Blueprint",
            "description": "Blueprint artifact",
            "icon": "LayoutTemplate",
            "schema_json": {"entity": "Blueprint"},
        },
    )

    with transaction.atomic():
        suffix = uuid.uuid4().hex[:8]
        revision_blueprint = Blueprint.objects.create(
            name=f"{source_blueprint.name}--rev-{suffix}",
            namespace=source_blueprint.namespace,
            status="active",
            description=source_blueprint.description or "",
            spec_text=source_blueprint.spec_text or "",
            metadata_json=source_blueprint.metadata_json if isinstance(source_blueprint.metadata_json, dict) else {},
            blueprint_family_id=family_id,
            derived_from_artifact=base_artifact,
            created_by=request.user,
            updated_by=request.user,
        )
        provisional_artifact = Artifact.objects.create(
            workspace=base_artifact.workspace,
            type=artifact_type,
            artifact_state="provisional",
            family_id=family_id,
            title=base_artifact.title or source_blueprint.name,
            summary=base_artifact.summary or source_blueprint.description or "",
            schema_version=base_artifact.schema_version or "v1",
            tags_json=base_artifact.tags_json or [],
            source_ref_type="Blueprint",
            source_ref_id=str(revision_blueprint.id),
            parent_artifact=base_artifact,
            lineage_root=base_artifact.lineage_root or base_artifact,
            status="draft",
            version=1,
            visibility=base_artifact.visibility,
            author=base_artifact.author,
            custodian=base_artifact.custodian,
            provenance_json={
                **(base_artifact.provenance_json or {}),
                "source_system": "xyn",
                "source_model": "Blueprint",
                "source_id": str(revision_blueprint.id),
                "revision_seed_hash": seed_hash,
            },
            scope_json=base_artifact.scope_json or {},
        )
        revision_blueprint.artifact = provisional_artifact
        revision_blueprint.save(update_fields=["artifact", "updated_at"])

    emit_ledger_event(
        actor=identity,
        action="artifact.create",
        artifact=provisional_artifact,
        summary="Created provisional Blueprint revision",
        metadata={
            "title": provisional_artifact.title,
            "initial_artifact_state": provisional_artifact.artifact_state,
            "family_id": family_id,
            "parent_artifact_id": str(base_artifact.id),
        },
        dedupe_key=make_dedupe_key("artifact.create", str(provisional_artifact.id)),
    )
    return JsonResponse(
        {
            "artifact_id": str(provisional_artifact.id),
            "blueprint_id": str(revision_blueprint.id),
            "family_id": family_id,
            "parent_artifact_id": str(base_artifact.id),
        }
    )


@csrf_exempt
@login_required
def blueprint_publish(request: HttpRequest, artifact_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    identity = _identity_from_user(request.user)

    artifact = get_object_or_404(
        Artifact.objects.select_related("type", "workspace", "lineage_root", "parent_artifact"),
        id=artifact_id,
    )
    if artifact.type.slug != "blueprint":
        return JsonResponse({"error": "artifact_type must be blueprint"}, status=400)
    if artifact.artifact_state != "provisional":
        return JsonResponse({"error": "artifact_state must be provisional"}, status=400)
    family_id = str(artifact.family_id or "").strip()
    if not family_id:
        return JsonResponse({"error": "family_id is required for blueprint artifacts"}, status=400)

    with transaction.atomic():
        hinted_canonical = get_current_canonical(family_id)
        family_rows = list(
            Artifact.objects.select_for_update()
            .select_related("type")
            .filter(type__slug="blueprint", family_id=family_id)
            .order_by("-created_at")
        )
        target = next((row for row in family_rows if row.id == artifact.id), artifact)
        validation_status, validation_errors = validate_artifact(target)
        content_hash = compute_content_hash(target)
        target.content_hash = content_hash
        target.validation_status = validation_status
        target.validation_errors_json = validation_errors or []
        if validation_status == "fail":
            return JsonResponse(
                {
                    "error": "artifact validation failed",
                    "validation_status": validation_status,
                    "validation_errors": validation_errors,
                },
                status=400,
            )
        superseded = next((row for row in family_rows if row.id != target.id and row.artifact_state == "canonical"), None)
        if not superseded and hinted_canonical and hinted_canonical.id != target.id:
            superseded = next((row for row in family_rows if row.id == hinted_canonical.id), hinted_canonical)
        superseded_id = str(superseded.id) if superseded else None

        if superseded:
            superseded.artifact_state = "deprecated"
            superseded.save(update_fields=["artifact_state", "updated_at"])
            emit_ledger_event(
                actor=identity,
                action="artifact.deprecate",
                artifact=superseded,
                summary="Deprecated Blueprint artifact",
                metadata={"reason": "superseded_by_publish", "superseded_by_artifact_id": str(target.id)},
                dedupe_key=make_dedupe_key("artifact.deprecate", str(superseded.id), state="deprecated"),
            )

        target.artifact_state = "canonical"
        target.save(update_fields=["artifact_state", "content_hash", "validation_status", "validation_errors_json", "updated_at"])
        publish_metadata = {
            "superseded_artifact_id": superseded_id,
            "validation_status": validation_status,
            "content_hash": content_hash,
        }
        emit_ledger_event(
            actor=identity,
            action="artifact.update",
            artifact=target,
            summary="Published Blueprint version",
            metadata=publish_metadata,
            dedupe_key=make_dedupe_key("artifact.update", str(target.id), diff_payload=publish_metadata),
        )

    return JsonResponse(
        {
            "artifact_id": str(artifact.id),
            "artifact_state": "canonical",
            "family_id": family_id,
            "superseded_artifact_id": superseded_id,
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
        artifact = ensure_module_artifact(module, owner_user=request.user)
        return JsonResponse({"id": str(module.id), "artifact_id": str(artifact.id)})
    if request.method == "DELETE":
        module.delete()
        return JsonResponse({"status": "deleted"})
    artifact = ensure_module_artifact(module, owner_user=request.user)
    return JsonResponse(
        {
            "id": str(module.id),
            "artifact_id": str(artifact.id),
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
