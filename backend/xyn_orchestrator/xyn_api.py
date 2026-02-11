import base64
import json
import logging
import os
import re
import secrets
import time
import uuid
import hashlib
import fnmatch
from functools import wraps
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from pathlib import Path
from typing import Any, Dict, Optional, List

import requests
import boto3
from authlib.jose import JsonWebKey, jwt
from django.core.paginator import Paginator
from django.db import models
from django.http import HttpRequest, JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404, redirect
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
    _require_staff,
    _resolve_context_pack_list,
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
    RoleBinding,
    UserIdentity,
    Tenant,
    Contact,
    TenantMembership,
    BrandProfile,
    Device,
)
from .module_registry import maybe_sync_modules_from_registry
from .oidc import (
    app_client_to_payload,
    generate_pkce_pair,
    get_discovery_doc,
    get_jwks,
    provider_to_payload,
    resolve_app_client,
    resolve_secret_ref as resolve_oidc_secret_ref,
)


def _parse_json(request: HttpRequest) -> Dict[str, Any]:
    if request.body:
        try:
            return json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


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
    tls_mode = (payload.get("tls") or {}).get("mode")
    if tls_mode == "nginx+acme" and not (payload.get("tls") or {}).get("acme_email"):
        errors.append("tls.acme_email: required when tls.mode is nginx+acme")
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
            "acme_email": tls.get("acme_email") or "",
            "redirect_http_to_https": bool(tls.get("redirect_http_to_https", True)),
        },
        "env": payload.get("env") or {},
        "secret_refs": payload.get("secret_refs") or [],
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
            "env": target.env_json or {},
            "secret_refs": target.secret_refs_json or [],
            "created_at": target.created_at.isoformat() if target.created_at else "",
            "updated_at": target.updated_at.isoformat() if target.updated_at else "",
        }
    return payload


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
    _fields, schema_payload = _normalize_provider_payload(payload)
    errors = _validate_schema_payload(schema_payload, "oidc_identity_provider.v1.schema.json")
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
        client = boto3.client("ssm")
        response = client.get_parameter(Name=name, WithDecryption=True)
        return response.get("Parameter", {}).get("Value")
    if value.startswith("ssm-arn:"):
        name = value[len("ssm-arn:") :]
        client = boto3.client("ssm")
        response = client.get_parameter(Name=name, WithDecryption=True)
        return response.get("Parameter", {}).get("Value")
    if value.startswith("secretsmanager:"):
        name = value[len("secretsmanager:") :]
        client = boto3.client("secretsmanager")
        response = client.get_secret_value(SecretId=name)
        return response.get("SecretString")
    if value.startswith("secretsmanager-arn:"):
        name = value[len("secretsmanager-arn:") :]
        client = boto3.client("secretsmanager")
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


def _get_roles(identity: UserIdentity) -> List[str]:
    return list(
        RoleBinding.objects.filter(user_identity=identity)
        .values_list("role", flat=True)
    )


def _is_platform_admin(identity: UserIdentity) -> bool:
    return RoleBinding.objects.filter(user_identity=identity, role="platform_admin").exists()


def _tenant_role_rank(role: str) -> int:
    order = {"tenant_viewer": 1, "tenant_operator": 2, "tenant_admin": 3}
    return order.get(role, 0)


def _require_tenant_access(identity: UserIdentity, tenant_id: str, minimum_role: str) -> bool:
    membership = TenantMembership.objects.filter(
        tenant_id=tenant_id,
        user_identity=identity,
        status="active",
    ).first()
    if not membership:
        return False
    return _tenant_role_rank(membership.role) >= _tenant_role_rank(minimum_role)


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
def identity_providers_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        errors = _validate_provider_payload(payload)
        if errors:
            return JsonResponse({"error": "invalid provider", "details": errors}, status=400)
        fields, _schema_payload = _normalize_provider_payload(payload)
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
    provider = get_object_or_404(IdentityProvider, id=provider_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        errors = _validate_provider_payload({**provider_to_payload(provider), **payload})
        if errors:
            return JsonResponse({"error": "invalid provider", "details": errors}, status=400)
        fields, _schema_payload = _normalize_provider_payload({**provider_to_payload(provider), **payload})
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
    if request.method == "POST":
        payload = _parse_json(request)
        errors = _validate_app_client_payload(payload)
        if errors:
            return JsonResponse({"error": "invalid app client", "details": errors}, status=400)
        fields, _schema_payload = _normalize_app_client_payload(payload)
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
    return {
        "app_id": client.app_id,
        "login_mode": client.login_mode,
        "default_provider_id": client.default_provider_id if client.default_provider_id else None,
        "allowed_providers": provider_payloads,
        "redirect_uris": client.redirect_uris_json or [],
        "post_logout_redirect_uris": client.post_logout_redirect_uris_json or [],
        "session": client.session_json or {},
        "token_validation": client.token_validation_json or {},
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
    next_url = request.GET.get("next") or "/app"
    request.session["post_login_redirect"] = next_url
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
    code = request.POST.get("code") if request.method == "POST" else request.GET.get("code")
    state = request.POST.get("state") if request.method == "POST" else request.GET.get("state")
    app_id = request.POST.get("appId") if request.method == "POST" else request.GET.get("appId")
    app_id = app_id or request.session.get("oidc_app_id") or ""
    if not code or not state:
        return JsonResponse({"error": "missing code/state"}, status=400)
    if not app_id:
        return JsonResponse({"error": "appId required"}, status=400)
    expected_state = request.session.get(f"oidc_state:{app_id}:{provider_id}")
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
    client_secret = resolve_oidc_secret_ref(provider.client_secret_ref_json)
    if client_secret:
        token_payload["client_secret"] = client_secret
    token_response = requests.post(discovery["token_endpoint"], data=token_payload, timeout=15)
    if token_response.status_code >= 400:
        try:
            details = token_response.json()
        except Exception:
            details = token_response.text
        return JsonResponse({"error": "token exchange failed", "details": details}, status=400)
    token_body = token_response.json()
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
    roles = _get_roles(identity)
    User = get_user_model()
    issuer_hash = hashlib.sha256(provider.issuer.encode("utf-8")).hexdigest()[:12]
    username = f"oidc:{issuer_hash}:{subject}"
    user, created = User.objects.get_or_create(
        username=username,
        defaults={"email": email, "is_staff": "platform_admin" in roles, "is_active": True},
    )
    if email and user.email != email:
        user.email = email
    user.is_staff = "platform_admin" in roles
    user.is_superuser = False
    user.is_active = True
    user.save()
    if not roles and app_id == "xyn-ui":
        return JsonResponse({"error": "no roles assigned"}, status=403)
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    request.session["user_identity_id"] = str(identity.id)
    redirect_to = request.session.get("post_login_redirect") or "/app"
    if app_id != "xyn-ui":
        split = urlsplit(redirect_to)
        fragment_params = dict(parse_qsl(split.fragment, keep_blank_values=True))
        fragment_params["id_token"] = id_token
        rebuilt = split._replace(fragment=urlencode(fragment_params))
        redirect_to = urlunsplit(rebuilt)
    return redirect(redirect_to)


@csrf_exempt
def auth_login(request: HttpRequest) -> HttpResponse:
    client = _resolve_app_config("xyn-ui")
    if client and client.default_provider_id:
        next_url = request.GET.get("next") or "/app"
        request.GET = request.GET.copy()
        request.GET["appId"] = "xyn-ui"
        request.GET["next"] = next_url
        return oidc_authorize(request, client.default_provider_id)
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
    next_url = request.GET.get("next") or "/app/ems"
    request.session["post_login_redirect"] = next_url
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
def auth_callback(request: HttpRequest) -> HttpResponse:
    provider_id = request.session.get("oidc_provider_id")
    if provider_id:
        return oidc_callback(request, provider_id)
    error = request.GET.get("error")
    if error:
        return JsonResponse({"error": error}, status=400)
    code = request.GET.get("code")
    state = request.GET.get("state")
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
            "is_staff": "platform_admin" in roles,
            "is_active": True,
        },
    )
    if email and user.email != email:
        user.email = email
    user.is_staff = "platform_admin" in roles
    user.is_superuser = False
    user.is_active = True
    user.save()
    if not roles:
        return JsonResponse({"error": "no roles assigned"}, status=403)
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    request.session["user_identity_id"] = str(identity.id)
    request.session["environment_id"] = str(env.id)
    redirect_to = request.session.get("post_login_redirect") or "/app/ems"
    return redirect(redirect_to)


@csrf_exempt
def auth_logout(request: HttpRequest) -> JsonResponse:
    request.session.flush()
    return JsonResponse({"status": "ok"})


def api_me(request: HttpRequest) -> JsonResponse:
    identity = _require_authenticated(request)
    if not identity:
        return JsonResponse({"error": "not authenticated"}, status=401)
    roles = _get_roles(identity)
    return JsonResponse(
        {
            "user": {
                "issuer": identity.issuer,
                "subject": identity.subject,
                "email": identity.email,
                "display_name": identity.display_name,
            },
            "roles": roles,
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
    data = [
        {
            "id": str(i.id),
            "provider": i.provider,
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
    if query := request.GET.get("q"):
        qs = qs.filter(models.Q(name__icontains=query) | models.Q(namespace__icontains=query))
    data = [
        {
            "id": str(b.id),
            "name": b.name,
            "namespace": b.namespace,
            "description": b.description,
            "spec_text": b.spec_text,
            "metadata_json": b.metadata_json,
            "created_at": b.created_at,
            "updated_at": b.updated_at,
            "latest_revision": b.revisions.order_by("-revision").first().revision if b.revisions.exists() else None,
        }
        for b in qs
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
        for field in ["name", "namespace", "description", "spec_text", "metadata_json"]:
            if field in payload:
                setattr(blueprint, field, payload[field])
        blueprint.updated_by = request.user
        blueprint.save(
            update_fields=["name", "namespace", "description", "spec_text", "metadata_json", "updated_by", "updated_at"]
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
        blueprint.delete()
        return JsonResponse({"status": "deleted"})

    latest = blueprint.revisions.order_by("-revision").first()
    return JsonResponse(
        {
            "id": str(blueprint.id),
            "name": blueprint.name,
            "namespace": blueprint.namespace,
            "description": blueprint.description,
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
        name = payload.get("name") or f"{blueprint.namespace}.{blueprint.name} Draft"
        blueprint_kind = payload.get("blueprint_kind", "solution")
        context_pack_ids = payload.get("context_pack_ids") or []
        if not isinstance(context_pack_ids, list):
            return JsonResponse({"error": "context_pack_ids must be a list"}, status=400)
        session = BlueprintDraftSession.objects.create(
            name=name,
            blueprint=blueprint,
            blueprint_kind=blueprint_kind,
            context_pack_ids=context_pack_ids,
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse({"session_id": str(session.id)})
    sessions = BlueprintDraftSession.objects.filter(blueprint=blueprint).order_by("-created_at")
    data = [
        {
            "id": str(session.id),
            "name": session.name,
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
    target.updated_by = request.user
    target.save()
    return JsonResponse({"id": str(target.id)})


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
        payload = _parse_json(request)
        name = payload.get("name")
        target_kind = payload.get("target_kind")
        target_fqn = payload.get("target_fqn")
        to_version = payload.get("to_version")
        if not name or not target_kind or not target_fqn or not to_version:
            return JsonResponse({"error": "name, target_kind, target_fqn, to_version required"}, status=400)
        if not payload.get("environment_id"):
            return JsonResponse({"error": "environment_id required"}, status=400)
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
    qs = ReleasePlan.objects.all().order_by("-created_at")
    if env_id := request.GET.get("environment_id"):
        qs = qs.filter(environment_id=env_id)
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
        for plan in qs
    ]
    return _paginate(request, data, "release_plans")


@csrf_exempt
@login_required
def release_plan_detail(request: HttpRequest, plan_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    plan = get_object_or_404(ReleasePlan, id=plan_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        if "environment_id" in payload and not payload.get("environment_id"):
            return JsonResponse({"error": "environment_id required"}, status=400)
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
        return JsonResponse({"id": str(plan.id)})
    if request.method == "DELETE":
        plan.delete()
        return JsonResponse({"status": "deleted"})
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
            "last_run": str(plan.last_run_id) if plan.last_run_id else None,
            "deployments": deployments,
            "created_at": plan.created_at,
            "updated_at": plan.updated_at,
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
    return JsonResponse({"status": "ok"})


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
    qs = Release.objects.all().order_by("-created_at")
    if blueprint_id := request.GET.get("blueprint_id"):
        qs = qs.filter(blueprint_id=blueprint_id)
    if status := request.GET.get("status"):
        qs = qs.filter(status=status)
    data = [
        {
            "id": str(release.id),
            "version": release.version,
            "status": release.status,
            "build_state": release.build_state,
            "blueprint_id": str(release.blueprint_id) if release.blueprint_id else None,
            "release_plan_id": str(release.release_plan_id) if release.release_plan_id else None,
            "created_from_run_id": str(release.created_from_run_id) if release.created_from_run_id else None,
            "created_at": release.created_at,
            "updated_at": release.updated_at,
        }
        for release in qs
    ]
    return _paginate(request, data, "releases")


@csrf_exempt
@login_required
def release_detail(request: HttpRequest, release_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    release = get_object_or_404(Release, id=release_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        prev_status = release.status
        for field in ["version", "status", "build_state", "artifacts_json", "release_plan_id", "blueprint_id"]:
            if field in payload:
                setattr(release, field, payload[field])
        release.updated_by = request.user
        release.save()
        build_run_id = None
        if payload.get("status") == "published" and prev_status != "published":
            release.build_state = "building"
            release.save(update_fields=["build_state", "updated_at"])
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
        release.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(
        {
            "id": str(release.id),
            "version": release.version,
            "status": release.status,
            "build_state": release.build_state,
            "blueprint_id": str(release.blueprint_id) if release.blueprint_id else None,
            "release_plan_id": str(release.release_plan_id) if release.release_plan_id else None,
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
