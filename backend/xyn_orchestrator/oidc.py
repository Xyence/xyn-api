import base64
import hashlib
import json
import os
import secrets
import time
from typing import Any, Dict, Optional, Tuple

import boto3
import requests
from django.utils import timezone

from .models import IdentityProvider, AppOIDCClient

DISCOVERY_TTL_SECONDS = 6 * 60 * 60
JWKS_TTL_SECONDS = 6 * 60 * 60


def _aws_region_name() -> str:
    return (os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "").strip()


def _encode_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def generate_pkce_pair() -> Tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = _encode_code_challenge(verifier)
    return verifier, challenge


def resolve_secret_ref(secret_ref: Optional[Dict[str, Any]]) -> Optional[str]:
    if not secret_ref:
        return None
    ref_type = (secret_ref.get("type") or "").lower()
    ref = secret_ref.get("ref") or ""
    if not ref:
        return None
    if ref_type == "env":
        return os.environ.get(ref)
    if ref_type == "aws.ssm":
        region = _aws_region_name()
        client = boto3.client("ssm", region_name=region) if region else boto3.client("ssm")
        response = client.get_parameter(Name=ref, WithDecryption=True)
        return response.get("Parameter", {}).get("Value")
    if ref_type == "aws.secrets_manager":
        region = _aws_region_name()
        client = boto3.client("secretsmanager", region_name=region) if region else boto3.client("secretsmanager")
        response = client.get_secret_value(SecretId=ref)
        return response.get("SecretString")
    return None


def _get_discovery_endpoint(provider: IdentityProvider) -> str:
    discovery = provider.discovery_json or {}
    if discovery.get("mode") == "manual":
        return ""
    issuer = provider.issuer.rstrip("/")
    return f"{issuer}/.well-known/openid-configuration"


def get_discovery_doc(provider: IdentityProvider, force: bool = False) -> Optional[Dict[str, Any]]:
    now = time.time()
    if (
        not force
        and provider.cached_discovery_doc
        and provider.last_discovery_refresh_at
        and now - provider.last_discovery_refresh_at.timestamp() < DISCOVERY_TTL_SECONDS
    ):
        return provider.cached_discovery_doc
    discovery = provider.discovery_json or {}
    manual = discovery.get("mode") == "manual"
    if manual:
        doc = {
            "issuer": provider.issuer,
            "jwks_uri": discovery.get("jwksUri"),
            "authorization_endpoint": discovery.get("authorizationEndpoint"),
            "token_endpoint": discovery.get("tokenEndpoint"),
            "userinfo_endpoint": discovery.get("userinfoEndpoint"),
        }
    else:
        endpoint = _get_discovery_endpoint(provider)
        if not endpoint:
            return None
        response = requests.get(endpoint, timeout=10)
        response.raise_for_status()
        doc = response.json()
    provider.cached_discovery_doc = doc
    provider.last_discovery_refresh_at = timezone.now()
    provider.save(update_fields=["cached_discovery_doc", "last_discovery_refresh_at", "updated_at"])
    return doc


def get_jwks(provider: IdentityProvider, force: bool = False, kid: Optional[str] = None) -> Optional[Dict[str, Any]]:
    now = time.time()
    if (
        not force
        and provider.cached_jwks
        and provider.jwks_cached_at
        and now - provider.jwks_cached_at.timestamp() < JWKS_TTL_SECONDS
    ):
        if not kid:
            return provider.cached_jwks
        keys = provider.cached_jwks.get("keys") if isinstance(provider.cached_jwks, dict) else []
        if any(key.get("kid") == kid for key in (keys or [])):
            return provider.cached_jwks
    discovery = get_discovery_doc(provider, force=force)
    jwks_uri = None
    if discovery:
        jwks_uri = discovery.get("jwks_uri")
    if not jwks_uri:
        discovery_meta = provider.discovery_json or {}
        jwks_uri = discovery_meta.get("jwksUri")
    if not jwks_uri:
        return None
    response = requests.get(jwks_uri, timeout=10)
    response.raise_for_status()
    jwks = response.json()
    provider.cached_jwks = jwks
    provider.jwks_cached_at = timezone.now()
    provider.save(update_fields=["cached_jwks", "jwks_cached_at", "updated_at"])
    return jwks


def resolve_app_client(app_id: str) -> Optional[AppOIDCClient]:
    return AppOIDCClient.objects.filter(app_id=app_id).order_by("-created_at").first()


def provider_to_payload(provider: IdentityProvider) -> Dict[str, Any]:
    return {
        "id": provider.id,
        "display_name": provider.display_name,
        "enabled": provider.enabled,
        "issuer": provider.issuer,
        "discovery": provider.discovery_json or {},
        "client": {
            "client_id": provider.client_id,
            "client_secret_ref": provider.client_secret_ref_json or None,
        },
        "scopes": provider.scopes_json or ["openid", "profile", "email"],
        "pkce": provider.pkce_enabled,
        "prompt": provider.prompt or None,
        "domain_rules": provider.domain_rules_json or {},
        "claims": provider.claims_json or {},
        "audience_rules": provider.audience_rules_json or {},
        "last_discovery_refresh_at": provider.last_discovery_refresh_at,
    }


def app_client_to_payload(client: AppOIDCClient) -> Dict[str, Any]:
    return {
        "id": str(client.id),
        "app_id": client.app_id,
        "login_mode": client.login_mode,
        "default_provider_id": client.default_provider_id if client.default_provider_id else None,
        "allowed_provider_ids": client.allowed_providers_json or [],
        "redirect_uris": client.redirect_uris_json or [],
        "post_logout_redirect_uris": client.post_logout_redirect_uris_json or [],
        "session": client.session_json or {},
        "token_validation": client.token_validation_json or {},
        "created_at": client.created_at,
        "updated_at": client.updated_at,
    }
