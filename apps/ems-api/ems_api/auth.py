import os
import time
from typing import Any, Dict

import jwt
import requests
from fastapi import HTTPException, Request, status

_OIDC_CACHE: Dict[str, Any] = {
    "expires_at": 0,
    "config": None,
    "jwks_by_issuer": {},
}


def _get_required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Missing required environment variable: {name}",
        )
    return value


def _xyn_base_url() -> str:
    return os.environ.get("EMS_PLATFORM_API_BASE", "https://xyence.io").rstrip("/")


def _oidc_app_id() -> str:
    return os.environ.get("EMS_OIDC_APP_ID", "ems.platform").strip() or "ems.platform"


def _load_oidc_config(force: bool = False) -> Dict[str, Any]:
    now = int(time.time())
    if not force and _OIDC_CACHE.get("config") and now < int(_OIDC_CACHE.get("expires_at", 0)):
        return _OIDC_CACHE["config"]
    response = requests.get(
        f"{_xyn_base_url()}/xyn/api/auth/oidc/config",
        params={"appId": _oidc_app_id()},
        timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    _OIDC_CACHE["config"] = payload
    _OIDC_CACHE["expires_at"] = now + 300
    return payload


def _provider_by_issuer(issuer: str) -> Dict[str, Any]:
    config = _load_oidc_config()
    providers = config.get("allowed_providers") or []
    for provider in providers:
        if str(provider.get("issuer", "")).rstrip("/") == issuer.rstrip("/"):
            return provider
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown OIDC issuer")


def _jwks_for_issuer(issuer: str, force: bool = False) -> str:
    cache_key = issuer.rstrip("/")
    if not force and cache_key in _OIDC_CACHE["jwks_by_issuer"]:
        return _OIDC_CACHE["jwks_by_issuer"][cache_key]
    discovery = requests.get(f"{cache_key}/.well-known/openid-configuration", timeout=10)
    discovery.raise_for_status()
    jwks_uri = discovery.json().get("jwks_uri")
    if not jwks_uri:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="OIDC discovery missing jwks_uri")
    _OIDC_CACHE["jwks_by_issuer"][cache_key] = jwks_uri
    return jwks_uri


def _decode_oidc_token(token: str) -> Dict[str, Any]:
    unverified = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    issuer = str(unverified.get("iss") or "").strip()
    if not issuer:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing issuer")
    provider = _provider_by_issuer(issuer)
    client_id = str(provider.get("client_id") or "").strip()
    if not client_id:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="OIDC provider missing client_id")
    jwks_uri = _jwks_for_issuer(issuer)
    jwk_client = jwt.PyJWKClient(jwks_uri)
    try:
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            issuer=issuer,
            audience=client_id,
        )
        return claims
    except Exception:
        # Unknown KID or rotated key; refresh discovery/JWKS and retry once.
        jwks_uri = _jwks_for_issuer(issuer, force=True)
        jwk_client = jwt.PyJWKClient(jwks_uri)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            issuer=issuer,
            audience=client_id,
        )


def decode_token(token: str) -> Dict[str, Any]:
    if os.environ.get("EMS_OIDC_ENABLED", "true").lower() in {"1", "true", "yes", "on"}:
        claims = _decode_oidc_token(token)
        if claims.get("roles") is None:
            claims["roles"] = ["viewer"]
        return claims
    secret = _get_required_env("EMS_JWT_SECRET")
    issuer = os.environ.get("EMS_JWT_ISSUER", "xyn-ems")
    audience = os.environ.get("EMS_JWT_AUDIENCE", "ems")
    claims = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer=issuer,
        audience=audience,
    )
    if claims.get("roles") is None:
        claims["roles"] = ["viewer"]
    return claims


def require_user(request: Request) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    token = auth_header.replace("Bearer ", "", 1).strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    try:
        claims = decode_token(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc
    request.state.user = claims
    return claims
