import os
import time
from typing import Any, Dict, Optional

import jwt
import requests
from django.contrib.auth import get_user_model


class ApiTokenAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = _extract_bearer_token(request)
        if token:
            expected = os.environ.get("XYENCE_UI_BEARER_TOKEN", "").strip()
            if expected and token == expected:
                request.user = _get_service_user()
                request._cached_user = request.user
                request._dont_enforce_csrf_checks = True
            else:
                claims = _verify_oidc_token(token)
                if claims:
                    user = _get_or_create_user_from_claims(claims)
                    if user:
                        request.user = user
                        request._cached_user = user
                        request._dont_enforce_csrf_checks = True
        return self.get_response(request)


def _extract_bearer_token(request) -> str:
    header = request.headers.get("Authorization", "")
    if not header:
        return ""
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def _get_service_user():
    User = get_user_model()
    username = os.environ.get("XYENCE_UI_BEARER_USER", "xyn-ui").strip() or "xyn-ui"
    user, created = User.objects.get_or_create(
        username=username,
        defaults={"is_staff": True, "is_active": True, "email": ""},
    )
    if created or not user.is_staff:
        user.is_staff = True
        user.is_active = True
        user.save(update_fields=["is_staff", "is_active"])
    return user


_JWKS_CLIENT: Optional[jwt.PyJWKClient] = None
_JWKS_CLIENT_TS: float = 0.0


def _verify_oidc_token(token: str) -> Optional[Dict[str, Any]]:
    issuer = os.environ.get("OIDC_ISSUER", "https://accounts.google.com").strip()
    audience = os.environ.get("OIDC_CLIENT_ID", "").strip()
    if not audience:
        return None
    try:
        jwk_client = _get_jwks_client(issuer)
        if not jwk_client:
            return None
        signing_key = jwk_client.get_signing_key_from_jwt(token).key
        return jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            options={"verify_exp": True},
        )
    except Exception:
        return None


def _get_jwks_client(issuer: str) -> Optional[jwt.PyJWKClient]:
    global _JWKS_CLIENT, _JWKS_CLIENT_TS
    now = time.time()
    if _JWKS_CLIENT and now - _JWKS_CLIENT_TS < 3600:
        return _JWKS_CLIENT
    try:
        config = requests.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration", timeout=10).json()
        jwks_uri = config.get("jwks_uri")
        if not jwks_uri:
            return None
        _JWKS_CLIENT = jwt.PyJWKClient(jwks_uri)
        _JWKS_CLIENT_TS = now
        return _JWKS_CLIENT
    except Exception:
        return None


def _get_or_create_user_from_claims(claims: Dict[str, Any]):
    email = (claims.get("email") or "").strip().lower()
    if not email:
        return None
    if claims.get("email_verified") is False:
        return None
    allowed = [d.strip().lower() for d in os.environ.get("OIDC_ALLOWED_DOMAINS", "xyence.io").split(",") if d.strip()]
    domain = email.split("@")[-1] if "@" in email else ""
    if allowed and domain not in allowed:
        return None
    User = get_user_model()
    user, created = User.objects.get_or_create(
        username=email,
        defaults={"email": email, "is_staff": True, "is_active": True},
    )
    if created or not user.is_staff:
        user.is_staff = True
        user.is_active = True
        user.email = email
        user.save(update_fields=["is_staff", "is_active", "email"])
    return user
