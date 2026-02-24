import os
import time
import hashlib
from typing import Any, Dict, Optional

import jwt
import requests
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from xyn_orchestrator.models import UserIdentity, RoleBinding


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
        if not getattr(request, "user", None) or not request.user.is_authenticated:
            identity_id = getattr(request, "session", {}).get("user_identity_id")
            if identity_id:
                identity = UserIdentity.objects.filter(id=identity_id).first()
                if identity:
                    user = _get_or_create_user_from_identity(identity)
                    if user:
                        request.user = user
                        request._cached_user = user
        return self.get_response(request)


PREVIEW_SESSION_KEY = "xyn.preview.v1"
PREVIEW_TTL_SECONDS = 60 * 60
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
PREVIEW_WRITE_ALLOWLIST = {
    "/xyn/api/preview/enable",
    "/xyn/api/preview/disable",
}


class PreviewModeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        session = getattr(request, "session", None)
        if not session:
            return self.get_response(request)
        preview = session.get(PREVIEW_SESSION_KEY)
        if not isinstance(preview, dict):
            return self.get_response(request)
        if not bool(preview.get("enabled")):
            return self.get_response(request)
        expires_at = int(preview.get("expires_at") or 0)
        if expires_at <= int(time.time()):
            session.pop(PREVIEW_SESSION_KEY, None)
            session.modified = True
            return self.get_response(request)
        is_xyn_api_path = request.path.startswith("/xyn/api/") or request.path.startswith("/xyn/internal/")
        if is_xyn_api_path and request.method.upper() in UNSAFE_METHODS and request.path not in PREVIEW_WRITE_ALLOWLIST:
            return JsonResponse(
                {
                    "code": "PREVIEW_READ_ONLY",
                    "message": "Preview mode is read-only.",
                },
                status=403,
            )
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


def _get_or_create_user_from_identity(identity: UserIdentity):
    User = get_user_model()
    issuer_hash = hashlib.sha256(identity.issuer.encode("utf-8")).hexdigest()[:12]
    username = f"oidc:{issuer_hash}:{identity.subject}"
    user, created = User.objects.get_or_create(
        username=username,
        defaults={"email": identity.email or "", "is_staff": False, "is_active": True},
    )
    roles = RoleBinding.objects.filter(user_identity=identity).values_list("role", flat=True)
    role_set = set(roles)
    is_staff = bool(role_set.intersection({"platform_owner", "platform_admin", "platform_architect"}))
    changed = False
    if user.email != (identity.email or ""):
        user.email = identity.email or ""
        changed = True
    if user.is_staff != is_staff:
        user.is_staff = is_staff
        changed = True
    if user.is_superuser:
        user.is_superuser = False
        changed = True
    if not user.is_active:
        user.is_active = True
        changed = True
    if created or changed:
        user.save()
    return user
