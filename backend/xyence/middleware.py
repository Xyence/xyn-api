import os

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser


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
