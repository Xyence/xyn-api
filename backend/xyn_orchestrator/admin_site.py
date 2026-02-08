from django.contrib import admin

from .models import UserIdentity, RoleBinding


def _has_platform_admin(request) -> bool:
    identity_id = request.session.get("user_identity_id")
    if not identity_id:
        return False
    identity = UserIdentity.objects.filter(id=identity_id).first()
    if not identity:
        return False
    return RoleBinding.objects.filter(user_identity=identity, role="platform_admin").exists()


def apply_admin_guard():
    def _guard(request):
        if not request.user.is_active or not request.user.is_staff:
            return False
        return _has_platform_admin(request)

    admin.site.has_permission = _guard


apply_admin_guard()
