import os

from allauth.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.utils import timezone
from django.http import HttpResponseForbidden
from xyn_orchestrator.models import RoleBinding, UserIdentity


def _allowed_domains():
    raw = os.environ.get("ALLOWED_LOGIN_DOMAINS", "xyence.io")
    return {domain.strip().lower() for domain in raw.split(",") if domain.strip()}


def _email_domain(email):
    if not email or "@" not in email:
        return ""
    return email.split("@", 1)[1].lower()


class DomainRestrictedSocialAccountAdapter(DefaultSocialAccountAdapter):
    def is_open_for_signup(self, request, sociallogin):
        email = sociallogin.user.email or sociallogin.account.extra_data.get("email")
        return _email_domain(email) in _allowed_domains()

    def pre_social_login(self, request, sociallogin):
        email = sociallogin.user.email or sociallogin.account.extra_data.get("email")
        if _email_domain(email) not in _allowed_domains():
            raise ImmediateHttpResponse(
                HttpResponseForbidden("Email domain is not allowed.")
            )
        _sync_identity_session(request, sociallogin)
        if sociallogin.user and sociallogin.user.pk and not sociallogin.user.is_staff:
            sociallogin.user.is_staff = True
            sociallogin.user.save(update_fields=["is_staff"])

    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        _sync_identity_session(request, sociallogin)
        email = user.email or getattr(sociallogin.account, "extra_data", {}).get("email")
        if email and hasattr(user, "username"):
            if user.username != email:
                user.username = email
                user.save(update_fields=["username"])
        if not user.is_staff:
            user.is_staff = True
            user.save(update_fields=["is_staff"])
        return user


def _sync_identity_session(request, sociallogin):
    account = getattr(sociallogin, "account", None)
    extra_data = getattr(account, "extra_data", {}) or {}
    subject = (getattr(account, "uid", "") or extra_data.get("sub") or "").strip()
    if not subject:
        return
    email = (
        (getattr(getattr(sociallogin, "user", None), "email", "") or extra_data.get("email") or "")
        .strip()
        .lower()
    )
    issuer = (os.environ.get("OIDC_ISSUER", "https://accounts.google.com").strip() or "https://accounts.google.com")
    provider_id = os.environ.get("OIDC_PROVIDER_ID", "google-workspace").strip() or "google-workspace"
    display_name = (extra_data.get("name") or "").strip()

    identity, created = UserIdentity.objects.get_or_create(
        issuer=issuer,
        subject=subject,
        defaults={
            "provider_id": provider_id,
            "provider": "google",
            "email": email,
            "display_name": display_name,
            "claims_json": extra_data,
            "last_login_at": timezone.now(),
        },
    )
    updated_fields = []
    if identity.provider_id != provider_id:
        identity.provider_id = provider_id
        updated_fields.append("provider_id")
    if identity.provider != "google":
        identity.provider = "google"
        updated_fields.append("provider")
    if email and identity.email != email:
        identity.email = email
        updated_fields.append("email")
    if display_name and identity.display_name != display_name:
        identity.display_name = display_name
        updated_fields.append("display_name")
    if identity.claims_json != extra_data:
        identity.claims_json = extra_data
        updated_fields.append("claims_json")
    identity.last_login_at = timezone.now()
    updated_fields.append("last_login_at")
    if created or updated_fields:
        identity.save(update_fields=updated_fields)

    if (
        os.environ.get("ALLOW_FIRST_ADMIN_BOOTSTRAP", "").lower() == "true"
        and not RoleBinding.objects.exists()
    ):
        RoleBinding.objects.get_or_create(
            user_identity=identity,
            scope_kind="platform",
            role="platform_admin",
        )

    request.session["user_identity_id"] = str(identity.id)
    request.session.modified = True
