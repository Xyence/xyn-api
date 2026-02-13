import os
from types import SimpleNamespace
from unittest import mock

from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory, TestCase

from xyn_orchestrator.models import RoleBinding, UserIdentity
from xyence.adapters import DomainRestrictedSocialAccountAdapter


def _with_session(request):
    middleware = SessionMiddleware(lambda req: None)
    middleware.process_request(request)
    request.session.save()
    return request


class DomainRestrictedSocialAccountAdapterTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.adapter = DomainRestrictedSocialAccountAdapter()
        self.User = get_user_model()

    def _sociallogin(self, *, email: str, uid: str, name: str = "User"):
        user = self.User(username=email, email=email, is_active=True)
        account = SimpleNamespace(
            uid=uid,
            extra_data={"email": email, "sub": uid, "name": name},
        )
        return SimpleNamespace(user=user, account=account)

    def test_save_user_syncs_identity_and_session(self):
        request = _with_session(self.factory.get("/accounts/google/login/callback/"))
        sociallogin = self._sociallogin(email="jrestivo@xyence.io", uid="sub-123")
        persisted_user = self.User.objects.create(
            username="jrestivo",
            email="jrestivo@xyence.io",
            is_active=True,
            is_staff=False,
        )
        with mock.patch.object(DefaultSocialAccountAdapter, "save_user", return_value=persisted_user):
            user = self.adapter.save_user(request, sociallogin)

        self.assertTrue(user.is_staff)
        self.assertEqual(user.username, "jrestivo@xyence.io")
        identity = UserIdentity.objects.get(issuer="https://accounts.google.com", subject="sub-123")
        self.assertEqual(identity.email, "jrestivo@xyence.io")
        self.assertEqual(request.session.get("user_identity_id"), str(identity.id))

    def test_save_user_bootstraps_first_platform_admin_when_enabled(self):
        request = _with_session(self.factory.get("/accounts/google/login/callback/"))
        sociallogin = self._sociallogin(email="firstadmin@xyence.io", uid="sub-first")
        persisted_user = self.User.objects.create(
            username="firstadmin",
            email="firstadmin@xyence.io",
            is_active=True,
            is_staff=False,
        )
        env = {**os.environ, "ALLOW_FIRST_ADMIN_BOOTSTRAP": "true"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(DefaultSocialAccountAdapter, "save_user", return_value=persisted_user),
        ):
            self.adapter.save_user(request, sociallogin)

        identity = UserIdentity.objects.get(issuer="https://accounts.google.com", subject="sub-first")
        self.assertTrue(
            RoleBinding.objects.filter(
                user_identity=identity,
                scope_kind="platform",
                role="platform_admin",
            ).exists()
        )
