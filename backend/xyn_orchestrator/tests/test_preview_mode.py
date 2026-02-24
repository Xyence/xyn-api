import json
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from xyn_orchestrator.models import AuditLog, RoleBinding, UserIdentity
from xyn_orchestrator.xyn_api import PREVIEW_SESSION_KEY


class PreviewModeTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(username="preview-staff", password="pass", is_staff=True)
        self.client.force_login(self.staff)

        self.admin_identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="preview-admin", email="admin@example.com"
        )
        self.operator_identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="preview-operator", email="operator@example.com"
        )
        self.owner_identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="preview-owner", email="owner@example.com"
        )

        RoleBinding.objects.create(user_identity=self.admin_identity, scope_kind="platform", role="platform_admin")
        RoleBinding.objects.create(user_identity=self.operator_identity, scope_kind="platform", role="platform_operator")
        RoleBinding.objects.create(user_identity=self.owner_identity, scope_kind="platform", role="platform_owner")

    def _set_identity(self, identity: UserIdentity):
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()

    def test_admin_can_enable_preview_for_operator(self):
        self._set_identity(self.admin_identity)
        response = self.client.post(
            "/xyn/api/preview/enable",
            data=json.dumps({"roles": ["platform_operator"], "readOnly": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()["preview"]
        self.assertTrue(payload["enabled"])
        self.assertEqual(payload["roles"], ["platform_operator"])
        self.assertTrue(payload["read_only"])

        status = self.client.get("/xyn/api/preview/status")
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["preview"]["effective_roles"], ["platform_operator"])
        self.assertTrue(AuditLog.objects.filter(message="PreviewEnabled").exists())

    def test_operator_cannot_enable_preview(self):
        self._set_identity(self.operator_identity)
        response = self.client.post(
            "/xyn/api/preview/enable",
            data=json.dumps({"roles": ["platform_admin"], "readOnly": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(AuditLog.objects.filter(message="PreviewRejected").exists())

    def test_preview_read_only_blocks_mutations(self):
        self._set_identity(self.admin_identity)
        enable = self.client.post(
            "/xyn/api/preview/enable",
            data=json.dumps({"roles": ["platform_operator"], "readOnly": True}),
            content_type="application/json",
        )
        self.assertEqual(enable.status_code, 200)

        blocked = self.client.post(
            "/xyn/api/ai/purposes",
            data=json.dumps({"slug": "preview-test", "name": "Preview Test", "status": "active"}),
            content_type="application/json",
        )
        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(blocked.json().get("code"), "PREVIEW_READ_ONLY")

    def test_preview_effective_roles_applied_to_admin_endpoint(self):
        self._set_identity(self.admin_identity)
        enable = self.client.post(
            "/xyn/api/preview/enable",
            data=json.dumps({"roles": ["platform_operator"], "readOnly": True}),
            content_type="application/json",
        )
        self.assertEqual(enable.status_code, 200)

        forbidden = self.client.get("/xyn/internal/role_bindings")
        self.assertEqual(forbidden.status_code, 403)

    def test_preview_expiry_clears_state(self):
        self._set_identity(self.owner_identity)
        session = self.client.session
        session[PREVIEW_SESSION_KEY] = {
            "enabled": True,
            "roles": ["platform_operator"],
            "read_only": True,
            "started_at": int(timezone.now().timestamp()) - 4000,
            "expires_at": int(timezone.now().timestamp()) - 10,
        }
        session.save()

        status = self.client.get("/xyn/api/preview/status")
        self.assertEqual(status.status_code, 200)
        self.assertFalse(status.json()["preview"]["enabled"])

    def test_disable_preview_emits_audit_event(self):
        self._set_identity(self.admin_identity)
        enable = self.client.post(
            "/xyn/api/preview/enable",
            data=json.dumps({"roles": ["platform_operator"], "readOnly": True}),
            content_type="application/json",
        )
        self.assertEqual(enable.status_code, 200)

        disable = self.client.post("/xyn/api/preview/disable", data=json.dumps({}), content_type="application/json")
        self.assertEqual(disable.status_code, 200)
        self.assertFalse(disable.json()["preview"]["enabled"])
        self.assertTrue(AuditLog.objects.filter(message="PreviewDisabled").exists())
