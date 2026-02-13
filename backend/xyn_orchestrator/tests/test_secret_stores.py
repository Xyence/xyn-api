import json
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from xyn_orchestrator.models import IdentityProvider, RoleBinding, SecretRef, SecretStore, UserIdentity


class SecretStoreApiTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="platform-admin",
            email="platform-admin@xyence.io",
            password="x",
            is_staff=True,
            is_active=True,
        )
        self.identity = UserIdentity.objects.create(
            provider="oidc",
            provider_id="google",
            issuer="https://accounts.google.com",
            subject="platform-admin",
            email="platform-admin@xyence.io",
        )
        RoleBinding.objects.create(user_identity=self.identity, scope_kind="platform", role="platform_admin")
        self.client.force_login(self.user)
        session = self.client.session
        session["user_identity_id"] = str(self.identity.id)
        session.save()

    def _create_default_store(self) -> SecretStore:
        return SecretStore.objects.create(
            name="default-aws",
            kind="aws_secrets_manager",
            is_default=True,
            config_json={"aws_region": "us-east-1", "name_prefix": "/xyn", "tags": {"xyn:managed": "true"}},
        )

    def test_secret_store_default_enforced_singleton(self):
        SecretStore.objects.create(
            name="primary",
            kind="aws_secrets_manager",
            is_default=True,
            config_json={"aws_region": "us-east-1", "name_prefix": "/xyn"},
        )
        store = SecretStore(
            name="secondary",
            kind="aws_secrets_manager",
            is_default=True,
            config_json={"aws_region": "us-east-1", "name_prefix": "/xyn"},
        )
        with self.assertRaises(ValidationError):
            store.full_clean()

    @mock.patch("xyn_orchestrator.secret_stores.boto3.client")
    def test_create_secret_writes_to_secrets_manager_and_creates_secretref(self, mock_boto_client):
        store = self._create_default_store()
        mock_sm = mock.Mock()

        class _ResourceExists(Exception):
            pass

        mock_sm.exceptions = mock.Mock(ResourceExistsException=_ResourceExists)
        mock_sm.create_secret.return_value = {"ARN": "arn:aws:secretsmanager:us-east-1:123:secret:/xyn/platform/idp/google/client_secret"}
        mock_boto_client.return_value = mock_sm

        response = self.client.post(
            "/xyn/internal/secrets",
            data=json.dumps(
                {
                    "name": "idp/google/client_secret",
                    "scope_kind": "platform",
                    "scope_id": None,
                    "store_id": str(store.id),
                    "value": "super-secret-value",
                    "description": "Google OIDC secret",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        secret_ref_id = body["secret_ref"]["id"]
        ref = SecretRef.objects.get(id=secret_ref_id)
        self.assertEqual(ref.scope_kind, "platform")
        self.assertEqual(ref.store_id, store.id)
        self.assertTrue(ref.external_ref.startswith("arn:aws:secretsmanager:"))
        self.assertEqual(ref.type, "secrets_manager")
        mock_sm.create_secret.assert_called_once()

    @mock.patch("xyn_orchestrator.secret_stores.boto3.client")
    def test_secret_value_never_returned(self, mock_boto_client):
        store = self._create_default_store()
        mock_sm = mock.Mock()

        class _ResourceExists(Exception):
            pass

        mock_sm.exceptions = mock.Mock(ResourceExistsException=_ResourceExists)
        mock_sm.create_secret.return_value = {"ARN": "arn:aws:secretsmanager:us-east-1:123:secret:/xyn/platform/idp/google/client_secret"}
        mock_boto_client.return_value = mock_sm

        response = self.client.post(
            "/xyn/internal/secrets",
            data=json.dumps(
                {
                    "name": "idp/google/client_secret",
                    "scope_kind": "platform",
                    "value": "ultra-secret",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        payload_text = json.dumps(payload)
        self.assertNotIn("ultra-secret", payload_text)
        self.assertNotIn("value", payload["secret_ref"])
        self.assertEqual(payload["secret_ref"]["store_id"], str(store.id))

    @mock.patch("xyn_orchestrator.secret_stores.boto3.client")
    def test_scope_auth_platform_only_for_platform_secret(self, mock_boto_client):
        User = get_user_model()
        limited_user = User.objects.create_user(
            username="tenant-viewer",
            email="tenant-viewer@xyence.io",
            password="x",
            is_staff=False,
            is_active=True,
        )
        limited_identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://accounts.google.com",
            subject="tenant-viewer",
            email="tenant-viewer@xyence.io",
        )
        self.client.force_login(limited_user)
        session = self.client.session
        session["user_identity_id"] = str(limited_identity.id)
        session.save()
        self._create_default_store()

        response = self.client.post(
            "/xyn/internal/secrets",
            data=json.dumps(
                {
                    "name": "idp/google/client_secret",
                    "scope_kind": "platform",
                    "value": "x",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        mock_boto_client.assert_not_called()

    @mock.patch("xyn_orchestrator.secret_stores.boto3.client")
    def test_idp_save_with_client_secret_value_creates_secretref_and_stores_ref_only(self, mock_boto_client):
        self._create_default_store()
        mock_sm = mock.Mock()

        class _ResourceExists(Exception):
            pass

        mock_sm.exceptions = mock.Mock(ResourceExistsException=_ResourceExists)
        mock_sm.create_secret.return_value = {"ARN": "arn:aws:secretsmanager:us-east-1:123:secret:/xyn/platform/idp/google-workspace/client_secret"}
        mock_boto_client.return_value = mock_sm

        payload = {
            "id": "google-workspace",
            "display_name": "Google Workspace",
            "enabled": True,
            "issuer": "https://accounts.google.com",
            "client": {
                "client_id": "abc123",
                "client_secret_value": "raw-client-secret",
            },
            "scopes": ["openid", "profile", "email"],
            "pkce": True,
        }
        response = self.client.post(
            "/xyn/api/platform/identity-providers",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        provider = IdentityProvider.objects.get(id="google-workspace")
        self.assertIsNotNone(provider.client_secret_ref_json)
        self.assertEqual(provider.client_secret_ref_json.get("type"), "aws.secrets_manager")
        self.assertTrue(str(provider.client_secret_ref_json.get("ref") or "").startswith("arn:aws:secretsmanager:"))
        self.assertNotIn("raw-client-secret", json.dumps(provider_to_safe_dict(provider)))
        self.assertEqual(SecretRef.objects.filter(name="idp/google-workspace/client_secret").count(), 1)


def provider_to_safe_dict(provider: IdentityProvider) -> dict:
    return {
        "id": provider.id,
        "display_name": provider.display_name,
        "issuer": provider.issuer,
        "client_secret_ref_json": provider.client_secret_ref_json,
    }
