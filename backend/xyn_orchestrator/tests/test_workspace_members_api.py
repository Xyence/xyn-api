import json
import uuid
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from xyn_orchestrator.models import RoleBinding, UserIdentity, Workspace, WorkspaceMembership


class WorkspaceMembersApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.admin_user = user_model.objects.create_user(
            username="workspace-admin",
            password="pass",
            email="workspace-admin@example.com",
            is_staff=True,
        )
        self.client.force_login(self.admin_user)
        self.admin_identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="workspace-admin",
            email="workspace-admin@example.com",
        )
        RoleBinding.objects.create(user_identity=self.admin_identity, scope_kind="platform", role="platform_admin")
        self.workspace = Workspace.objects.create(slug=f"civic-lab-{uuid.uuid4().hex[:8]}", name="Civic Lab")
        self.other_workspace = Workspace.objects.create(slug=f"platform-builder-{uuid.uuid4().hex[:8]}", name="Platform Builder")
        WorkspaceMembership.objects.create(
            workspace=self.workspace,
            user_identity=self.admin_identity,
            role="admin",
            termination_authority=True,
        )
        session = self.client.session
        session["user_identity_id"] = str(self.admin_identity.id)
        session.save()

    def test_post_member_by_email_creates_local_user_and_membership(self):
        response = self.client.post(
            f"/xyn/api/workspaces/{self.workspace.id}/members",
            data=json.dumps({"email": "new-customer@example.com", "role": "member"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()
        self.assertTrue(payload.get("created_user"))
        self.assertTrue(payload.get("temp_password"))
        self.assertEqual(payload["member"]["role"], "member")
        self.assertEqual(payload["member"]["auth_source_label"], "Local")
        membership = WorkspaceMembership.objects.get(id=payload["id"])
        self.assertEqual(membership.role, "reader")
        self.assertEqual(membership.user_identity.email.lower(), "new-customer@example.com")

    def test_members_list_includes_auth_source_fields(self):
        identity = UserIdentity.objects.create(
            provider="oidc",
            provider_id="google",
            issuer="https://accounts.google.com",
            subject="member-google",
            email="member-google@example.com",
        )
        WorkspaceMembership.objects.create(
            workspace=self.workspace,
            user_identity=identity,
            role="reader",
            termination_authority=False,
        )
        response = self.client.get(f"/xyn/api/workspaces/{self.workspace.id}/members")
        self.assertEqual(response.status_code, 200, response.content.decode())
        memberships = response.json().get("memberships", [])
        google_member = next((row for row in memberships if row.get("email") == "member-google@example.com"), None)
        self.assertIsNotNone(google_member)
        self.assertEqual(google_member.get("auth_source"), "google")
        self.assertEqual(google_member.get("auth_source_label"), "Google IdP")

    def test_delete_member_removes_membership(self):
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="member-one",
            email="member-one@example.com",
        )
        membership = WorkspaceMembership.objects.create(
            workspace=self.workspace,
            user_identity=identity,
            role="reader",
            termination_authority=False,
        )
        response = self.client.delete(f"/xyn/api/workspaces/{self.workspace.id}/members/{membership.id}")
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.json().get("status"), "deleted")
        self.assertFalse(WorkspaceMembership.objects.filter(id=membership.id).exists())

    def test_local_user_can_sign_in_with_temp_password(self):
        add_response = self.client.post(
            f"/xyn/api/workspaces/{self.workspace.id}/members",
            data=json.dumps({"email": "local-demo@example.com", "role": "member"}),
            content_type="application/json",
        )
        self.assertEqual(add_response.status_code, 200, add_response.content.decode())
        temp_password = add_response.json().get("temp_password")
        self.assertTrue(temp_password)

        self.client.logout()
        login_response = self.client.post(
            "/auth/local-login",
            data={
                "appId": "xyn-ui",
                "returnTo": "/app",
                "email": "local-demo@example.com",
                "password": temp_password,
            },
        )
        self.assertEqual(login_response.status_code, 302, login_response.content.decode())
        self.assertEqual(login_response["Location"], "/app")
        self.assertTrue(self.client.session.get("user_identity_id"))

    def test_workspace_list_platform_admin_sees_all_and_member_sees_only_assigned(self):
        admin_response = self.client.get("/xyn/api/workspaces")
        self.assertEqual(admin_response.status_code, 200, admin_response.content.decode())
        admin_ids = {row["id"] for row in admin_response.json().get("workspaces", [])}
        self.assertIn(str(self.workspace.id), admin_ids)
        self.assertIn(str(self.other_workspace.id), admin_ids)

        user_model = get_user_model()
        member_user = user_model.objects.create_user(
            username="workspace-member",
            password="pass",
            email="workspace-member@example.com",
        )
        member_identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="workspace-member",
            email="workspace-member@example.com",
        )
        WorkspaceMembership.objects.create(
            workspace=self.workspace,
            user_identity=member_identity,
            role="reader",
            termination_authority=False,
        )
        member_client = Client()
        member_client.force_login(member_user)
        member_session = member_client.session
        member_session["user_identity_id"] = str(member_identity.id)
        member_session.save()

        member_response = member_client.get("/xyn/api/workspaces")
        self.assertEqual(member_response.status_code, 200, member_response.content.decode())
        member_ids = {row["id"] for row in member_response.json().get("workspaces", [])}
        self.assertEqual(member_ids, {str(self.workspace.id)})

    def test_workspace_auth_policy_patch_and_get(self):
        patch_response = self.client.patch(
            f"/xyn/api/workspaces/{self.workspace.id}/auth-policy",
            data=json.dumps(
                {
                    "auth_mode": "oidc",
                    "oidc_enabled": True,
                    "oidc_issuer_url": "https://issuer.example.com",
                    "oidc_client_id": "workspace-client-id",
                    "oidc_scopes": "openid profile email",
                    "oidc_claim_email": "email",
                    "oidc_allow_auto_provision": False,
                    "oidc_allowed_email_domains": ["example.com"],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(patch_response.status_code, 200, patch_response.content.decode())
        get_response = self.client.get(f"/xyn/api/workspaces/{self.workspace.id}/auth-policy")
        self.assertEqual(get_response.status_code, 200, get_response.content.decode())
        policy = get_response.json().get("auth_policy", {})
        self.assertEqual(policy.get("auth_mode"), "oidc")
        self.assertTrue(policy.get("oidc_enabled"))
        self.assertEqual(policy.get("oidc_issuer_url"), "https://issuer.example.com")
        self.assertEqual(policy.get("oidc_client_id"), "workspace-client-id")

    @mock.patch("xyn_orchestrator.xyn_api.requests.get")
    def test_workspace_auth_policy_test_discovery(self, mock_get):
        self.workspace.oidc_issuer_url = "https://issuer.example.com"
        self.workspace.save(update_fields=["oidc_issuer_url", "updated_at"])
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/oauth2/v1/authorize",
            "token_endpoint": "https://issuer.example.com/oauth2/v1/token",
            "jwks_uri": "https://issuer.example.com/oauth2/v1/keys",
        }
        mock_get.return_value.raise_for_status.return_value = None
        response = self.client.post(f"/xyn/api/workspaces/{self.workspace.id}/auth-policy/test-discovery")
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertTrue(response.json().get("ok"))

    @mock.patch("xyn_orchestrator.xyn_api.requests.get")
    def test_workspace_oidc_login_redirects_to_authorize_endpoint(self, mock_get):
        self.workspace.auth_mode = "oidc"
        self.workspace.oidc_enabled = True
        self.workspace.oidc_issuer_url = "https://issuer.example.com"
        self.workspace.oidc_client_id = "workspace-client-id"
        self.workspace.save(update_fields=["auth_mode", "oidc_enabled", "oidc_issuer_url", "oidc_client_id", "updated_at"])
        mock_get.return_value.status_code = 200
        mock_get.return_value.raise_for_status.return_value = None
        mock_get.return_value.json.return_value = {
            "authorization_endpoint": "https://issuer.example.com/oauth2/v1/authorize",
        }
        response = self.client.get(f"/w/{self.workspace.id}/auth/login")
        self.assertEqual(response.status_code, 302, response.content.decode())
        self.assertIn("https://issuer.example.com/oauth2/v1/authorize", response["Location"])
