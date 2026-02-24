import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.access_explorer import merge_scope, compute_effective_permissions
from xyn_orchestrator.models import RoleBinding, UserIdentity


class AccessExplorerApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(username="access-explorer-admin", password="pass", is_staff=True)
        self.client.force_login(self.staff)

        self.admin_identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="admin-subject", email="admin@example.com", display_name="Admin"
        )
        self.dev_identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="dev-subject", email="dev@example.com", display_name="Dev"
        )
        self.operator_identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="op-subject", email="op@example.com", display_name="Operator"
        )

        RoleBinding.objects.create(user_identity=self.admin_identity, scope_kind="platform", role="platform_admin")
        RoleBinding.objects.create(user_identity=self.dev_identity, scope_kind="platform", role="platform_operator")
        RoleBinding.objects.create(user_identity=self.operator_identity, scope_kind="platform", role="platform_operator")

    def _set_identity(self, identity: UserIdentity):
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()

    def test_registry_endpoint_returns_canonical_payload(self):
        self._set_identity(self.admin_identity)
        response = self.client.get("/xyn/api/access/registry")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("permissions", payload)
        self.assertIn("roles", payload)
        self.assertIn("rolePermissions", payload)
        self.assertTrue(any(p.get("key") == "manage_users" for p in payload["permissions"]))

    def test_access_users_roles_and_effective_endpoints(self):
        self._set_identity(self.admin_identity)

        users_response = self.client.get("/xyn/api/access/users?query=dev")
        self.assertEqual(users_response.status_code, 200)
        users = users_response.json().get("users") or []
        self.assertTrue(any(item.get("email") == "dev@example.com" for item in users))

        roles_response = self.client.get(f"/xyn/api/access/users/{self.dev_identity.id}/roles")
        self.assertEqual(roles_response.status_code, 200)
        roles = roles_response.json().get("roles") or []
        self.assertTrue(any(item.get("roleId") == "platform_operator" for item in roles))

        effective_response = self.client.get(f"/xyn/api/access/users/{self.dev_identity.id}/effective")
        self.assertEqual(effective_response.status_code, 200)
        effective_payload = effective_response.json()
        self.assertIn("effective", effective_payload)
        self.assertIn("summary", effective_payload)
        self.assertTrue(any(item.get("permissionKey") == "view_platform" for item in effective_payload["effective"]))

    def test_role_detail_endpoint(self):
        self._set_identity(self.admin_identity)
        response = self.client.get("/xyn/api/access/roles/platform_admin")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["role"]["id"], "platform_admin")
        self.assertTrue(any(item.get("permissionKey") == "manage_users" for item in payload.get("permissions") or []))

    def test_scope_merge_is_deterministic(self):
        role_scope = {"scope_kind": "workspace", "scope_id": "abc", "env": "prod"}
        perm_scope = {"resourceType": "article", "env": "stage"}
        merged = merge_scope(role_scope, perm_scope)
        self.assertEqual(
            merged,
            {"scope_kind": "workspace", "scope_id": "abc", "env": "stage", "resourceType": "article"},
        )

    def test_effective_permissions_align_with_role_based_auth(self):
        self._set_identity(self.admin_identity)
        admin_effective = compute_effective_permissions(str(self.admin_identity.id))
        operator_effective = compute_effective_permissions(str(self.operator_identity.id))

        admin_keys = {row["permissionKey"] for row in admin_effective["effective"]}
        operator_keys = {row["permissionKey"] for row in operator_effective["effective"]}

        # mirrors admin-only API constraints in runtime role checks
        self.assertIn("manage_users", admin_keys)
        self.assertNotIn("manage_users", operator_keys)

        forbidden_for_operator = self.client.get("/xyn/api/access/registry")
        self.assertEqual(forbidden_for_operator.status_code, 200)

        self._set_identity(self.operator_identity)
        denied = self.client.get("/xyn/api/access/registry")
        self.assertEqual(denied.status_code, 403)
