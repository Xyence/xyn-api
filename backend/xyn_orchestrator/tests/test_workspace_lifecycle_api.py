import importlib
import json

from django.apps import apps as django_apps
from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import RoleBinding, UserIdentity, Workspace, WorkspaceMembership

backfill_workspace_org_name = importlib.import_module(
    "xyn_orchestrator.migrations.0094_workspace_lifecycle_metadata"
).backfill_workspace_org_name


class WorkspaceLifecycleApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username="workspace-admin", password="pass", is_staff=True)
        self.client.force_login(self.user)
        self.identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="workspace-admin",
            email="workspace-admin@example.com",
        )
        RoleBinding.objects.create(user_identity=self.identity, scope_kind="platform", role="platform_admin")
        self.operator = Workspace.objects.create(slug="operator", name="Operator Workspace")
        WorkspaceMembership.objects.create(workspace=self.operator, user_identity=self.identity, role="admin", termination_authority=True)
        session = self.client.session
        session["user_identity_id"] = str(self.identity.id)
        session.save()

    def test_create_workspace_with_parent_and_defaults(self):
        response = self.client.post(
            "/xyn/api/workspaces",
            data=json.dumps(
                {
                    "name": "Acme Power",
                    "org_name": "Acme Power",
                    "kind": "customer",
                    "lifecycle_stage": "prospect",
                    "parent_workspace_id": str(self.operator.id),
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()["workspace"]
        self.assertEqual(payload["org_name"], "Acme Power")
        self.assertEqual(payload["kind"], "customer")
        self.assertEqual(payload["lifecycle_stage"], "prospect")
        self.assertEqual(payload["parent_workspace_id"], str(self.operator.id))
        created = Workspace.objects.get(id=payload["id"])
        self.assertEqual(created.parent_workspace_id, self.operator.id)
        self.assertTrue(WorkspaceMembership.objects.filter(workspace=created, user_identity=self.identity, role="admin").exists())

    def test_patch_workspace_lifecycle_fields(self):
        child = Workspace.objects.create(slug="acme-power", name="Acme Power")
        WorkspaceMembership.objects.create(workspace=child, user_identity=self.identity, role="admin", termination_authority=True)
        response = self.client.patch(
            f"/xyn/api/workspaces/{child.id}",
            data=json.dumps(
                {
                    "org_name": "Acme Power Co.",
                    "kind": "customer",
                    "lifecycle_stage": "customer",
                    "parent_workspace_id": str(self.operator.id),
                    "metadata": {"billing_id": "BILL-123"},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()["workspace"]
        self.assertEqual(payload["org_name"], "Acme Power Co.")
        self.assertEqual(payload["lifecycle_stage"], "customer")
        self.assertEqual(payload["parent_workspace_id"], str(self.operator.id))
        self.assertEqual(payload["metadata"]["billing_id"], "BILL-123")

    def test_cycle_prevention_rejects_descendant_parent(self):
        parent = Workspace.objects.create(slug="parent-ws", name="Parent")
        child = Workspace.objects.create(slug="child-ws", name="Child", parent_workspace=parent)
        WorkspaceMembership.objects.create(workspace=parent, user_identity=self.identity, role="admin", termination_authority=True)
        WorkspaceMembership.objects.create(workspace=child, user_identity=self.identity, role="admin", termination_authority=True)
        response = self.client.patch(
            f"/xyn/api/workspaces/{parent.id}",
            data=json.dumps({"parent_workspace_id": str(child.id)}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400, response.content.decode())
        self.assertEqual(response.json().get("error"), "parent_workspace_id creates a cycle")

    def test_workspace_list_includes_lifecycle_fields(self):
        child = Workspace.objects.create(slug="prospect-ws", name="Prospect Workspace", kind="customer", lifecycle_stage="prospect", parent_workspace=self.operator)
        WorkspaceMembership.objects.create(workspace=child, user_identity=self.identity, role="contributor", termination_authority=False)
        response = self.client.get("/xyn/api/workspaces")
        self.assertEqual(response.status_code, 200, response.content.decode())
        row = next(item for item in response.json().get("workspaces", []) if item["id"] == str(child.id))
        self.assertEqual(row["kind"], "customer")
        self.assertEqual(row["lifecycle_stage"], "prospect")
        self.assertEqual(row["parent_workspace_id"], str(self.operator.id))

    def test_backfill_sets_org_name_for_existing_rows(self):
        ws = Workspace.objects.create(slug="legacy-org", name="Legacy Org", org_name=None)
        backfill_workspace_org_name(django_apps, None)
        ws.refresh_from_db()
        self.assertEqual(ws.org_name, "Legacy Org")
