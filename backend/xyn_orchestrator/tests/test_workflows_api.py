import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import RoleBinding, UserIdentity, Workspace


class WorkflowsApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username="wf-admin", password="pass", is_staff=True)
        self.client.force_login(self.user)
        self.identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer", subject="wf-admin", email="wf-admin@example.com")
        RoleBinding.objects.create(user_identity=self.identity, scope_kind="platform", role="platform_admin")
        self.workspace, _ = Workspace.objects.get_or_create(slug="platform-builder", defaults={"name": "Platform Builder"})
        session = self.client.session
        session["user_identity_id"] = str(self.identity.id)
        session.save()

    def _tour_spec(self):
        return {
            "profile": "tour",
            "schema_version": 1,
            "title": "Test Tour",
            "description": "desc",
            "category_slug": "xyn_usage",
            "steps": [
                {
                    "id": "s1",
                    "type": "modal",
                    "title": "Welcome",
                    "body_md": "hello",
                    "route": "/app/home",
                }
            ],
            "settings": {"allow_skip": True, "show_progress": True},
        }

    def test_create_and_list_workflow(self):
        response = self.client.post(
            "/xyn/api/workflows",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "My Tour",
                    "slug": "my-tour",
                    "profile": "tour",
                    "category_slug": "xyn_usage",
                    "visibility_type": "authenticated",
                    "workflow_spec_json": self._tour_spec(),
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        workflow_id = response.json()["workflow"]["id"]

        listing = self.client.get("/xyn/api/workflows?profile=tour&include_unpublished=1")
        self.assertEqual(listing.status_code, 200)
        self.assertTrue(any(row["id"] == workflow_id for row in listing.json().get("workflows", [])))

    def test_invalid_spec_rejected(self):
        response = self.client.post(
            "/xyn/api/workflows",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Bad Tour",
                    "slug": "bad-tour",
                    "profile": "tour",
                    "workflow_spec_json": {"profile": "tour", "steps": []},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_action_execution_and_run_logging(self):
        create = self.client.post(
            "/xyn/api/workflows",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Action Tour",
                    "slug": "action-tour",
                    "profile": "tour",
                    "workflow_spec_json": self._tour_spec(),
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        workflow_id = create.json()["workflow"]["id"]

        action = self.client.post(
            "/xyn/api/workflows/actions/execute",
            data=json.dumps({
                "action_id": "blueprint.create_demo_draft",
                "params": {"title": "demo-wf"},
            }),
            content_type="application/json",
        )
        self.assertEqual(action.status_code, 200, action.content.decode())

        start = self.client.post(f"/xyn/api/workflows/{workflow_id}/run/start", data=json.dumps({}), content_type="application/json")
        self.assertEqual(start.status_code, 200)
        run_id = start.json()["run"]["id"]

        event = self.client.post(
            f"/xyn/api/workflows/{workflow_id}/run/{run_id}/event",
            data=json.dumps({"step_id": "s1", "type": "step_viewed", "payload_json": {"ok": True}}),
            content_type="application/json",
        )
        self.assertEqual(event.status_code, 200)

        complete = self.client.post(
            f"/xyn/api/workflows/{workflow_id}/run/{run_id}/complete",
            data=json.dumps({"status": "completed"}),
            content_type="application/json",
        )
        self.assertEqual(complete.status_code, 200)
