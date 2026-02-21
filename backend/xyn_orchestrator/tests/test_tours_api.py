from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import RoleBinding, UserIdentity


class ToursApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(username="staff-tours", password="pass", is_staff=True)
        self.client.force_login(self.staff)
        self.identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="tour-user", email="tour-user@example.com"
        )
        RoleBinding.objects.create(user_identity=self.identity, scope_kind="platform", role="app_user")
        session = self.client.session
        session["user_identity_id"] = str(self.identity.id)
        session.save()

    def test_deploy_subscriber_notes_tour_uses_v2_schema(self):
        response = self.client.get("/xyn/api/tours/deploy-subscriber-notes")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload.get("schema_version"), 2)
        self.assertEqual(payload.get("slug"), "deploy-subscriber-notes")
        self.assertTrue(any(step.get("id") == "draft-create" for step in payload.get("steps", [])))
        self.assertIn("variables", payload)

