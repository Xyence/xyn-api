import importlib

from django.apps import apps as django_apps
from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.artifact_links import ensure_blueprint_artifact, ensure_draft_session_artifact
from xyn_orchestrator.models import Artifact, Blueprint, BlueprintDraftSession, UserIdentity


class UnifiedArtifactsApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(username="artifact-admin", password="pass", is_staff=True, email="admin@example.com")
        self.client.force_login(self.staff)
        self.identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="artifact-admin",
            email="admin@example.com",
            display_name="Artifact Admin",
        )

    def test_backfill_forward_is_idempotent(self):
        blueprint = Blueprint.objects.create(name="bp-one", namespace="core", created_by=self.staff, updated_by=self.staff)
        session = BlueprintDraftSession.objects.create(name="Draft one", title="Draft one", created_by=self.staff, updated_by=self.staff)

        migration = importlib.import_module("xyn_orchestrator.migrations.0081_unified_artifact_links")
        migration.forward(django_apps, None)
        blueprint.refresh_from_db()
        session.refresh_from_db()
        first_count = Artifact.objects.filter(source_ref_id__in=[str(blueprint.id), str(session.id)]).count()

        migration.forward(django_apps, None)
        blueprint.refresh_from_db()
        session.refresh_from_db()
        second_count = Artifact.objects.filter(source_ref_id__in=[str(blueprint.id), str(session.id)]).count()

        self.assertIsNotNone(blueprint.artifact_id)
        self.assertIsNotNone(session.artifact_id)
        self.assertEqual(first_count, 2)
        self.assertEqual(second_count, 2)

    def test_artifacts_list_filters_by_type_and_query(self):
        blueprint = Blueprint.objects.create(
            name="signal-gateway",
            namespace="core",
            description="Signal processing",
            created_by=self.staff,
            updated_by=self.staff,
        )
        session = BlueprintDraftSession.objects.create(
            name="billing draft",
            title="Billing Draft",
            created_by=self.staff,
            updated_by=self.staff,
        )
        ensure_blueprint_artifact(blueprint, owner_user=self.staff)
        ensure_draft_session_artifact(session, owner_user=self.staff)

        response = self.client.get("/xyn/api/artifacts", {"type": "blueprint", "query": "signal"})
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["artifacts"][0]["artifact_type"], "blueprint")
        self.assertEqual(payload["artifacts"][0]["source"]["name"], "signal-gateway")

    def test_artifact_detail_embeds_source(self):
        session = BlueprintDraftSession.objects.create(
            name="api draft",
            title="API Draft",
            created_by=self.staff,
            updated_by=self.staff,
        )
        artifact = ensure_draft_session_artifact(session, owner_user=self.staff)

        response = self.client.get(f"/xyn/api/artifacts/{artifact.id}")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["artifact_type"], "draft_session")
        self.assertEqual(payload["source"]["id"], str(session.id))
