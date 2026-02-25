from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.artifact_links import ensure_blueprint_artifact
from xyn_orchestrator.models import Artifact, Blueprint, LedgerEvent, UserIdentity


class BlueprintProvisionalVersionTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(
            username="blueprint-version-admin",
            password="pass",
            is_staff=True,
            email="versions@example.com",
        )
        self.client.force_login(self.staff)
        self.identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="blueprint-version-admin",
            email="versions@example.com",
            display_name="Blueprint Version Admin",
        )

    def test_revise_creates_provisional_artifact(self):
        blueprint = Blueprint.objects.create(name="svc", namespace="core", spec_text="v1", created_by=self.staff, updated_by=self.staff)
        base_artifact = ensure_blueprint_artifact(blueprint, owner_user=self.staff)
        self.assertEqual(base_artifact.artifact_state, "canonical")

        response = self.client.post(f"/xyn/api/blueprints/{base_artifact.id}/revise", data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()
        revised_artifact = Artifact.objects.get(id=payload["artifact_id"])
        self.assertEqual(revised_artifact.artifact_state, "provisional")
        self.assertEqual(revised_artifact.parent_artifact_id, base_artifact.id)
        self.assertEqual(revised_artifact.family_id, base_artifact.family_id or str(base_artifact.id))
        self.assertEqual(LedgerEvent.objects.filter(artifact=revised_artifact, action="artifact.create").count(), 1)

    def test_publish_promotes_provisional_and_supersedes_canonical(self):
        canonical_blueprint = Blueprint.objects.create(name="svc", namespace="core", spec_text="v1", created_by=self.staff, updated_by=self.staff)
        canonical_artifact = ensure_blueprint_artifact(canonical_blueprint, owner_user=self.staff)

        revise = self.client.post(f"/xyn/api/blueprints/{canonical_artifact.id}/revise", data="{}", content_type="application/json")
        self.assertEqual(revise.status_code, 200, revise.content.decode())
        provisional_artifact = Artifact.objects.get(id=revise.json()["artifact_id"])
        family_id = provisional_artifact.family_id

        publish = self.client.post(f"/xyn/api/blueprints/{provisional_artifact.id}/publish", data="{}", content_type="application/json")
        self.assertEqual(publish.status_code, 200, publish.content.decode())
        canonical_artifact.refresh_from_db()
        provisional_artifact.refresh_from_db()
        self.assertEqual(canonical_artifact.artifact_state, "deprecated")
        self.assertEqual(provisional_artifact.artifact_state, "canonical")
        canonical_count = Artifact.objects.filter(type__slug="blueprint", family_id=family_id, artifact_state="canonical").count()
        self.assertEqual(canonical_count, 1)

        publish_retry = self.client.post(f"/xyn/api/blueprints/{provisional_artifact.id}/publish", data="{}", content_type="application/json")
        self.assertEqual(publish_retry.status_code, 400)
        self.assertEqual(
            LedgerEvent.objects.filter(artifact=provisional_artifact, action="artifact.update", summary="Published Blueprint version").count(),
            1,
        )
