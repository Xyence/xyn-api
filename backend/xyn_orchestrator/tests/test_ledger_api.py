from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.artifact_links import ensure_draft_session_artifact
from xyn_orchestrator.models import Artifact, BlueprintDraftSession, LedgerEvent, UserIdentity


class LedgerApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(
            username="ledger-admin",
            password="pass",
            is_staff=True,
            email="ledger-admin@example.com",
        )
        self.client.force_login(self.staff)
        self.identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="ledger-admin",
            email="ledger-admin@example.com",
            display_name="Ledger Admin",
        )

    def _create_draft_artifact(self) -> Artifact:
        response = self.client.post(
            "/xyn/api/artifacts/create-draft-session",
            data='{"title":"Ledger Draft","kind":"blueprint"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        return Artifact.objects.get(id=response.json()["artifact_id"])

    def test_create_draft_emits_single_ledger_create(self):
        artifact = self._create_draft_artifact()
        events = LedgerEvent.objects.filter(artifact=artifact, action="artifact.create")
        self.assertEqual(events.count(), 1)
        self.assertIn("Draft Session", events.first().summary)

    def test_meaningful_patch_emits_update_non_meaningful_does_not(self):
        artifact = self._create_draft_artifact()
        baseline_count = LedgerEvent.objects.count()

        response = self.client.patch(
            f"/xyn/api/artifacts/{artifact.id}",
            data='{"title":"Ledger Draft Updated"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(LedgerEvent.objects.filter(artifact=artifact, action="artifact.update").count(), 1)

        response = self.client.patch(
            f"/xyn/api/artifacts/{artifact.id}",
            data='{"title":"Ledger Draft Updated"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(LedgerEvent.objects.filter(artifact=artifact, action="artifact.update").count(), 1)
        self.assertEqual(LedgerEvent.objects.count(), baseline_count + 1)

    def test_canonize_emits_canonize_and_blueprint_create_with_dedupe(self):
        session = BlueprintDraftSession.objects.create(
            name="Canonize Session",
            title="Canonize Session",
            namespace="core",
            current_draft_json={"apiVersion": "xyn.blueprint/v1", "kind": "SolutionBlueprint"},
            created_by=self.staff,
            updated_by=self.staff,
        )
        artifact = ensure_draft_session_artifact(session, owner_user=self.staff)

        response = self.client.post(
            f"/xyn/api/artifacts/{artifact.id}/canonize-to-blueprint",
            data='{"name":"canonize-session","namespace":"core"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()

        response_retry = self.client.post(
            f"/xyn/api/artifacts/{artifact.id}/canonize-to-blueprint",
            data='{"name":"canonize-session","namespace":"core"}',
            content_type="application/json",
        )
        self.assertEqual(response_retry.status_code, 200, response_retry.content.decode())

        self.assertEqual(
            LedgerEvent.objects.filter(artifact_id=artifact.id, action="artifact.canonize").count(),
            1,
        )
        self.assertEqual(
            LedgerEvent.objects.filter(artifact_id=payload["blueprint_artifact_id"], action="artifact.create").count(),
            1,
        )

    def test_ledger_query_and_summary_endpoints(self):
        artifact = self._create_draft_artifact()
        response = self.client.get(
            "/xyn/api/ledger",
            {
                "artifact_id": str(artifact.id),
                "action": "artifact.create",
                "workspace": str(artifact.workspace_id),
                "artifact_type": "draft_session",
            },
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        self.assertEqual(response.json()["count"], 1)
        event = response.json()["events"][0]
        self.assertEqual(event["artifact_type"], "draft_session")
        self.assertEqual(event["artifact_title"], artifact.title)
        self.assertEqual(event["artifact_workspace_id"], str(artifact.workspace_id))

        by_user = self.client.get("/xyn/api/ledger/summary/by-user", {"workspace": str(artifact.workspace_id)})
        self.assertEqual(by_user.status_code, 200, by_user.content.decode())
        self.assertTrue(any(int(row.get("create_count", 0)) >= 1 for row in by_user.json()["rows"]))
        first = by_user.json()["rows"][0]
        self.assertIn("top_artifacts", first)
        self.assertIn("total_count", first)

        by_artifact = self.client.get("/xyn/api/ledger/summary/by-artifact", {"artifact_id": str(artifact.id)})
        self.assertEqual(by_artifact.status_code, 200, by_artifact.content.decode())
        self.assertTrue(any(row["action"] == "artifact.create" for row in by_artifact.json()["counts"]))
