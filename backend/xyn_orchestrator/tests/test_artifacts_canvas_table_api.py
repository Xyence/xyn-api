import json
import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from xyn_orchestrator.models import Artifact, ArtifactType, Workspace, WorkspaceArtifactBinding


class ArtifactsCanvasTableApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(username="staff", email="staff@example.com", password="pass", is_staff=True)
        self.client.force_login(self.staff)
        self.workspace, _ = Workspace.objects.get_or_create(slug="platform-builder", defaults={"name": "Platform Builder"})
        self.module_type, _ = ArtifactType.objects.get_or_create(slug="module", defaults={"name": "Module"})
        self.article_type, _ = ArtifactType.objects.get_or_create(slug="article", defaults={"name": "Article"})

    def _create_artifact(self, *, slug: str, title: str, kind: str = "module") -> Artifact:
        artifact_type = self.module_type if kind == "module" else self.article_type
        unique_slug = f"{slug}-{uuid.uuid4().hex[:6]}"
        return Artifact.objects.create(
            workspace=self.workspace,
            type=artifact_type,
            title=title,
            slug=unique_slug,
            status="published",
            visibility="team",
        )

    def test_structured_canvas_returns_schema_and_rows(self):
        core = self._create_artifact(slug="core.authn-jwt", title="Auth JWT", kind="module")
        self._create_artifact(slug="content.article-1", title="Article One", kind="article")
        WorkspaceArtifactBinding.objects.create(workspace=self.workspace, artifact=core, enabled=True, installed_state="installed")

        response = self.client.get(
            "/xyn/api/artifacts",
            {
                "entity": "artifacts",
                "workspace_id": str(self.workspace.id),
                "filters": json.dumps([{"field": "namespace", "op": "eq", "value": "core"}]),
                "sort": json.dumps([{"field": "updated_at", "dir": "desc"}]),
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload.get("type"), "canvas.table")
        dataset = payload.get("dataset") or {}
        self.assertEqual(dataset.get("name"), "artifacts")
        self.assertEqual(dataset.get("primary_key"), "slug")
        columns = dataset.get("columns") or []
        self.assertTrue(any(col.get("key") == "namespace" for col in columns))
        rows = dataset.get("rows") or []
        self.assertGreaterEqual(len(rows), 1)
        matching = [row for row in rows if str(row.get("slug") or "").startswith("core.authn-jwt")]
        self.assertTrue(matching)
        self.assertEqual(matching[0].get("installed"), True)

    def test_relative_time_filter_now_1h(self):
        recent = self._create_artifact(slug="core.recent", title="Recent Module", kind="module")
        stale = self._create_artifact(slug="core.stale", title="Stale Module", kind="module")
        Artifact.objects.filter(id=recent.id).update(updated_at=timezone.now() - timezone.timedelta(minutes=30))
        Artifact.objects.filter(id=stale.id).update(updated_at=timezone.now() - timezone.timedelta(hours=2))

        response = self.client.get(
            "/xyn/api/artifacts",
            {
                "entity": "artifacts",
                "filters": json.dumps([{"field": "updated_at", "op": "gte", "value": "now-1h"}]),
                "sort": json.dumps([{"field": "updated_at", "dir": "desc"}]),
            },
        )
        self.assertEqual(response.status_code, 200)
        rows = ((response.json() or {}).get("dataset") or {}).get("rows") or []
        slugs = {str(row.get("slug") or "") for row in rows}
        self.assertTrue(any(slug.startswith("core.recent") for slug in slugs) or len(slugs) > 0)
        self.assertFalse(any(slug.startswith("core.stale") for slug in slugs))

    def test_installed_filter_requires_workspace_context(self):
        self._create_artifact(slug="core.authn-jwt", title="Auth JWT", kind="module")
        response = self.client.get(
            "/xyn/api/artifacts",
            {
                "entity": "artifacts",
                "filters": json.dumps([{"field": "installed", "op": "eq", "value": True}]),
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("workspace_id", str(response.json().get("error")))
