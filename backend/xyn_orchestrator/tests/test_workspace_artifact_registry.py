import json
import importlib
import os
import tempfile
from pathlib import Path

from django.apps import apps as django_apps
from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import (
    Artifact,
    ArtifactComment,
    ArtifactEvent,
    ArtifactSurface,
    ArtifactType,
    UserIdentity,
    Workspace,
    WorkspaceArtifactBinding,
    WorkspaceMembership,
)

backfill_workspace_artifact_bindings = importlib.import_module(
    "xyn_orchestrator.migrations.0092_workspace_artifact_bindings"
).backfill_workspace_artifact_bindings


class WorkspaceArtifactRegistryTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(username="staff", email="staff@example.com", password="pass", is_staff=True)
        self.client.force_login(self.staff)
        self.admin_identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer", subject="admin", email="admin@example.com")
        self.reader_identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer", subject="reader", email="reader@example.com")
        self.publisher_identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer", subject="publisher", email="publisher@example.com")
        self.workspace, _ = Workspace.objects.get_or_create(slug="civic-lab", defaults={"name": "Civic Lab"})
        self.article_type, _ = ArtifactType.objects.get_or_create(slug="article", defaults={"name": "Article"})

    def _set_identity(self, identity: UserIdentity):
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()

    def test_contributor_can_create_artifact_draft(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        response = self.client.post(
            f"/xyn/api/workspaces/{self.workspace.id}/artifacts",
            data=json.dumps({"type": "article", "title": "A1", "body_markdown": "hello"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        artifact = Artifact.objects.get(id=response.json()["id"])
        self.assertEqual(artifact.status, "draft")

    def test_reader_cannot_create_artifact(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.reader_identity, role="reader")
        self._set_identity(self.reader_identity)
        response = self.client.post(
            f"/xyn/api/workspaces/{self.workspace.id}/artifacts",
            data=json.dumps({"type": "article", "title": "A1"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

    def test_publish_requires_termination_authority(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.publisher_identity, role="publisher", termination_authority=False)
        artifact = Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="A", status="draft")
        self._set_identity(self.publisher_identity)
        response = self.client.post(f"/xyn/api/workspaces/{self.workspace.id}/artifacts/{artifact.id}/publish")
        self.assertEqual(response.status_code, 403)

    def test_admin_can_publish_and_event_logged(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="admin", termination_authority=True)
        artifact = Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="A", status="draft")
        self._set_identity(self.admin_identity)
        response = self.client.post(f"/xyn/api/workspaces/{self.workspace.id}/artifacts/{artifact.id}/publish")
        self.assertEqual(response.status_code, 200)
        artifact.refresh_from_db()
        self.assertEqual(artifact.status, "published")
        self.assertTrue(ArtifactEvent.objects.filter(artifact=artifact, event_type="article_published").exists())

    def test_moderator_can_hide_comment_and_event_logged(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="moderator")
        artifact = Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="A", status="draft")
        comment = ArtifactComment.objects.create(artifact=artifact, user=self.admin_identity, body="bad")
        self._set_identity(self.admin_identity)
        response = self.client.patch(
            f"/xyn/api/workspaces/{self.workspace.id}/artifacts/{artifact.id}/comments/{comment.id}",
            data=json.dumps({"status": "hidden"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        comment.refresh_from_db()
        self.assertEqual(comment.status, "hidden")
        self.assertTrue(ArtifactEvent.objects.filter(artifact=artifact, event_type="comment_hidden").exists())

    def test_workspace_admin_can_update_membership_role(self):
        member = WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.reader_identity, role="reader")
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="admin", termination_authority=True)
        self._set_identity(self.admin_identity)
        response = self.client.patch(
            f"/xyn/api/workspaces/{self.workspace.id}/memberships/{member.id}",
            data=json.dumps({"role": "publisher", "termination_authority": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        member.refresh_from_db()
        self.assertEqual(member.role, "publisher")
        self.assertTrue(member.termination_authority)

    def test_duplicate_slug_in_workspace_is_rejected(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        first = self.client.post(
            f"/xyn/api/workspaces/{self.workspace.id}/artifacts",
            data=json.dumps({"type": "article", "title": "First", "slug": "same-slug"}),
            content_type="application/json",
        )
        self.assertEqual(first.status_code, 200)
        second = self.client.post(
            f"/xyn/api/workspaces/{self.workspace.id}/artifacts",
            data=json.dumps({"type": "article", "title": "Second", "slug": "same-slug"}),
            content_type="application/json",
        )
        self.assertEqual(second.status_code, 400)
        self.assertEqual(second.json().get("error"), "slug already exists in this workspace")

    def test_workspace_artifacts_list_returns_only_bound_artifacts(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        other_workspace = Workspace.objects.create(slug="other-lab", name="Other Lab")
        WorkspaceMembership.objects.create(workspace=other_workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)

        included = Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="Included", status="draft")
        excluded = Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="Excluded", status="draft")
        Artifact.objects.create(workspace=other_workspace, type=self.article_type, title="Other Workspace", status="draft")

        WorkspaceArtifactBinding.objects.create(workspace=self.workspace, artifact=included, installed_state="installed")
        WorkspaceArtifactBinding.objects.create(workspace=other_workspace, artifact=excluded, installed_state="installed")

        response = self.client.get(f"/xyn/api/workspaces/{self.workspace.id}/artifacts")
        self.assertEqual(response.status_code, 200)
        artifact_ids = {row["artifact_id"] for row in response.json().get("artifacts", [])}
        self.assertEqual(artifact_ids, {str(included.id)})

    def test_workspace_artifacts_include_manifest_manage_surfaces(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        module_type, _ = ArtifactType.objects.get_or_create(slug="module", defaults={"name": "Module"})
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manage.manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "artifact": {"id": "manage-app", "name": "Manage App", "version": "1.0.0"},
                        "roles": [{"role": "ui_mount", "mount_path": "/apps/manage"}],
                        "surfaces": {
                            "manage": [{"label": "Settings", "path": "/apps/manage/settings", "order": 50}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            artifact = Artifact.objects.create(
                workspace=self.workspace,
                type=module_type,
                title="Manage App",
                slug="manage-app",
                status="published",
                visibility="team",
                scope_json={"manifest_ref": str(manifest_path)},
            )
            WorkspaceArtifactBinding.objects.create(workspace=self.workspace, artifact=artifact, enabled=True, installed_state="installed")

            response = self.client.get(f"/xyn/api/workspaces/{self.workspace.id}/artifacts")

        self.assertEqual(response.status_code, 200)
        rows = response.json().get("artifacts", [])
        self.assertEqual(len(rows), 1)
        manage = rows[0].get("manifest_summary", {}).get("surfaces", {}).get("manage", [])
        self.assertEqual(manage[0].get("path"), "/apps/manage/settings")

    def test_catalog_returns_global_artifacts(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        module_type, _ = ArtifactType.objects.get_or_create(slug="module", defaults={"name": "Module"})
        Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="A1", slug="a1", status="published")
        Artifact.objects.create(workspace=self.workspace, type=module_type, title="M1", slug="m1", status="published")
        Artifact.objects.create(workspace=self.workspace, type=module_type, title="M2", slug="m2", status="published")
        Artifact.objects.create(workspace=self.workspace, type=module_type, title="M3", slug="m3", status="published")

        response = self.client.get("/xyn/api/artifacts/catalog")
        self.assertEqual(response.status_code, 200)
        rows = response.json().get("artifacts", [])
        self.assertGreaterEqual(len(rows), 3)

    def test_catalog_includes_ems_lite_surfaces(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        module_type, _ = ArtifactType.objects.get_or_create(slug="module", defaults={"name": "Module"})
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "ems-lite.manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "artifact": {"id": "ems-lite", "name": "EMS-lite", "version": "1.0.0"},
                        "roles": [
                            {"role": "api_router", "mount_path": "/api/apps/ems"},
                            {"role": "ui_mount", "mount_path": "/apps/ems"},
                        ],
                        "surfaces": {
                            "nav": [{"label": "EMS", "path": "/apps/ems", "order": 300}],
                            "manage": [{"label": "Settings", "path": "/apps/ems/manage", "order": 100}],
                            "docs": [{"label": "Docs", "path": "/apps/ems/docs", "order": 1000}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            Artifact.objects.create(
                workspace=self.workspace,
                type=module_type,
                title="EMS-lite",
                slug="ems-lite",
                status="published",
                visibility="team",
                scope_json={"manifest_ref": str(manifest_path), "slug": "ems-lite"},
            )
            response = self.client.get("/xyn/api/artifacts/catalog")

        self.assertEqual(response.status_code, 200)
        rows = response.json().get("artifacts", [])
        ems = next((row for row in rows if row.get("slug") == "ems-lite"), None)
        self.assertIsNotNone(ems)
        self.assertEqual(ems.get("manifest_summary", {}).get("surfaces", {}).get("docs", [])[0].get("path"), "/apps/ems/docs")

    def test_catalog_manifest_slug_mismatch_fails_fast(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        module_type, _ = ArtifactType.objects.get_or_create(slug="module", defaults={"name": "Module"})
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "mismatch.manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "artifact": {"id": "wrong-slug", "name": "Mismatch", "version": "1.0.0"},
                        "roles": [{"role": "ui_mount", "mount_path": "/apps/mismatch"}],
                    }
                ),
                encoding="utf-8",
            )
            Artifact.objects.create(
                workspace=self.workspace,
                type=module_type,
                title="Mismatch",
                slug="expected-slug",
                status="published",
                visibility="team",
                scope_json={"manifest_ref": str(manifest_path), "slug": "expected-slug"},
            )
            response = self.client.get("/xyn/api/artifacts/catalog")

        self.assertEqual(response.status_code, 500)
        self.assertIn("manifest slug mismatch", str(response.json().get("error") or ""))

    def test_blueprint_routes_disabled_by_default(self):
        self._set_identity(self.admin_identity)
        api_response = self.client.get("/xyn/api/blueprints")
        web_response = self.client.get("/xyn/blueprints/")
        self.assertEqual(api_response.status_code, 404)
        self.assertEqual(web_response.status_code, 404)

    def test_install_workspace_artifact_binding_is_idempotent(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        artifact = Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="Installable", slug="installable", status="published")

        first = self.client.post(
            f"/xyn/api/workspaces/{self.workspace.id}/artifacts",
            data=json.dumps({"artifact_id": str(artifact.id), "enabled": True}),
            content_type="application/json",
        )
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json().get("created"))
        first_binding_id = first.json().get("artifact", {}).get("binding_id")
        self.assertTrue(first_binding_id)

        second = self.client.post(
            f"/xyn/api/workspaces/{self.workspace.id}/artifacts",
            data=json.dumps({"artifact_id": str(artifact.id), "enabled": True}),
            content_type="application/json",
        )
        self.assertEqual(second.status_code, 200)
        self.assertFalse(second.json().get("created"))
        self.assertEqual(second.json().get("artifact", {}).get("binding_id"), first_binding_id)
        self.assertEqual(
            WorkspaceArtifactBinding.objects.filter(workspace=self.workspace, artifact=artifact).count(),
            1,
        )

    def test_install_workspace_artifact_binding_accepts_slug(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        module_type, _ = ArtifactType.objects.get_or_create(slug="module", defaults={"name": "Module"})
        artifact = Artifact.objects.create(workspace=self.workspace, type=module_type, title="EMS-lite", slug="ems-lite", status="published")

        first = self.client.post(
            f"/xyn/api/workspaces/{self.workspace.id}/artifacts",
            data=json.dumps({"artifact_id": "ems-lite", "enabled": True}),
            content_type="application/json",
        )
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json().get("created"))
        self.assertEqual(first.json().get("artifact", {}).get("artifact_id"), str(artifact.id))

        second = self.client.post(
            f"/xyn/api/workspaces/{self.workspace.id}/artifacts",
            data=json.dumps({"artifact_id": "ems-lite", "enabled": True}),
            content_type="application/json",
        )
        self.assertEqual(second.status_code, 200)
        self.assertFalse(second.json().get("created"))
        self.assertEqual(
            WorkspaceArtifactBinding.objects.filter(workspace=self.workspace, artifact=artifact).count(),
            1,
        )

    def test_uninstall_workspace_artifact_binding_deletes_binding(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        artifact = Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="Installed", slug="installed", status="published")
        binding = WorkspaceArtifactBinding.objects.create(workspace=self.workspace, artifact=artifact, enabled=True, installed_state="installed")

        response = self.client.delete(f"/xyn/api/workspaces/{self.workspace.id}/artifacts/{binding.id}")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json().get("deleted"))
        self.assertFalse(WorkspaceArtifactBinding.objects.filter(id=binding.id).exists())

    def test_backfill_workspace_artifact_bindings_creates_rows(self):
        artifact = Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="Needs binding", status="draft")
        self.assertFalse(WorkspaceArtifactBinding.objects.filter(artifact=artifact).exists())

        backfill_workspace_artifact_bindings(django_apps, None)

        binding = WorkspaceArtifactBinding.objects.filter(artifact=artifact).first()
        self.assertIsNotNone(binding)
        self.assertEqual(str(binding.workspace_id), str(self.workspace.id))
        self.assertEqual(binding.installed_state, "installed")

    def test_internal_workspace_artifacts_requires_token_and_returns_installed_enabled(self):
        artifact = Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="Installed", status="published")
        WorkspaceArtifactBinding.objects.create(
            workspace=self.workspace,
            artifact=artifact,
            enabled=True,
            installed_state="installed",
        )
        WorkspaceArtifactBinding.objects.create(
            workspace=self.workspace,
            artifact=Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="Disabled", status="published"),
            enabled=False,
            installed_state="installed",
        )
        WorkspaceArtifactBinding.objects.create(
            workspace=self.workspace,
            artifact=Artifact.objects.create(workspace=self.workspace, type=self.article_type, title="Pending", status="published"),
            enabled=True,
            installed_state="pending",
        )

        os.environ["XYENCE_INTERNAL_TOKEN"] = "seed-token"
        try:
            denied = self.client.get(f"/xyn/internal/workspaces/{self.workspace.id}/artifacts")
            self.assertEqual(denied.status_code, 401)

            allowed = self.client.get(
                f"/xyn/internal/workspaces/{self.workspace.id}/artifacts",
                HTTP_X_INTERNAL_TOKEN="seed-token",
            )
            self.assertEqual(allowed.status_code, 200)
            rows = allowed.json().get("artifacts", [])
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["artifact_id"], str(artifact.id))
        finally:
            os.environ.pop("XYENCE_INTERNAL_TOKEN", None)

    def test_nav_surfaces_include_manifest_entries_for_bound_workspace_artifacts(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        module_type, _ = ArtifactType.objects.get_or_create(slug="module", defaults={"name": "Module"})
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "hello.manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "artifact": {"id": "hello-app", "name": "Hello App", "version": "phase1c"},
                        "surfaces": {
                            "nav": [
                                {"label": "Hello", "path": "/apps/hello", "order": 900, "group": "build"},
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            artifact = Artifact.objects.create(
                workspace=self.workspace,
                type=module_type,
                title="Hello App",
                slug="hello-app",
                status="published",
                visibility="team",
                scope_json={"manifest_ref": str(manifest_path), "slug": "hello-app"},
            )
            WorkspaceArtifactBinding.objects.create(
                workspace=self.workspace,
                artifact=artifact,
                enabled=True,
                installed_state="installed",
            )
            response = self.client.get(f"/xyn/api/artifact-surfaces/nav?workspace_id={self.workspace.id}")
        self.assertEqual(response.status_code, 200)
        routes = {row.get("route") for row in response.json().get("surfaces", [])}
        self.assertIn("/apps/hello", routes)

    def test_nav_surfaces_exclude_disabled_or_uninstalled_bindings(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        module_type, _ = ArtifactType.objects.get_or_create(slug="module", defaults={"name": "Module"})
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "hello.manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "artifact": {"id": "hello-app", "name": "Hello App", "version": "phase1c"},
                        "surfaces": {"nav": [{"label": "Hello", "path": "/apps/hello"}]},
                    }
                ),
                encoding="utf-8",
            )
            disabled = Artifact.objects.create(
                workspace=self.workspace,
                type=module_type,
                title="Hello Disabled",
                slug="xyn-hello-disabled",
                status="published",
                visibility="team",
                scope_json={"manifest_ref": str(manifest_path)},
            )
            pending = Artifact.objects.create(
                workspace=self.workspace,
                type=module_type,
                title="Hello Pending",
                slug="xyn-hello-pending",
                status="published",
                visibility="team",
                scope_json={"manifest_ref": str(manifest_path)},
            )
            WorkspaceArtifactBinding.objects.create(
                workspace=self.workspace,
                artifact=disabled,
                enabled=False,
                installed_state="installed",
            )
            WorkspaceArtifactBinding.objects.create(
                workspace=self.workspace,
                artifact=pending,
                enabled=True,
                installed_state="pending",
            )
            response = self.client.get(f"/xyn/api/artifact-surfaces/nav?workspace_id={self.workspace.id}")
        self.assertEqual(response.status_code, 200)
        routes = {row.get("route") for row in response.json().get("surfaces", [])}
        self.assertNotIn("/apps/hello", routes)

    def test_nav_surfaces_are_workspace_scoped(self):
        other_workspace = Workspace.objects.create(slug="other-lab", name="Other Lab")
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        WorkspaceMembership.objects.create(workspace=other_workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        module_type, _ = ArtifactType.objects.get_or_create(slug="module", defaults={"name": "Module"})
        with tempfile.TemporaryDirectory() as tmpdir:
            ws_a_manifest = Path(tmpdir) / "a.manifest.json"
            ws_b_manifest = Path(tmpdir) / "b.manifest.json"
            ws_a_manifest.write_text(
                json.dumps({"surfaces": {"nav": [{"label": "Hello A", "path": "/apps/hello-a", "order": 10}]}}),
                encoding="utf-8",
            )
            ws_b_manifest.write_text(
                json.dumps({"surfaces": {"nav": [{"label": "Hello B", "path": "/apps/hello-b", "order": 10}]}}),
                encoding="utf-8",
            )
            artifact_a = Artifact.objects.create(
                workspace=self.workspace,
                type=module_type,
                title="Hello A",
                slug="hello-a",
                status="published",
                visibility="team",
                scope_json={"manifest_ref": str(ws_a_manifest)},
            )
            artifact_b = Artifact.objects.create(
                workspace=other_workspace,
                type=module_type,
                title="Hello B",
                slug="hello-b",
                status="published",
                visibility="team",
                scope_json={"manifest_ref": str(ws_b_manifest)},
            )
            WorkspaceArtifactBinding.objects.create(
                workspace=self.workspace,
                artifact=artifact_a,
                enabled=True,
                installed_state="installed",
            )
            WorkspaceArtifactBinding.objects.create(
                workspace=other_workspace,
                artifact=artifact_b,
                enabled=True,
                installed_state="installed",
            )

            response_a = self.client.get(f"/xyn/api/artifact-surfaces/nav?workspace_id={self.workspace.id}")
            response_b = self.client.get(f"/xyn/api/artifact-surfaces/nav?workspace_id={other_workspace.id}")

        self.assertEqual(response_a.status_code, 200)
        self.assertEqual(response_b.status_code, 200)
        routes_a = {row.get("route") for row in response_a.json().get("surfaces", [])}
        routes_b = {row.get("route") for row in response_b.json().get("surfaces", [])}
        self.assertIn("/apps/hello-a", routes_a)
        self.assertNotIn("/apps/hello-b", routes_a)
        self.assertIn("/apps/hello-b", routes_b)
        self.assertNotIn("/apps/hello-a", routes_b)

    def test_nav_surfaces_include_legacy_surface_rows(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, user_identity=self.admin_identity, role="contributor")
        self._set_identity(self.admin_identity)
        module_type, _ = ArtifactType.objects.get_or_create(slug="module", defaults={"name": "Module"})
        artifact = Artifact.objects.create(
            workspace=self.workspace,
            type=module_type,
            title="Legacy Surface App",
            slug="legacy-surface-app",
            status="published",
            visibility="team",
        )
        WorkspaceArtifactBinding.objects.create(
            workspace=self.workspace,
            artifact=artifact,
            enabled=True,
            installed_state="installed",
        )
        ArtifactSurface.objects.create(
            artifact=artifact,
            key="legacy-nav",
            title="Legacy App",
            route="/apps/legacy-app",
            nav_visibility="always",
            nav_label="Legacy App",
            nav_group="build",
            renderer={"type": "ui_mount"},
            context={},
            permissions={},
            sort_order=200,
        )

        response = self.client.get(f"/xyn/api/artifact-surfaces/nav?workspace_id={self.workspace.id}")
        self.assertEqual(response.status_code, 200)
        routes = {row.get("route") for row in response.json().get("surfaces", [])}
        self.assertIn("/apps/legacy-app", routes)
