import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import (
    Artifact,
    ArtifactComment,
    ArtifactEvent,
    ArtifactType,
    UserIdentity,
    Workspace,
    WorkspaceMembership,
)


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
