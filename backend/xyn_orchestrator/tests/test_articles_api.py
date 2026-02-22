import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import Artifact, ArtifactEvent, ArtifactType, ArticleCategory, RoleBinding, UserIdentity, Workspace


class GovernedArticlesApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(username="staff", email="staff@example.com", password="pass", is_staff=True)
        self.client.force_login(self.staff)
        self.admin_identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer", subject="admin", email="admin@example.com")
        self.reader_identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer", subject="reader", email="reader@example.com")
        RoleBinding.objects.create(user_identity=self.admin_identity, scope_kind="platform", role="platform_admin")
        RoleBinding.objects.create(user_identity=self.reader_identity, scope_kind="platform", role="app_user")
        self.workspace, _ = Workspace.objects.get_or_create(slug="platform-builder", defaults={"name": "Platform Builder"})
        self.article_type, _ = ArtifactType.objects.get_or_create(slug="article", defaults={"name": "Article"})

    def _set_identity(self, identity: UserIdentity):
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()

    def test_admin_can_create_article_and_revision(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Core Concepts",
                    "slug": f"core-concepts-{self.admin_identity.id}",
                    "category": "core-concepts",
                    "visibility_type": "authenticated",
                    "route_bindings": ["/app/guides"],
                    "tags": ["guide", "core-concepts"],
                    "body_markdown": "# Intro",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200, create.content.decode())
        article_id = create.json()["article"]["id"]
        article = Artifact.objects.get(id=article_id)
        self.assertEqual(article.type.slug, "article")
        self.assertEqual(article.status, "draft")

        revision = self.client.post(
            f"/xyn/api/articles/{article_id}/revisions",
            data=json.dumps({"body_markdown": "# Intro\n\nUpdated", "summary": "Summary 1"}),
            content_type="application/json",
        )
        self.assertEqual(revision.status_code, 200)
        article.refresh_from_db()
        self.assertEqual(article.version, 2)
        self.assertTrue(ArtifactEvent.objects.filter(artifact=article, event_type="article_revision_created").exists())

    def test_publish_transition_is_logged(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps({"workspace_id": str(self.workspace.id), "title": "Web Article", "slug": "web-article", "category": "web"}),
            content_type="application/json",
        )
        article_id = create.json()["article"]["id"]
        publish = self.client.post(
            f"/xyn/api/articles/{article_id}/transition",
            data=json.dumps({"to_status": "published"}),
            content_type="application/json",
        )
        self.assertEqual(publish.status_code, 200)
        body = publish.json()["article"]
        self.assertEqual(body["status"], "published")
        self.assertTrue(
            ArtifactEvent.objects.filter(artifact_id=article_id, event_type="article_published").exists()
        )

    def test_role_based_visibility_filters_reader_access(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Internal Guide",
                    "slug": "internal-guide",
                    "category": "guide",
                    "visibility_type": "role_based",
                    "allowed_roles": ["platform_operator"],
                    "status": "published",
                    "body_markdown": "content",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)

        self._set_identity(self.reader_identity)
        listing = self.client.get("/xyn/api/articles?category=guide")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["articles"], [])

    def test_docs_by_route_resolves_article_guides(self):
        self._set_identity(self.admin_identity)
        self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Drafts Guide",
                    "slug": "drafts-guide",
                    "category": "guide",
                    "visibility_type": "authenticated",
                    "status": "published",
                    "route_bindings": ["/app/drafts"],
                    "body_markdown": "Help content",
                }
            ),
            content_type="application/json",
        )

        self._set_identity(self.reader_identity)
        response = self.client.get("/xyn/api/docs/by-route?route_id=/app/drafts")
        self.assertEqual(response.status_code, 200)
        payload = response.json()["doc"]
        self.assertEqual(payload["slug"], "drafts-guide")
        self.assertEqual(payload["title"], "Drafts Guide")

    def test_article_detail_includes_published_to_bindings(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Guide Article",
                    "slug": "guide-article",
                    "category": "guide",
                    "status": "published",
                    "body_markdown": "content",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200, create.content.decode())
        article_id = create.json()["article"]["id"]
        detail = self.client.get(f"/xyn/api/articles/{article_id}")
        self.assertEqual(detail.status_code, 200)
        published_to = detail.json()["article"].get("published_to") or []
        self.assertTrue(any(item.get("target_value") == "/app/guides" and item.get("source") == "category" for item in published_to))

    def test_category_delete_conflict_when_referenced(self):
        self._set_identity(self.admin_identity)
        category = ArticleCategory.objects.create(slug="playbook", name="Playbook", enabled=True)
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Playbook One",
                    "slug": "playbook-one",
                    "category": "playbook",
                    "body_markdown": "content",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200, create.content.decode())
        delete = self.client.delete(f"/xyn/api/articles/categories/{category.slug}")
        self.assertEqual(delete.status_code, 409)
        payload = delete.json()
        self.assertEqual(payload.get("error"), "category_in_use")
