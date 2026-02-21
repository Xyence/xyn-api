import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import AgentPurpose, Artifact, ArtifactType, RoleBinding, UserIdentity, Workspace


class DocsApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(username="staff-docs", password="pass", is_staff=True)
        self.client.force_login(self.staff)

        self.admin_identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="docs-admin", email="docs-admin@example.com"
        )
        self.reader_identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="docs-reader", email="docs-reader@example.com"
        )
        RoleBinding.objects.create(user_identity=self.admin_identity, scope_kind="platform", role="platform_admin")
        RoleBinding.objects.create(user_identity=self.reader_identity, scope_kind="platform", role="app_user")

        Workspace.objects.get_or_create(slug="platform-builder", defaults={"name": "Platform Builder"})
        ArtifactType.objects.get_or_create(slug="doc_page", defaults={"name": "Doc Page"})

    def _set_identity(self, identity: UserIdentity):
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()

    def test_admin_can_create_publish_and_lookup_doc_by_route(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/docs",
            data=json.dumps(
                {
                    "title": "Blueprints Guide",
                    "slug": "blueprints-guide",
                    "body_markdown": "How to use blueprints",
                    "route_bindings": ["app.blueprints"],
                    "tags": ["guide"],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        doc_id = create.json()["doc"]["id"]

        publish = self.client.post(f"/xyn/api/docs/{doc_id}/publish")
        self.assertEqual(publish.status_code, 200)
        self.assertEqual(publish.json()["doc"]["status"], "published")

        self._set_identity(self.reader_identity)
        by_route = self.client.get("/xyn/api/docs/by-route?route_id=app.blueprints")
        self.assertEqual(by_route.status_code, 200)
        self.assertEqual(by_route.json()["doc"]["slug"], "blueprints-guide")

    def test_reader_cannot_create_doc(self):
        self._set_identity(self.reader_identity)
        response = self.client.post(
            "/xyn/api/docs",
            data=json.dumps(
                {
                    "title": "No Access",
                    "slug": "no-access",
                    "body_markdown": "x",
                    "route_bindings": ["app.home"],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

    def test_lookup_by_route_returns_null_when_not_found(self):
        self._set_identity(self.reader_identity)
        response = self.client.get("/xyn/api/docs/by-route?route_id=app.missing")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json()["doc"])

    def test_ai_purposes_read_and_admin_update(self):
        self._set_identity(self.reader_identity)
        list_response = self.client.get("/xyn/api/ai/purposes")
        self.assertEqual(list_response.status_code, 200)
        purposes = list_response.json()["purposes"]
        self.assertTrue(any(item["slug"] == "documentation" for item in purposes))
        self.assertIn("preamble", purposes[0])
        self.assertNotIn("system_prompt_markdown", purposes[0])

        update_forbidden = self.client.put(
            "/xyn/api/ai/purposes/documentation",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
        )
        self.assertEqual(update_forbidden.status_code, 403)

        self._set_identity(self.admin_identity)
        update_ok = self.client.put(
            "/xyn/api/ai/purposes/documentation",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
        )
        self.assertEqual(update_ok.status_code, 200)
        self.assertFalse(update_ok.json()["purpose"]["enabled"])
        self.assertFalse(AgentPurpose.objects.get(slug="documentation").enabled)

        update_preamble = self.client.patch(
            "/xyn/api/ai/purposes/documentation",
            data=json.dumps({"preamble": "Docs purpose preamble"}),
            content_type="application/json",
        )
        self.assertEqual(update_preamble.status_code, 200)
        self.assertEqual(update_preamble.json()["purpose"]["preamble"], "Docs purpose preamble")
        self.assertEqual(AgentPurpose.objects.get(slug="documentation").preamble, "Docs purpose preamble")

        compat_update = self.client.patch(
            "/xyn/api/ai/purposes/documentation",
            data=json.dumps({"system_prompt": "Compat preamble"}),
            content_type="application/json",
        )
        self.assertEqual(compat_update.status_code, 200)
        self.assertEqual(compat_update.json()["purpose"]["preamble"], "Compat preamble")

    def test_docs_slug_lookup_requires_published_for_reader(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/docs",
            data=json.dumps(
                {
                    "title": "Draft Only",
                    "slug": "draft-only",
                    "body_markdown": "draft content",
                    "route_bindings": ["app.home"],
                    "visibility": "team",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        artifact_id = create.json()["doc"]["id"]
        artifact = Artifact.objects.get(id=artifact_id)
        self.assertEqual(artifact.status, "draft")

        self._set_identity(self.reader_identity)
        response = self.client.get("/xyn/api/docs/slug/draft-only")
        self.assertEqual(response.status_code, 403)
