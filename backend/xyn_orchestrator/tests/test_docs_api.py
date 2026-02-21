import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import (
    AgentDefinition,
    AgentDefinitionPurpose,
    AgentPurpose,
    Artifact,
    ArtifactType,
    ModelConfig,
    ModelProvider,
    RoleBinding,
    UserIdentity,
    Workspace,
)


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
        self.architect_identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="docs-architect", email="docs-architect@example.com"
        )
        RoleBinding.objects.create(user_identity=self.admin_identity, scope_kind="platform", role="platform_admin")
        RoleBinding.objects.create(user_identity=self.reader_identity, scope_kind="platform", role="app_user")
        RoleBinding.objects.create(user_identity=self.architect_identity, scope_kind="platform", role="platform_architect")

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

    def test_non_admin_cannot_create_purpose(self):
        self._set_identity(self.reader_identity)
        response = self.client.post(
            "/xyn/api/ai/purposes",
            data=json.dumps({"slug": "ops", "name": "Ops", "enabled": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

    def test_architect_can_create_update_and_delete_unreferenced_purpose(self):
        self._set_identity(self.architect_identity)
        create = self.client.post(
            "/xyn/api/ai/purposes",
            data=json.dumps(
                {
                    "slug": "analysis",
                    "name": "Analysis",
                    "enabled": True,
                    "preamble": "Analyze data and summarize outcomes.",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        self.assertEqual(create.json()["purpose"]["slug"], "analysis")
        self.assertEqual(create.json()["purpose"]["referenced_by"]["agents"], 0)

        update = self.client.patch(
            "/xyn/api/ai/purposes/analysis",
            data=json.dumps({"enabled": False, "slug": "analysis"}),
            content_type="application/json",
        )
        self.assertEqual(update.status_code, 200)
        self.assertFalse(update.json()["purpose"]["enabled"])

        delete = self.client.delete("/xyn/api/ai/purposes/analysis")
        self.assertEqual(delete.status_code, 204)
        self.assertFalse(AgentPurpose.objects.filter(slug="analysis").exists())

    def test_delete_referenced_purpose_returns_conflict(self):
        self._set_identity(self.admin_identity)
        provider, _ = ModelProvider.objects.get_or_create(slug="openai", defaults={"name": "OpenAI", "enabled": True})
        config = ModelConfig.objects.create(provider=provider, model_name="gpt-4o-mini")
        purpose = AgentPurpose.objects.get(slug="documentation")
        agent = AgentDefinition.objects.create(
            slug="docs-purpose-test",
            name="Docs Purpose Test",
            model_config=config,
            system_prompt_text="test",
            enabled=True,
        )
        AgentDefinitionPurpose.objects.create(agent_definition=agent, purpose=purpose)

        response = self.client.delete("/xyn/api/ai/purposes/documentation")
        self.assertEqual(response.status_code, 409)
        payload = response.json()
        self.assertEqual(payload["error"], "purpose_in_use")
        self.assertEqual(payload["referenced_by"]["agents"], 1)
        self.assertTrue(AgentPurpose.objects.filter(slug="documentation").exists())

    def test_disabling_referenced_purpose_keeps_agent_association(self):
        self._set_identity(self.admin_identity)
        provider, _ = ModelProvider.objects.get_or_create(slug="openai", defaults={"name": "OpenAI", "enabled": True})
        config = ModelConfig.objects.create(provider=provider, model_name="gpt-4o-mini")
        purpose = AgentPurpose.objects.get(slug="documentation")
        agent = AgentDefinition.objects.create(
            slug="docs-purpose-disable-test",
            name="Docs Purpose Disable Test",
            model_config=config,
            system_prompt_text="test",
            enabled=True,
        )
        AgentDefinitionPurpose.objects.create(agent_definition=agent, purpose=purpose)

        response = self.client.patch(
            "/xyn/api/ai/purposes/documentation",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AgentPurpose.objects.get(slug="documentation").enabled)
        self.assertTrue(
            AgentDefinitionPurpose.objects.filter(agent_definition=agent, purpose__slug="documentation").exists()
        )

    def test_slug_is_immutable(self):
        self._set_identity(self.admin_identity)
        response = self.client.patch(
            "/xyn/api/ai/purposes/documentation",
            data=json.dumps({"slug": "docs-renamed"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("immutable", response.json().get("error", "").lower())

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
