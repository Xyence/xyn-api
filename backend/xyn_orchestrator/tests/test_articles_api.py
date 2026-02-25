import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import (
    AgentDefinition,
    AgentDefinitionPurpose,
    AgentPurpose,
    Artifact,
    ArtifactEvent,
    ArtifactType,
    ArticleCategory,
    ContextPack,
    ModelConfig,
    ModelProvider,
    RoleBinding,
    UserIdentity,
    Workspace,
)
from xyn_orchestrator import xyn_api


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

    def _create_agent_for_purpose(self, purpose_slug: str, agent_slug: str, *, enabled: bool = True, is_default_for_purpose: bool = False):
        provider, _ = ModelProvider.objects.get_or_create(slug="openai", defaults={"name": "OpenAI", "enabled": True})
        model = ModelConfig.objects.create(provider=provider, model_name=f"gpt-{agent_slug}", enabled=True)
        purpose, _ = AgentPurpose.objects.get_or_create(
            slug=purpose_slug,
            defaults={
                "name": purpose_slug,
                "description": purpose_slug,
                "status": "active",
                "enabled": True,
            },
        )
        agent = AgentDefinition.objects.create(
            slug=agent_slug,
            name=agent_slug,
            model_config=model,
            system_prompt_text=f"Prompt for {agent_slug}",
            enabled=enabled,
        )
        if is_default_for_purpose:
            AgentDefinitionPurpose.objects.filter(purpose=purpose, is_default_for_purpose=True).update(is_default_for_purpose=False)
        AgentDefinitionPurpose.objects.create(
            agent_definition=agent,
            purpose=purpose,
            is_default_for_purpose=is_default_for_purpose,
        )
        return agent

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

    def test_delete_unreferenced_category_returns_204(self):
        self._set_identity(self.admin_identity)
        category = ArticleCategory.objects.create(slug="throwaway", name="Throwaway", enabled=True)
        delete = self.client.delete(f"/xyn/api/articles/categories/{category.slug}")
        self.assertEqual(delete.status_code, 204)
        self.assertFalse(ArticleCategory.objects.filter(slug="throwaway").exists())

    def test_patch_disable_referenced_category_succeeds_and_counts_exposed(self):
        self._set_identity(self.admin_identity)
        self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Guide One",
                    "slug": "guide-one",
                    "category": "guide",
                    "body_markdown": "content",
                }
            ),
            content_type="application/json",
        )
        patch = self.client.patch(
            "/xyn/api/articles/categories/guide",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
        )
        self.assertEqual(patch.status_code, 200, patch.content.decode())
        category = patch.json()["category"]
        self.assertFalse(category["enabled"])
        self.assertGreaterEqual(category["referenced_article_count"], 1)

        listing = self.client.get("/xyn/api/articles/categories")
        self.assertEqual(listing.status_code, 200)
        guide = next(item for item in listing.json()["categories"] if item["slug"] == "guide")
        self.assertIn("referenced_article_count", guide)

    def test_convert_html_to_markdown_creates_revision(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Legacy Html",
                    "slug": "legacy-html",
                    "category": "web",
                    "body_html": "<h1>Hello</h1><p>World</p>",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200, create.content.decode())
        article_id = create.json()["article"]["id"]
        convert = self.client.post(f"/xyn/api/articles/{article_id}/convert-html")
        self.assertEqual(convert.status_code, 200, convert.content.decode())
        payload = convert.json()
        self.assertTrue(payload.get("converted"))
        revision = payload["revision"]
        self.assertIn("# Hello", revision.get("body_markdown") or "")

    def test_video_initialize_creates_default_spec(self):
        self._set_identity(self.admin_identity)
        default_pack = ContextPack.objects.create(
            name="explainer-video-default",
            purpose="video_explainer",
            scope="global",
            namespace="",
            project_key="",
            version="1.0.0",
            is_active=True,
            is_default=True,
            content_markdown="default video context",
            applies_to_json={"purpose": "video_explainer", "artifact_type": "video_explainer"},
            created_by=self.staff,
            updated_by=self.staff,
        )
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Video Guide",
                    "slug": "video-guide-init",
                    "category": "guide",
                    "body_markdown": "seed content",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200, create.content.decode())
        article_id = create.json()["article"]["id"]

        initialize = self.client.post(f"/xyn/api/articles/{article_id}/video/initialize")
        self.assertEqual(initialize.status_code, 200, initialize.content.decode())
        payload = initialize.json()["article"]
        self.assertEqual(payload["format"], "video_explainer")
        self.assertIsInstance(payload.get("video_spec_json"), dict)
        self.assertEqual(payload["video_spec_json"].get("version"), 1)
        self.assertIn("script", payload["video_spec_json"])
        self.assertEqual(payload.get("video_context_pack_id"), str(default_pack.id))

    def test_generate_script_adds_proposal_without_overwriting_existing_draft(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Video Guide",
                    "slug": "video-guide-script",
                    "category": "guide",
                    "format": "video_explainer",
                    "video_spec_json": {
                        "version": 1,
                        "title": "Video Guide",
                        "intent": "Explain the feature",
                        "audience": "mixed",
                        "tone": "clear",
                        "duration_seconds_target": 120,
                        "voice": {"style": "conversational", "speaker": "neutral", "pace": "medium"},
                        "script": {"draft": "Human-authored draft", "last_generated_at": None, "notes": "", "proposals": []},
                        "storyboard": {"draft": [], "last_generated_at": None, "notes": "", "proposals": []},
                        "scenes": [],
                        "generation": {"provider": None, "status": "not_started", "last_render_id": None},
                    },
                    "body_markdown": "Base article",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200, create.content.decode())
        article_id = create.json()["article"]["id"]

        with patch("xyn_orchestrator.xyn_api._video_generate_text", return_value=("AI script proposal", {"agent_slug": "mock-agent"})):
            generated = self.client.post(
                f"/xyn/api/articles/{article_id}/video/generate-script",
                data=json.dumps({"agent_slug": "mock-agent"}),
                content_type="application/json",
            )
        self.assertEqual(generated.status_code, 200, generated.content.decode())
        payload = generated.json()
        self.assertFalse(payload.get("overwrote_draft"))
        self.assertEqual(payload["article"]["video_spec_json"]["script"]["draft"], "Human-authored draft")
        self.assertEqual(payload["article"]["video_spec_json"]["script"]["proposals"][0]["text"], "AI script proposal")

    def test_video_render_enqueue_and_process_transitions_state(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Video Guide",
                    "slug": "video-guide-render",
                    "category": "guide",
                    "format": "video_explainer",
                    "body_markdown": "Base article",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200, create.content.decode())
        article_id = create.json()["article"]["id"]

        with patch("xyn_orchestrator.xyn_api._async_mode", return_value="redis"), patch("xyn_orchestrator.xyn_api._enqueue_job") as enqueue_job:
            queued = self.client.post(
                f"/xyn/api/articles/{article_id}/video/renders",
                data=json.dumps({"provider": "stub"}),
                content_type="application/json",
            )
        self.assertEqual(queued.status_code, 200, queued.content.decode())
        render_payload = queued.json()["render"]
        self.assertEqual(render_payload["status"], "queued")
        enqueue_job.assert_called_once()

        render = xyn_api.VideoRender.objects.get(id=render_payload["id"])
        processed = xyn_api._process_video_render(render)
        processed.refresh_from_db()
        self.assertEqual(processed.status, "succeeded")
        self.assertTrue(isinstance(processed.output_assets, list) and len(processed.output_assets) >= 1)

    def test_video_generate_script_rejects_non_explainer_context_pack(self):
        self._set_identity(self.admin_identity)
        script_agent = self._create_agent_for_purpose("explainer_script", "script-agent")
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Video Guide",
                    "slug": "video-guide-pack-reject",
                    "category": "guide",
                    "format": "video_explainer",
                    "body_markdown": "Base article",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200, create.content.decode())
        article_id = create.json()["article"]["id"]
        non_video_pack = ContextPack.objects.create(
            name="Planner Pack",
            purpose="planner",
            scope="global",
            version="1.0.0",
            content_markdown="planner instructions",
        )
        response = self.client.post(
            f"/xyn/api/articles/{article_id}/video/generate-script",
            data=json.dumps({"agent_slug": script_agent.slug, "context_pack_id": str(non_video_pack.id)}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400, response.content.decode())
        self.assertIn("purpose", response.json().get("error", ""))

    def test_video_render_records_context_pack_id_and_hash(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Video Guide",
                    "slug": "video-guide-pack-hash",
                    "category": "guide",
                    "format": "video_explainer",
                    "body_markdown": "Base article",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200, create.content.decode())
        article_id = create.json()["article"]["id"]
        video_pack = ContextPack.objects.create(
            name="Explainer Pack",
            purpose="video_explainer",
            scope="global",
            version="1.0.0",
            content_markdown="Use concrete examples and plain language.",
        )
        with patch("xyn_orchestrator.xyn_api._async_mode", return_value="redis"), patch("xyn_orchestrator.xyn_api._enqueue_job"):
            queued = self.client.post(
                f"/xyn/api/articles/{article_id}/video/renders",
                data=json.dumps(
                    {
                        "provider": "stub",
                        "model_name": "video-model-a",
                        "context_pack_id": str(video_pack.id),
                        "request_payload_json": {"mode": "full_render"},
                    }
                ),
                content_type="application/json",
            )
        self.assertEqual(queued.status_code, 200, queued.content.decode())
        render = queued.json()["render"]
        self.assertEqual(render["context_pack_id"], str(video_pack.id))
        self.assertTrue(bool(render.get("context_pack_hash")))
        self.assertTrue(bool(render.get("spec_snapshot_hash")))
        self.assertTrue(bool(render.get("input_snapshot_hash")))
        self.assertEqual(render.get("model_name"), "video-model-a")
        self.assertEqual(
            (render.get("request_payload_json") or {}).get("context_pack", {}).get("id"),
            str(video_pack.id),
        )
        self.assertEqual(
            (render.get("request_payload_json") or {}).get("input_snapshot", {}).get("model_name"),
            "video-model-a",
        )

        with patch("xyn_orchestrator.xyn_api._async_mode", return_value="redis"), patch("xyn_orchestrator.xyn_api._enqueue_job"):
            queued_model_b = self.client.post(
                f"/xyn/api/articles/{article_id}/video/renders",
                data=json.dumps(
                    {
                        "provider": "stub",
                        "model_name": "video-model-b",
                        "context_pack_id": str(video_pack.id),
                        "request_payload_json": {"mode": "full_render"},
                    }
                ),
                content_type="application/json",
            )
        self.assertEqual(queued_model_b.status_code, 200, queued_model_b.content.decode())
        render_b = queued_model_b.json()["render"]
        self.assertEqual(render.get("context_pack_hash"), render_b.get("context_pack_hash"))
        self.assertTrue(bool(render_b.get("spec_snapshot_hash")))
        self.assertNotEqual(render.get("input_snapshot_hash"), render_b.get("input_snapshot_hash"))

    def test_video_ai_config_get_returns_effective_resolution(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Video Config",
                    "slug": "video-ai-config-get",
                    "category": "guide",
                    "format": "video_explainer",
                    "body_markdown": "Base article",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200, create.content.decode())
        article_id = create.json()["article"]["id"]

        script_agent = self._create_agent_for_purpose("explainer_script", "script-agent", is_default_for_purpose=True)
        pack = ContextPack.objects.create(
            name="Script Pack",
            purpose="explainer_script",
            scope="global",
            version="1.0.0",
            content_markdown="Script defaults",
            is_active=True,
        )
        purpose = AgentPurpose.objects.get(slug="explainer_script")
        purpose.default_context_pack_refs_json = [{"id": str(pack.id)}]
        purpose.save(update_fields=["default_context_pack_refs_json", "updated_at"])

        response = self.client.get(f"/xyn/api/articles/{article_id}/video/ai-config")
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()
        self.assertIn("effective", payload)
        self.assertEqual(payload["effective"]["explainer_script"]["agent"]["slug"], script_agent.slug)
        self.assertEqual(payload["effective"]["explainer_script"]["agent_source"], "purpose_default")
        self.assertEqual(payload["effective"]["explainer_script"]["context_source"], "purpose_default")

    def test_video_ai_config_put_validates_agent_link_and_context_pack_purpose(self):
        self._set_identity(self.admin_identity)
        create = self.client.post(
            "/xyn/api/articles",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Video Config",
                    "slug": "video-ai-config-put",
                    "category": "guide",
                    "format": "video_explainer",
                    "body_markdown": "Base article",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200, create.content.decode())
        article_id = create.json()["article"]["id"]

        storyboard_agent = self._create_agent_for_purpose("explainer_storyboard", "storyboard-agent")
        wrong_agent = self._create_agent_for_purpose("explainer_narration", "narration-agent")
        disabled_script_agent = self._create_agent_for_purpose("explainer_script", "disabled-script-agent", enabled=False)

        wrong_pack = ContextPack.objects.create(
            name="Wrong Pack",
            purpose="planner",
            scope="global",
            version="1.0.0",
            content_markdown="wrong purpose",
            is_active=True,
        )
        right_pack = ContextPack.objects.create(
            name="Storyboard Pack",
            purpose="explainer_storyboard",
            scope="global",
            version="1.0.0",
            content_markdown="storyboard purpose",
            is_active=True,
        )

        bad_agent_resp = self.client.put(
            f"/xyn/api/articles/{article_id}/video/ai-config",
            data=json.dumps({"agents": {"explainer_storyboard": wrong_agent.slug}}),
            content_type="application/json",
        )
        self.assertEqual(bad_agent_resp.status_code, 400, bad_agent_resp.content.decode())
        self.assertIn("not linked", bad_agent_resp.json().get("error", ""))

        disabled_agent_resp = self.client.put(
            f"/xyn/api/articles/{article_id}/video/ai-config",
            data=json.dumps({"agents": {"explainer_script": disabled_script_agent.slug}}),
            content_type="application/json",
        )
        self.assertEqual(disabled_agent_resp.status_code, 400, disabled_agent_resp.content.decode())
        self.assertIn("not found or disabled", disabled_agent_resp.json().get("error", ""))

        bad_pack_resp = self.client.put(
            f"/xyn/api/articles/{article_id}/video/ai-config",
            data=json.dumps({"context_packs": {"explainer_storyboard": [str(wrong_pack.id)]}}),
            content_type="application/json",
        )
        self.assertEqual(bad_pack_resp.status_code, 400, bad_pack_resp.content.decode())
        self.assertIn("does not match explainer_storyboard", bad_pack_resp.json().get("error", ""))

        ok_resp = self.client.put(
            f"/xyn/api/articles/{article_id}/video/ai-config",
            data=json.dumps(
                {
                    "agents": {"explainer_storyboard": storyboard_agent.slug},
                    "context_packs": {"explainer_storyboard": [str(right_pack.id)]},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(ok_resp.status_code, 200, ok_resp.content.decode())
        payload = ok_resp.json()
        self.assertEqual(payload["overrides"]["agents"]["explainer_storyboard"], storyboard_agent.slug)
        self.assertEqual(payload["effective"]["explainer_storyboard"]["agent"]["slug"], storyboard_agent.slug)
