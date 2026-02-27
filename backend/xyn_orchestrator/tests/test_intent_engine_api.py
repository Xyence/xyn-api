import json
import os
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.intent_engine.contracts import DraftIntakeContractRegistry
from xyn_orchestrator.intent_engine.engine import IntentResolutionEngine, ResolutionContext
from xyn_orchestrator.intent_engine.proposal_provider import IntentContextPackMissingError
from xyn_orchestrator.artifact_links import ensure_context_pack_artifact
from xyn_orchestrator.models import Artifact, ArticleCategory, ContextPack, LedgerEvent, RoleBinding, UserIdentity, Workspace


class _FakeProvider:
    def __init__(self, proposal):
        self.proposal = proposal

    def propose(self, **_kwargs):
        return dict(self.proposal)


class IntentEngineApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username="intent-admin", password="pass", is_staff=True)
        self.client.force_login(self.user)
        self.identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="intent-admin",
            email="intent-admin@example.com",
        )
        RoleBinding.objects.create(user_identity=self.identity, scope_kind="platform", role="platform_admin")
        self.workspace, _ = Workspace.objects.get_or_create(slug="platform-builder", defaults={"name": "Platform Builder"})
        session = self.client.session
        session["user_identity_id"] = str(self.identity.id)
        session.save()
        os.environ["XYN_INTENT_ENGINE_V1"] = "1"

    def tearDown(self):
        os.environ.pop("XYN_INTENT_ENGINE_V1", None)

    def test_contract_no_longer_requires_intent_for_explainer_video(self):
        registry = DraftIntakeContractRegistry(category_options_provider=lambda: [{"slug": "web", "name": "Web"}])
        contract = registry.get("ArticleDraft")
        self.assertIsNotNone(contract)
        assert contract is not None
        merged = contract.merge_defaults({"title": "x", "category": "web", "format": "explainer_video"})
        self.assertNotIn("intent", contract.missing_fields(merged))

    def test_contract_infers_explicit_fields_from_message(self):
        registry = DraftIntakeContractRegistry(category_options_provider=lambda: [{"slug": "demo", "name": "Demo"}])
        contract = registry.get("ArticleDraft")
        self.assertIsNotNone(contract)
        assert contract is not None
        inferred = contract.infer_fields(
            message='Intent: Create an explainer video about Xyn governance ledger for telecom engineers. title: "What I Did On My Summer Vacation". category: demo',
            inferred_fields={},
        )
        self.assertEqual(inferred.get("format"), "explainer_video")
        self.assertEqual(inferred.get("title"), "What I Did On My Summer Vacation")
        self.assertEqual(inferred.get("category"), "demo")
        self.assertTrue(str(inferred.get("intent") or "").lower().startswith("create an explainer video"))

    def test_contract_infers_category_from_natural_phrase(self):
        registry = DraftIntakeContractRegistry(category_options_provider=lambda: [{"slug": "demo", "name": "Demo"}])
        contract = registry.get("ArticleDraft")
        self.assertIsNotNone(contract)
        assert contract is not None
        inferred = contract.infer_fields(
            message='Create an explainer video about Xyn governance ledger for telecom engineers. The title is "What I Did On My Summer Vacation". Create it in the demo category.',
            inferred_fields={},
        )
        self.assertEqual(inferred.get("category"), "demo")

    def test_contract_infers_title_from_title_it_phrase(self):
        registry = DraftIntakeContractRegistry(category_options_provider=lambda: [{"slug": "demo", "name": "Demo"}])
        contract = registry.get("ArticleDraft")
        self.assertIsNotNone(contract)
        assert contract is not None
        inferred = contract.infer_fields(
            message=(
                "Create an explainer video about turtles. Make it scientific. "
                "Title it 'Adult Non-mutant Tai-Chi Turtles' and put it in the demo category."
            ),
            inferred_fields={},
        )
        self.assertEqual(inferred.get("title"), "Adult Non-mutant Tai-Chi Turtles")

    def test_context_pack_contract_defaults(self):
        registry = DraftIntakeContractRegistry(category_options_provider=lambda: [{"slug": "demo", "name": "Demo"}])
        contract = registry.get("ContextPack")
        self.assertIsNotNone(contract)
        assert contract is not None
        merged = contract.merge_defaults({"title": "Pack", "content": "{}"})
        self.assertEqual(merged.get("format"), "json")
        self.assertEqual(contract.missing_fields(merged), [])

    def test_engine_rejects_unknown_action_type(self):
        registry = DraftIntakeContractRegistry(category_options_provider=lambda: [{"slug": "web", "name": "Web"}])
        engine = IntentResolutionEngine(
            proposal_provider=_FakeProvider(
                {
                    "action_type": "DoSomethingElse",
                    "artifact_type": "ArticleDraft",
                    "inferred_fields": {},
                    "confidence": 0.9,
                }
            ),
            contracts=registry,
        )
        result, _ = engine.resolve(message="hello", context=ResolutionContext(artifact=None))
        self.assertEqual(result["status"], "UnsupportedIntent")

    def test_resolve_create_returns_missing_fields_when_incomplete(self):
        with patch(
            "xyn_orchestrator.intent_engine.proposal_provider.LlmIntentProposalProvider.propose",
            return_value={
                "action_type": "CreateDraft",
                "artifact_type": "ArticleDraft",
                "inferred_fields": {"title": "Draft title"},
                "confidence": 0.93,
                "_model": "fake",
                "_context_pack_slug": "xyn-console-default",
                "_context_pack_version": "1.0.0",
                "_context_pack_hash": "abc123",
            },
        ):
            response = self.client.post(
                "/xyn/api/xyn/intent/resolve",
                data=json.dumps({"message": "create draft"}),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()
        self.assertEqual(payload["status"], "MissingFields")
        self.assertTrue(any(item["field"] == "category" for item in payload.get("missing_fields", [])))
        self.assertEqual((payload.get("audit") or {}).get("context_pack_slug"), "xyn-console-default")

    def test_resolve_heuristic_create_fallback_for_low_confidence(self):
        with patch(
            "xyn_orchestrator.intent_engine.proposal_provider.LlmIntentProposalProvider.propose",
            return_value={
                "action_type": "ValidateDraft",
                "artifact_type": "ArticleDraft",
                "inferred_fields": {},
                "confidence": 0.01,
                "_model": "fake",
            },
        ):
            response = self.client.post(
                "/xyn/api/xyn/intent/resolve",
                data=json.dumps({"message": "Create an explainer video about governance ledger for telecom engineers."}),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()
        self.assertEqual(payload["status"], "MissingFields")
        self.assertEqual(payload["action_type"], "CreateDraft")
        self.assertEqual(payload["artifact_type"], "ArticleDraft")
        self.assertNotEqual(payload["summary"], "Intent is ambiguous; provide clearer draft instructions.")

    def test_resolve_low_confidence_with_explicit_fields_returns_draft_ready(self):
        with patch(
            "xyn_orchestrator.intent_engine.proposal_provider.LlmIntentProposalProvider.propose",
            return_value={
                "action_type": "ValidateDraft",
                "artifact_type": "ArticleDraft",
                "inferred_fields": {},
                "confidence": 0.1,
                "_model": "fake",
            },
        ):
            response = self.client.post(
                "/xyn/api/xyn/intent/resolve",
                data=json.dumps(
                    {
                        "message": 'Intent: Create an explainer video about Xyn governance ledger for telecom engineers. title: "What I Did On My Summer Vacation". category: demo'
                    }
                ),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()
        self.assertEqual(payload["status"], "DraftReady")
        self.assertEqual((payload.get("draft_payload") or {}).get("category"), "demo")
        self.assertEqual((payload.get("draft_payload") or {}).get("title"), "What I Did On My Summer Vacation")

    def test_resolve_returns_explicit_error_when_console_context_pack_missing(self):
        with patch(
            "xyn_orchestrator.intent_engine.proposal_provider.LlmIntentProposalProvider.propose",
            side_effect=IntentContextPackMissingError("xyn-console-default"),
        ):
            response = self.client.post(
                "/xyn/api/xyn/intent/resolve",
                data=json.dumps({"message": "create an explainer video"}),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()
        self.assertEqual(payload.get("status"), "UnsupportedIntent")
        self.assertIn("context pack missing", str(payload.get("summary") or "").lower())

    def test_apply_patch_rejects_unauthorized_fields(self):
        create_response = self.client.post(
            "/xyn/api/xyn/intent/apply",
            data=json.dumps(
                {
                    "action_type": "CreateDraft",
                    "artifact_type": "ArticleDraft",
                    "payload": {
                        "title": "Patch Target",
                        "category": "web",
                        "format": "article",
                    },
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create_response.status_code, 200, create_response.content.decode())
        artifact_id = create_response.json().get("artifact_id")

        patch_response = self.client.post(
            "/xyn/api/xyn/intent/apply",
            data=json.dumps(
                {
                    "action_type": "ApplyPatch",
                    "artifact_type": "ArticleDraft",
                    "artifact_id": artifact_id,
                    "payload": {"evil_field": "value"},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(patch_response.status_code, 400)
        self.assertEqual(patch_response.json().get("status"), "ValidationError")

    def test_context_pack_apply_patch_validates_and_writes_ledger(self):
        pack = ContextPack.objects.create(
            name="xyn-console-default",
            purpose="any",
            scope="global",
            version="1.0.0",
            is_active=True,
            content_markdown='{"hello":"world"}',
            applies_to_json={"content_format": "json"},
        )
        artifact = ensure_context_pack_artifact(pack, owner_user=self.user)
        bad = self.client.post(
            "/xyn/api/xyn/intent/apply",
            data=json.dumps(
                {
                    "action_type": "ApplyPatch",
                    "artifact_type": "ContextPack",
                    "artifact_id": str(artifact.id),
                    "payload": {"content": "{invalid json}", "format": "json"},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(bad.status_code, 400, bad.content.decode())
        self.assertEqual(bad.json().get("status"), "ValidationError")

        ok = self.client.post(
            "/xyn/api/xyn/intent/apply",
            data=json.dumps(
                {
                    "action_type": "ApplyPatch",
                    "artifact_type": "ContextPack",
                    "artifact_id": str(artifact.id),
                    "payload": {"title": "xyn-console-default", "content": '{"hello":"xyn"}', "format": "json"},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(ok.status_code, 200, ok.content.decode())
        artifact.refresh_from_db()
        pack.refresh_from_db()
        self.assertEqual(pack.content_markdown, '{"hello":"xyn"}')
        self.assertTrue(LedgerEvent.objects.filter(artifact=artifact, action="contextpack.patched").exists())

    def test_resolve_context_pack_with_context(self):
        pack = ContextPack.objects.create(
            name="xyn-console-default",
            purpose="any",
            scope="global",
            version="1.0.0",
            is_active=True,
            content_markdown='{"hello":"world"}',
            applies_to_json={"content_format": "json"},
        )
        artifact = ensure_context_pack_artifact(pack, owner_user=self.user)
        with patch(
            "xyn_orchestrator.intent_engine.proposal_provider.LlmIntentProposalProvider.propose",
            return_value={
                "action_type": "ProposePatch",
                "artifact_type": "ContextPack",
                "inferred_fields": {"content": '{"hello":"patched"}', "format": "json"},
                "confidence": 0.95,
                "_model": "fake",
            },
        ):
            response = self.client.post(
                "/xyn/api/xyn/intent/resolve",
                data=json.dumps(
                    {
                        "message": "Update context pack content",
                        "context": {"artifact_id": str(artifact.id), "artifact_type": "ContextPack"},
                    }
                ),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()
        self.assertEqual(payload.get("status"), "ProposedPatch")
        self.assertEqual(payload.get("artifact_type"), "ContextPack")

    def test_show_options_returns_categories_and_formats(self):
        options = self.client.get("/xyn/api/xyn/intent/options?artifact_type=ArticleDraft&field=format")
        self.assertEqual(options.status_code, 200)
        self.assertIn("explainer_video", options.json().get("options", []))

        categories = self.client.get("/xyn/api/xyn/intent/options?artifact_type=ArticleDraft&field=category")
        self.assertEqual(categories.status_code, 200)
        self.assertTrue(categories.json().get("options"))

    def test_create_and_patch_write_ledger_events(self):
        create_response = self.client.post(
            "/xyn/api/xyn/intent/apply",
            data=json.dumps(
                {
                    "action_type": "CreateDraft",
                    "artifact_type": "ArticleDraft",
                    "payload": {
                        "title": "Ledger Draft",
                        "category": "web",
                        "format": "article",
                        "summary": "initial",
                    },
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create_response.status_code, 200, create_response.content.decode())
        artifact_id = create_response.json().get("artifact_id")
        artifact = Artifact.objects.get(id=artifact_id)

        self.assertTrue(LedgerEvent.objects.filter(artifact=artifact, action="draft.created").exists())

        patch_response = self.client.post(
            "/xyn/api/xyn/intent/apply",
            data=json.dumps(
                {
                    "action_type": "ApplyPatch",
                    "artifact_type": "ArticleDraft",
                    "artifact_id": artifact_id,
                    "payload": {"summary": "updated summary"},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(patch_response.status_code, 200, patch_response.content.decode())
        self.assertTrue(LedgerEvent.objects.filter(artifact=artifact, action="draft.patched").exists())

    def test_resolve_and_apply_integration(self):
        with patch(
            "xyn_orchestrator.intent_engine.proposal_provider.LlmIntentProposalProvider.propose",
            return_value={
                "action_type": "CreateDraft",
                "artifact_type": "ArticleDraft",
                "inferred_fields": {
                    "title": "Intent Generated Draft",
                    "category": "web",
                    "format": "explainer_video",
                    "intent": "Explain Xyn governance quickly",
                    "duration": "5m",
                },
                "confidence": 0.95,
                "_model": "fake",
            },
        ):
            resolve_response = self.client.post(
                "/xyn/api/xyn/intent/resolve",
                data=json.dumps({"message": "Create an explainer video draft"}),
                content_type="application/json",
            )
        self.assertEqual(resolve_response.status_code, 200, resolve_response.content.decode())
        resolve_payload = resolve_response.json()
        self.assertEqual(resolve_payload.get("status"), "DraftReady")
        self.assertTrue(resolve_payload.get("draft_payload"))

        apply_response = self.client.post(
            "/xyn/api/xyn/intent/apply",
            data=json.dumps(
                {
                    "action_type": "CreateDraft",
                    "artifact_type": "ArticleDraft",
                    "payload": resolve_payload.get("draft_payload") or {},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(apply_response.status_code, 200, apply_response.content.decode())
        created = Artifact.objects.get(id=apply_response.json().get("artifact_id"))
        self.assertEqual(created.format, "video_explainer")
        self.assertEqual((created.video_spec_json or {}).get("intent"), "Explain Xyn governance quickly")
        scenes = (created.video_spec_json or {}).get("scenes") if isinstance(created.video_spec_json, dict) else []
        self.assertTrue(isinstance(scenes, list) and len(scenes) >= 3)
        latest = created.revisions.order_by("-revision_number").first()
        content = latest.content_json if latest and isinstance(latest.content_json, dict) else {}
        self.assertTrue(str(content.get("summary") or "").strip())
        self.assertTrue(str(content.get("body_markdown") or "").strip())
        serialized_scenes = json.dumps(scenes).lower()
        self.assertNotIn("/app/artifacts", serialized_scenes)
        self.assertNotIn("validation", serialized_scenes)
        self.assertNotIn("content_hash", serialized_scenes)

    def test_create_explainer_uses_structured_topic_and_auto_binds_default_pack(self):
        ArticleCategory.objects.get_or_create(slug="demo", defaults={"name": "Demo", "enabled": True})
        default_pack, _ = ContextPack.objects.get_or_create(
            name="explainer-video-default",
            purpose="video_explainer",
            scope="global",
            version="1.0.0",
            namespace="",
            project_key="",
            defaults={
                "is_active": True,
                "is_default": False,
                "content_markdown": "Ground scenes in factual biology.",
            },
        )
        if not default_pack.is_active:
            default_pack.is_active = True
            default_pack.save(update_fields=["is_active", "updated_at"])
        response = self.client.post(
            "/xyn/api/xyn/intent/apply",
            data=json.dumps(
                {
                    "action_type": "CreateDraft",
                    "artifact_type": "ArticleDraft",
                    "payload": {
                        "title": "The Intrigue of Salamanders",
                        "category": "demo",
                        "format": "explainer_video",
                        "intent": (
                            "Create an explainer video about salamanders. Ground it in actual biology. "
                            "The title is 'The Intrigue of Salamanders'. Create it in the demo category."
                        ),
                    },
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        artifact = Artifact.objects.get(id=response.json().get("artifact_id"))
        self.assertEqual(str(artifact.video_context_pack_id), str(default_pack.id))
        latest = artifact.revisions.order_by("-revision_number").first()
        content = latest.content_json if latest and isinstance(latest.content_json, dict) else {}
        summary = str(content.get("summary") or "").lower()
        body = str(content.get("body_markdown") or "").lower()
        self.assertIn("salamander", summary)
        self.assertIn("salamander", body)
        self.assertNotIn("create an explainer video", summary)
        self.assertNotIn("create an explainer video", body)
        scenes = (artifact.video_spec_json or {}).get("scenes") if isinstance(artifact.video_spec_json, dict) else []
        self.assertTrue(isinstance(scenes, list) and len(scenes) >= 3)
        scene_blob = json.dumps(scenes).lower()
        self.assertIn("regener", scene_blob)
        self.assertIn("amphib", scene_blob)
        self.assertNotIn("hook / premise", scene_blob)
        self.assertNotIn("setup / context", scene_blob)
