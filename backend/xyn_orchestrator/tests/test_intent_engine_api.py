import json
import os
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.intent_engine.contracts import DraftIntakeContractRegistry
from xyn_orchestrator.intent_engine.engine import IntentResolutionEngine, ResolutionContext
from xyn_orchestrator.models import Artifact, LedgerEvent, RoleBinding, UserIdentity, Workspace


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

    def test_contract_requires_intent_for_explainer_video(self):
        registry = DraftIntakeContractRegistry(category_options_provider=lambda: [{"slug": "web", "name": "Web"}])
        contract = registry.get("ArticleDraft")
        self.assertIsNotNone(contract)
        assert contract is not None
        merged = contract.merge_defaults({"title": "x", "category": "web", "format": "explainer_video"})
        self.assertIn("intent", contract.missing_fields(merged))

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
