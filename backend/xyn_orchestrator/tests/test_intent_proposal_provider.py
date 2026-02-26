import json
from unittest.mock import patch

from django.test import TestCase

from xyn_orchestrator.intent_engine.proposal_provider import (
    IntentContextPackMissingError,
    LlmIntentProposalProvider,
)
from xyn_orchestrator.models import ContextPack


class IntentProposalProviderTests(TestCase):
    def setUp(self):
        LlmIntentProposalProvider._context_cache = {"value": None, "expires_at": 0.0}

    def test_missing_context_pack_raises_and_skips_model_call(self):
        provider = LlmIntentProposalProvider()
        with patch("xyn_orchestrator.intent_engine.proposal_provider.invoke_model") as invoke_mock:
            with self.assertRaises(IntentContextPackMissingError):
                provider.propose(message="create draft")
            invoke_mock.assert_not_called()

    def test_prompt_uses_seeded_context_pack_content(self):
        ContextPack.objects.create(
            name="xyn-console-default",
            purpose="any",
            scope="global",
            namespace="",
            project_key="",
            version="1.0.0",
            is_active=True,
            is_default=True,
            content_markdown='{"policy":"seeded-console-policy"}',
            applies_to_json={},
        )
        provider = LlmIntentProposalProvider()
        captured = {}

        def _fake_invoke(*, resolved_config, messages):
            captured["messages"] = messages
            return {
                "content": json.dumps(
                    {
                        "action_type": "CreateDraft",
                        "artifact_type": "ArticleDraft",
                        "inferred_fields": {"format": "explainer_video"},
                        "confidence": 0.91,
                    }
                ),
                "model": "fake-model",
            }

        with patch("xyn_orchestrator.intent_engine.proposal_provider.resolve_ai_config", return_value={"model_name": "fake-model"}):
            with patch("xyn_orchestrator.intent_engine.proposal_provider.invoke_model", side_effect=_fake_invoke):
                result = provider.propose(message="create explainer video")

        messages = captured.get("messages") or []
        developer_message = next((msg for msg in messages if isinstance(msg, dict) and msg.get("role") == "developer"), {})
        self.assertIn("seeded-console-policy", str(developer_message.get("content") or ""))
        self.assertEqual(result.get("_context_pack_slug"), "xyn-console-default")
        self.assertTrue(str(result.get("_context_pack_hash") or "").strip())
