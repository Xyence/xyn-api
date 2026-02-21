import os
from unittest.mock import Mock, patch

from django.test import TestCase

from xyn_orchestrator.ai_runtime import (
    _extract_openai_response_text,
    assemble_system_prompt,
    ensure_default_ai_seeds,
    invoke_model,
    resolve_ai_config,
)
from xyn_orchestrator.models import AgentDefinition, AgentDefinitionPurpose, AgentPurpose, ModelConfig, ModelProvider, ProviderCredential


class AiRuntimeTests(TestCase):
    def test_assemble_system_prompt_preamble_only(self):
        self.assertEqual(assemble_system_prompt("", "Purpose preamble"), "Purpose preamble")

    def test_assemble_system_prompt_agent_only(self):
        self.assertEqual(assemble_system_prompt("Agent prompt", ""), "Agent prompt")

    def test_assemble_system_prompt_both(self):
        self.assertEqual(
            assemble_system_prompt("Agent prompt", "Purpose preamble"),
            "Purpose preamble\n\nAgent prompt",
        )

    def test_assemble_system_prompt_neither(self):
        self.assertEqual(assemble_system_prompt("", ""), "")

    def test_bootstrap_removes_legacy_documentation_default_agent(self):
        provider, _ = ModelProvider.objects.get_or_create(slug="openai", defaults={"name": "OpenAI", "enabled": True})
        legacy, _ = AgentDefinition.objects.get_or_create(
            slug="documentation-default",
            defaults={
                "name": "Documentation Default",
                "model_config": provider.model_configs.create(model_name="gpt-4o-mini"),
                "enabled": True,
            },
        )
        legacy.name = "Documentation Default"
        legacy.enabled = True
        legacy.save(update_fields=["name", "enabled", "updated_at"])
        ensure_default_ai_seeds()
        self.assertFalse(AgentDefinition.objects.filter(slug="documentation-default").exists())
        default_assistant = AgentDefinition.objects.get(slug="default-assistant")
        self.assertEqual(default_assistant.name, "Xyn Default Assistant")
        self.assertTrue(default_assistant.purposes.filter(slug="coding").exists())
        self.assertTrue(default_assistant.purposes.filter(slug="documentation").exists())

    def test_resolve_ai_config_uses_provider_default_credential_when_model_credential_missing(self):
        provider, _ = ModelProvider.objects.get_or_create(slug="openai", defaults={"name": "OpenAI", "enabled": True})
        os.environ["XYN_TEST_OPENAI_KEY"] = "sk-runtime-test-1234"
        ProviderCredential.objects.create(
            provider=provider,
            name="default-openai",
            auth_type="env_ref",
            env_var_name="XYN_TEST_OPENAI_KEY",
            is_default=True,
            enabled=True,
        )
        model = ModelConfig.objects.create(provider=provider, model_name="gpt-4o-mini", credential=None, enabled=True)
        purpose, _ = AgentPurpose.objects.get_or_create(slug="coding", defaults={"name": "Coding", "status": "active", "enabled": True})
        agent = AgentDefinition.objects.create(
            slug="test-default-credential-agent",
            name="Test Default Credential Agent",
            model_config=model,
            enabled=True,
        )
        AgentDefinitionPurpose.objects.create(agent_definition=agent, purpose=purpose)
        resolved = resolve_ai_config(agent_slug=agent.slug)
        self.assertEqual(resolved.get("provider"), "openai")
        self.assertEqual(resolved.get("api_key"), "sk-runtime-test-1234")

    def test_extract_openai_response_text_from_output_content(self):
        payload = {
            "id": "resp_123",
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Health check passed.",
                        }
                    ],
                }
            ],
        }
        self.assertEqual(_extract_openai_response_text(payload), "Health check passed.")

    @patch("xyn_orchestrator.ai_runtime.requests.post")
    def test_invoke_model_omits_unsupported_temperature_for_gpt5(self, post_mock):
        response = Mock()
        response.status_code = 200
        response.json.return_value = {"output_text": "ok"}
        post_mock.return_value = response
        invoke_model(
            resolved_config={
                "provider": "openai",
                "model_name": "gpt-5",
                "api_key": "sk-test",
                "temperature": 0.2,
                "top_p": 0.95,
                "max_tokens": 120,
            },
            messages=[{"role": "user", "content": "hello"}],
        )
        kwargs = post_mock.call_args.kwargs
        body = kwargs["json"]
        self.assertNotIn("temperature", body)
        self.assertNotIn("top_p", body)
        self.assertEqual(body.get("max_output_tokens"), 120)
