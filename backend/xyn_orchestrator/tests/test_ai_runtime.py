from django.test import TestCase

from xyn_orchestrator.ai_runtime import assemble_system_prompt, ensure_default_ai_seeds
from xyn_orchestrator.models import AgentDefinition, ModelProvider


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
