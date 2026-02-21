from django.test import TestCase

from xyn_orchestrator.ai_runtime import assemble_system_prompt


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

