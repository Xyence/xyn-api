from django.test import TestCase

from xyn_orchestrator.ai_compat import compute_effective_params


class AiCompatTests(TestCase):
    def test_openai_gpt5_drops_temperature_and_top_p(self):
        effective, warnings = compute_effective_params(
            provider="openai",
            model_name="gpt-5",
            base_params={"temperature": 0.2, "top_p": 0.9, "max_tokens": 500},
            invocation_mode="chat",
        )
        self.assertNotIn("temperature", effective)
        self.assertNotIn("top_p", effective)
        self.assertEqual(effective.get("max_tokens"), 500)
        warned_params = {item["param"] for item in warnings}
        self.assertIn("temperature", warned_params)
        self.assertIn("top_p", warned_params)

    def test_openai_gpt4o_mini_keeps_temperature(self):
        effective, warnings = compute_effective_params(
            provider="openai",
            model_name="gpt-4o-mini",
            base_params={"temperature": 0.2, "max_tokens": 500},
            invocation_mode="chat",
        )
        self.assertEqual(effective.get("temperature"), 0.2)
        self.assertEqual(effective.get("max_tokens"), 500)
        self.assertEqual(warnings, [])

