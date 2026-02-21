import json
import os
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import ModelConfig, ModelProvider, RoleBinding, UserIdentity


class AiConfigApiTests(TestCase):
    def setUp(self):
        os.environ.setdefault("XYN_CREDENTIALS_ENCRYPTION_KEY", "V2S8x7lAB2BaN8A-14EvhA-gF1kq4KOlnS2vPc9vulE=")
        os.environ["XYN_OPENAI_API_KEY"] = "sk-test-openai-1234"
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(username="staff-ai", password="pass", is_staff=True)
        self.client.force_login(self.staff)

        self.admin_identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="ai-admin", email="ai-admin@example.com"
        )
        self.user_identity = UserIdentity.objects.create(
            provider="oidc", issuer="https://issuer", subject="ai-user", email="ai-user@example.com"
        )
        RoleBinding.objects.create(user_identity=self.admin_identity, scope_kind="platform", role="platform_admin")
        RoleBinding.objects.create(user_identity=self.user_identity, scope_kind="platform", role="app_user")

    def _set_identity(self, identity: UserIdentity):
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()

    def _ensure_provider(self) -> ModelProvider:
        provider, _ = ModelProvider.objects.get_or_create(slug="openai", defaults={"name": "OpenAI", "enabled": True})
        return provider

    def test_non_admin_cannot_mutate_ai_credentials(self):
        self._set_identity(self.user_identity)
        response = self.client.post(
            "/xyn/api/ai/credentials",
            data=json.dumps({
                "provider": "openai",
                "name": "blocked",
                "auth_type": "env_ref",
                "env_var_name": "XYN_OPENAI_API_KEY",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

    def test_credential_model_agent_flow_and_purpose_filter(self):
        self._set_identity(self.admin_identity)
        self._ensure_provider()

        created_credential = self.client.post(
            "/xyn/api/ai/credentials",
            data=json.dumps(
                {
                    "provider": "openai",
                    "name": "openai-primary",
                    "auth_type": "api_key_encrypted",
                    "api_key": "sk-live-abcdefghijklmn1234",
                    "is_default": True,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(created_credential.status_code, 200)
        payload = created_credential.json()["credential"]
        self.assertNotIn("api_key", payload)
        self.assertTrue(payload["secret"]["configured"])
        self.assertEqual(payload["secret"]["last4"], "1234")

        config_response = self.client.post(
            "/xyn/api/ai/model-configs",
            data=json.dumps(
                {
                    "provider": "openai",
                    "credential_id": payload["id"],
                    "model_name": "gpt-4o-mini",
                    "temperature": 0.2,
                    "max_tokens": 800,
                    "enabled": True,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(config_response.status_code, 200)
        model_config = config_response.json()["model_config"]

        agent_response = self.client.post(
            "/xyn/api/ai/agents",
            data=json.dumps(
                {
                    "slug": "docs-default",
                    "name": "Docs Default",
                    "model_config_id": model_config["id"],
                    "system_prompt_text": "You are docs.",
                    "purposes": ["documentation"],
                    "enabled": True,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(agent_response.status_code, 200)

        docs_agents = self.client.get("/xyn/api/ai/agents?purpose=documentation")
        self.assertEqual(docs_agents.status_code, 200)
        doc_slugs = [item["slug"] for item in docs_agents.json()["agents"]]
        self.assertIn("docs-default", doc_slugs)

        coding_agents = self.client.get("/xyn/api/ai/agents?purpose=coding")
        self.assertEqual(coding_agents.status_code, 200)
        self.assertEqual(len(coding_agents.json()["agents"]), 0)

    @patch("xyn_orchestrator.xyn_api.invoke_model")
    def test_ai_invoke_uses_agent_and_returns_content(self, invoke_mock):
        self._set_identity(self.admin_identity)
        provider = self._ensure_provider()
        model_config = ModelConfig.objects.create(provider=provider, model_name="gpt-4o-mini", enabled=True)

        create_agent = self.client.post(
            "/xyn/api/ai/agents",
            data=json.dumps(
                {
                    "slug": "docs-invoke",
                    "name": "Docs Invoke",
                    "model_config_id": str(model_config.id),
                    "system_prompt_text": "assist docs",
                    "purposes": ["documentation"],
                    "enabled": True,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create_agent.status_code, 200)

        invoke_mock.return_value = {
            "content": "Generated markdown",
            "provider": "openai",
            "model": "gpt-4o-mini",
            "usage": {"input_tokens": 1},
        }

        response = self.client.post(
            "/xyn/api/ai/invoke",
            data=json.dumps(
                {
                    "agent_slug": "docs-invoke",
                    "messages": [{"role": "user", "content": "Hello"}],
                    "metadata": {"feature": "articles_ai_assist"},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["content"], "Generated markdown")
        self.assertEqual(body["provider"], "openai")
        self.assertEqual(body["agent_slug"], "docs-invoke")
